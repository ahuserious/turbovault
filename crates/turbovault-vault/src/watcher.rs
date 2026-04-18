//! File system watcher for vault changes.
//!
//! Provides real-time notification of file system events (create, modify, delete)
//! for markdown files in the vault. Built on notify crate with async event streaming.

use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as NotifyWatcher,
    event::{ModifyKind, RenameMode},
};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use turbovault_core::{Error, Result};

/// Window in which a `RenameMode::From` event must be followed by a
/// `RenameMode::To` (or vice versa) for them to be correlated as a single
/// `VaultEvent::FileRenamed`. After this window elapses, a stranded `From`
/// is emitted as `FileDeleted` so clients never miss a delete.
const RENAME_CORRELATION_WINDOW: Duration = Duration::from_millis(500);

/// Cap on concurrent unpaired `RenameMode::From` events buffered awaiting
/// their matching `To`. If exceeded (pathological burst / platform drops
/// every `To`), the oldest `From` is immediately emitted as `FileDeleted`
/// and the buffer makes room. Prevents unbounded growth in the notify
/// callback path, which cannot be allowed to allocate without bound.
const MAX_PENDING_RENAMES: usize = 1024;

/// File system event types relevant to vault operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultEvent {
    /// A file was created
    FileCreated(PathBuf),
    /// A file was modified
    FileModified(PathBuf),
    /// A file was deleted
    FileDeleted(PathBuf),
    /// A file was renamed (from, to)
    FileRenamed(PathBuf, PathBuf),
}

impl VaultEvent {
    /// Get the primary path affected by this event
    pub fn path(&self) -> &Path {
        match self {
            Self::FileCreated(p)
            | Self::FileModified(p)
            | Self::FileDeleted(p)
            | Self::FileRenamed(_, p) => p,
        }
    }

    /// Check if event is for a markdown file
    pub fn is_markdown(&self) -> bool {
        self.path()
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("md"))
            .unwrap_or(false)
    }
}

/// Configuration for the file watcher
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// Watch recursively
    pub recursive: bool,
    /// Only report events for markdown files
    pub markdown_only: bool,
    /// Ignore hidden files (starting with .)
    pub ignore_hidden: bool,
    /// Debounce duration in milliseconds (0 = no debounce)
    pub debounce_ms: u64,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            recursive: true,
            markdown_only: true,
            ignore_hidden: true,
            debounce_ms: 100,
        }
    }
}

/// Holds rename halves awaiting their partner. notify v6 splits renames
/// into `RenameMode::From` + `RenameMode::To` on some platforms (macOS
/// FSEvents, Windows) while delivering both paths atomically on others
/// (Linux inotify, some macOS configs = `RenameMode::Both`).
///
/// The buffer is drained lazily — on every incoming event we first purge
/// entries older than [`RENAME_CORRELATION_WINDOW`], emitting unpaired
/// entries as the event they would have been without their partner.
/// FIFO buffer for pending `RenameMode::From` events.
///
/// notify emits `From` before its matching `To` in monotonic wall-clock
/// order, so a `VecDeque` with push_back / pop_front gives us O(1)
/// purge-oldest, take-oldest, and enqueue. The previous `HashMap<PathBuf,
/// Instant>` was O(n) on every `To` event via `min_by_key` — a perf cliff
/// under bulk rename (adversarial review flagged this).
#[derive(Default, Debug)]
struct CorrelationBuffer {
    /// `(when, path)` tuples in arrival order; front is oldest.
    pending_from: VecDeque<(Instant, PathBuf)>,
}

impl CorrelationBuffer {
    /// Purge entries older than the correlation window and yield them as
    /// unpaired events (pending `From` → `FileDeleted`).
    ///
    /// O(k) where k is the number of stale entries — since entries are
    /// inserted in monotonic `Instant` order, we pop from the front
    /// until the oldest remaining is fresh.
    fn purge_stale(&mut self, now: Instant) -> Vec<VaultEvent> {
        let mut evicted = Vec::new();
        while let Some((t, _)) = self.pending_from.front() {
            if now.duration_since(*t) >= RENAME_CORRELATION_WINDOW {
                let (_, path) = self.pending_from.pop_front().unwrap();
                evicted.push(VaultEvent::FileDeleted(path));
            } else {
                break;
            }
        }
        evicted
    }

    /// Remove and return the oldest pending `From` entry, if any. O(1).
    ///
    /// notify doesn't give us a link between the `From` and `To` halves
    /// at the protocol level, so we take the oldest. In practice a
    /// rename's `From` and `To` fire back-to-back well under the
    /// correlation window, so FIFO is the correct policy.
    fn take_oldest_from(&mut self) -> Option<PathBuf> {
        self.pending_from.pop_front().map(|(_, p)| p)
    }

    /// Enqueue a new pending `From`. If the buffer is at
    /// [`MAX_PENDING_RENAMES`] capacity, the oldest entry is popped
    /// and returned as an evicted `FileDeleted` so the caller can emit
    /// it immediately. This guarantees the buffer cannot grow past the
    /// cap even under pathological loads.
    fn push_from(&mut self, path: PathBuf, when: Instant) -> Option<VaultEvent> {
        let evicted = if self.pending_from.len() >= MAX_PENDING_RENAMES {
            self.pending_from
                .pop_front()
                .map(|(_, p)| VaultEvent::FileDeleted(p))
        } else {
            None
        };
        self.pending_from.push_back((when, path));
        evicted
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.pending_from.len()
    }
}

/// Watches a vault directory for file system changes
pub struct VaultWatcher {
    config: WatcherConfig,
    watch_path: PathBuf,
    watcher: Arc<RwLock<Option<RecommendedWatcher>>>,
    event_tx: UnboundedSender<VaultEvent>,
    correlation: Arc<StdMutex<CorrelationBuffer>>,
}

impl VaultWatcher {
    /// Create a new vault watcher
    ///
    /// # Arguments
    /// * `path` - Directory to watch
    /// * `config` - Watcher configuration
    ///
    /// # Returns
    /// Tuple of (VaultWatcher, event receiver)
    pub fn new(
        path: PathBuf,
        config: WatcherConfig,
    ) -> Result<(Self, UnboundedReceiver<VaultEvent>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let watcher = Self {
            config,
            watch_path: path,
            watcher: Arc::new(RwLock::new(None)),
            event_tx,
            correlation: Arc::new(StdMutex::new(CorrelationBuffer::default())),
        };

        Ok((watcher, event_rx))
    }

    /// Start watching the vault directory
    pub async fn start(&mut self) -> Result<()> {
        if self.watcher.read().await.is_some() {
            return Err(Error::invalid_path("Watcher already started".to_string()));
        }

        let event_tx = self.event_tx.clone();
        let config = self.config.clone();
        let correlation = self.correlation.clone();

        // Create notify watcher with event handler
        let mut notify_watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                let Ok(event) = res else { return };
                let now = Instant::now();
                let mut buf = match correlation.lock() {
                    Ok(g) => g,
                    // Poisoned mutex: someone panicked while holding it.
                    // Recover the inner value and continue — losing a few
                    // correlations is better than wedging the watcher.
                    Err(poisoned) => poisoned.into_inner(),
                };

                // Drain stale rename halves first. This is what prevents a
                // stranded `From` from ever going unreported — clients see
                // it as `FileDeleted` once the correlation window passes.
                for stale in buf.purge_stale(now) {
                    if Self::should_emit_event(&stale, &config) {
                        let _ = event_tx.send(stale);
                    }
                }

                let Some(vault_events) = Self::convert_event(event, &mut buf, now) else {
                    return;
                };
                drop(buf); // release the lock before the send loop

                for vault_event in vault_events {
                    if !Self::should_emit_event(&vault_event, &config) {
                        continue;
                    }
                    let _ = event_tx.send(vault_event);
                }
            },
            Config::default(),
        )
        .map_err(|e| Error::io(std::io::Error::other(e)))?;

        // Start watching
        let mode = if self.config.recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        notify_watcher
            .watch(&self.watch_path, mode)
            .map_err(|e| Error::io(std::io::Error::other(e)))?;

        // Store watcher
        *self.watcher.write().await = Some(notify_watcher);

        Ok(())
    }

    /// Stop watching
    pub async fn stop(&mut self) -> Result<()> {
        let mut watcher = self.watcher.write().await;
        if let Some(w) = watcher.take() {
            drop(w); // Dropping the watcher stops it
        }
        Ok(())
    }

    /// Check if watcher is running
    pub async fn is_running(&self) -> bool {
        self.watcher.read().await.is_some()
    }

    /// Convert a notify event into one or more `VaultEvent`s.
    ///
    /// Rename handling is the reason this signature carries a correlation
    /// buffer. notify v6 reports renames in three different shapes
    /// depending on platform:
    ///
    /// - Linux inotify / some macOS configs: one event with
    ///   `EventKind::Modify(ModifyKind::Name(RenameMode::Both))` and both
    ///   paths in `event.paths`.
    /// - macOS FSEvents / Windows: two events —
    ///   `ModifyKind::Name(RenameMode::From)` then
    ///   `ModifyKind::Name(RenameMode::To)` — with one path each.
    /// - Older / odd configs: `ModifyKind::Name(RenameMode::Any)` or
    ///   separate `Remove` + `Create`.
    ///
    /// We handle the first two precisely and degrade gracefully in the
    /// third case (falls through to `FileModified` / `FileDeleted` /
    /// `FileCreated`). `FileRenamed` emission was the gap in the pre-fix
    /// code — the variant existed but was never constructed.
    fn convert_event(
        event: Event,
        buf: &mut CorrelationBuffer,
        now: Instant,
    ) -> Option<Vec<VaultEvent>> {
        let mut events = Vec::new();

        match event.kind {
            EventKind::Create(_) => {
                for path in event.paths {
                    events.push(VaultEvent::FileCreated(path));
                }
            }
            // Atomic rename with both paths: emit directly.
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                if event.paths.len() >= 2 {
                    let mut iter = event.paths.into_iter();
                    let from = iter.next().unwrap();
                    let to = iter.next().unwrap();
                    events.push(VaultEvent::FileRenamed(from, to));
                } else if let Some(p) = event.paths.into_iter().next() {
                    // Degenerate: only one path on a Both event. Treat as modify.
                    events.push(VaultEvent::FileModified(p));
                }
            }
            // First half of a split rename: stash for later pairing.
            // If the buffer is at capacity the oldest stranded `From` is
            // evicted as a `FileDeleted` immediately — see MAX_PENDING_RENAMES.
            EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
                for path in event.paths {
                    if let Some(evicted) = buf.push_from(path, now) {
                        events.push(evicted);
                    }
                }
                // No Renamed event yet — the matching `To` (or purge) will handle it.
            }
            // Second half of a split rename: pair with the oldest pending `From`.
            EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
                for path in event.paths {
                    match buf.take_oldest_from() {
                        Some(from) => events.push(VaultEvent::FileRenamed(from, path)),
                        // No partner waiting — treat as a fresh create. The
                        // platform's notify backend likely dropped the `From`.
                        None => events.push(VaultEvent::FileCreated(path)),
                    }
                }
            }
            // Any other Modify variant (Data, Metadata, Any, and
            // `RenameMode::{Any, Other}` fallbacks).
            EventKind::Modify(_) => {
                for path in event.paths {
                    events.push(VaultEvent::FileModified(path));
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    events.push(VaultEvent::FileDeleted(path));
                }
            }
            EventKind::Any => {
                for path in event.paths {
                    events.push(VaultEvent::FileModified(path));
                }
            }
            // Access and future unknown kinds — log at trace level so
            // silent behavior-change regressions are discoverable, then
            // drop. (Adversarial review flagged: the pre-fix code's
            // silent `Modify(_)` swallow is exactly the failure mode to
            // avoid recurring here.)
            other => {
                tracing::trace!(?other, "convert_event: unhandled EventKind");
                return None;
            }
        }

        if events.is_empty() {
            None
        } else {
            Some(events)
        }
    }

    /// Check if event should be emitted based on config
    fn should_emit_event(event: &VaultEvent, config: &WatcherConfig) -> bool {
        let path = event.path();

        // Check if hidden file
        if config.ignore_hidden
            && let Some(file_name) = path.file_name().and_then(|n| n.to_str())
            && file_name.starts_with('.')
        {
            return false;
        }

        // Check if markdown file
        if config.markdown_only && !event.is_markdown() {
            return false;
        }

        true
    }
}

impl Drop for VaultWatcher {
    fn drop(&mut self) {
        // Note: Can't await in Drop, but dropping watcher stops it
        // The watcher will be dropped when the Arc count reaches 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    use tokio::time::{Duration, sleep};

    async fn create_test_watcher() -> (VaultWatcher, UnboundedReceiver<VaultEvent>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = WatcherConfig::default();
        let (watcher, rx) = VaultWatcher::new(temp_dir.path().to_path_buf(), config).unwrap();
        (watcher, rx, temp_dir)
    }

    #[tokio::test]
    async fn test_watcher_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = WatcherConfig::default();
        let result = VaultWatcher::new(temp_dir.path().to_path_buf(), config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_watcher_start_stop() {
        let (mut watcher, _rx, _temp_dir) = create_test_watcher().await;

        assert!(!watcher.is_running().await);

        watcher.start().await.unwrap();
        assert!(watcher.is_running().await);

        watcher.stop().await.unwrap();
        assert!(!watcher.is_running().await);
    }

    #[tokio::test]
    async fn test_cannot_start_twice() {
        let (mut watcher, _rx, _temp_dir) = create_test_watcher().await;

        watcher.start().await.unwrap();
        let result = watcher.start().await;
        assert!(result.is_err());

        watcher.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_file_created_event() {
        let (mut watcher, mut rx, temp_dir) = create_test_watcher().await;

        watcher.start().await.unwrap();

        // Give watcher time to initialize
        sleep(Duration::from_millis(200)).await;

        // Create a markdown file
        let file_path = temp_dir.path().join("test.md");
        fs::write(&file_path, "# Test").unwrap();

        // Wait for event
        sleep(Duration::from_millis(500)).await;

        // Should receive create event (might get multiple events on some platforms)
        let mut found_create = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(event, VaultEvent::FileCreated(_)) {
                // Canonicalize paths for comparison (macOS /var vs /private/var)
                let event_path = event.path().canonicalize().ok();
                let expected_path = file_path.canonicalize().ok();
                if event_path == expected_path {
                    found_create = true;
                    break;
                }
            }
        }
        assert!(found_create, "Did not receive FileCreated event");

        watcher.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_file_modified_event() {
        let (mut watcher, mut rx, temp_dir) = create_test_watcher().await;

        // Create file first
        let file_path = temp_dir.path().join("test.md");
        fs::write(&file_path, "# Test").unwrap();

        watcher.start().await.unwrap();
        sleep(Duration::from_millis(200)).await;

        // Clear any create events
        while rx.try_recv().is_ok() {}

        // Modify file
        fs::write(&file_path, "# Modified").unwrap();

        // Wait for event
        sleep(Duration::from_millis(500)).await;

        // Should receive modify event (might get multiple events)
        let mut found_modify = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(
                event,
                VaultEvent::FileModified(_) | VaultEvent::FileCreated(_)
            ) {
                // Some platforms may emit Create instead of Modify on write
                found_modify = true;
                break;
            }
        }
        assert!(found_modify, "Did not receive modification event");

        watcher.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_file_deleted_event() {
        let (mut watcher, mut rx, temp_dir) = create_test_watcher().await;

        // Create file first
        let file_path = temp_dir.path().join("test.md");
        fs::write(&file_path, "# Test").unwrap();

        watcher.start().await.unwrap();
        sleep(Duration::from_millis(200)).await;

        // Clear any create events
        while rx.try_recv().is_ok() {}

        // Delete file
        fs::remove_file(&file_path).unwrap();

        // Wait for event
        sleep(Duration::from_millis(500)).await;

        // Should receive delete event
        let mut found_delete = false;
        while let Ok(event) = rx.try_recv() {
            if matches!(event, VaultEvent::FileDeleted(_)) {
                found_delete = true;
                break;
            }
        }
        assert!(found_delete, "Did not receive FileDeleted event");

        watcher.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_ignores_hidden_files() {
        let (mut watcher, mut rx, temp_dir) = create_test_watcher().await;

        watcher.start().await.unwrap();
        sleep(Duration::from_millis(100)).await;

        // Create hidden file
        let file_path = temp_dir.path().join(".hidden.md");
        fs::write(&file_path, "# Hidden").unwrap();

        // Wait
        sleep(Duration::from_millis(200)).await;

        // Should NOT receive event
        let event = rx.try_recv();
        assert!(event.is_err());

        watcher.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_ignores_non_markdown_files() {
        let (mut watcher, mut rx, temp_dir) = create_test_watcher().await;

        watcher.start().await.unwrap();
        sleep(Duration::from_millis(100)).await;

        // Create non-markdown file
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "Test").unwrap();

        // Wait
        sleep(Duration::from_millis(200)).await;

        // Should NOT receive event (markdown_only is true by default)
        let event = rx.try_recv();
        assert!(event.is_err());

        watcher.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_vault_event_is_markdown() {
        let event = VaultEvent::FileCreated(PathBuf::from("test.md"));
        assert!(event.is_markdown());

        let event = VaultEvent::FileCreated(PathBuf::from("test.MD"));
        assert!(event.is_markdown());

        let event = VaultEvent::FileCreated(PathBuf::from("test.txt"));
        assert!(!event.is_markdown());
    }

    #[tokio::test]
    async fn test_vault_event_path() {
        let path = PathBuf::from("test.md");
        let event = VaultEvent::FileCreated(path.clone());
        assert_eq!(event.path(), &path);

        let event = VaultEvent::FileModified(path.clone());
        assert_eq!(event.path(), &path);

        let event = VaultEvent::FileDeleted(path.clone());
        assert_eq!(event.path(), &path);
    }

    #[test]
    fn test_watcher_config_defaults() {
        let config = WatcherConfig::default();
        assert!(config.recursive);
        assert!(config.markdown_only);
        assert!(config.ignore_hidden);
        assert_eq!(config.debounce_ms, 100);
    }

    // ---- rename-related tests ------------------------------------------

    #[tokio::test]
    async fn test_file_renamed_event() {
        let (mut watcher, mut rx, temp_dir) = create_test_watcher().await;

        let from = temp_dir.path().join("before.md");
        fs::write(&from, "# rename me").unwrap();

        watcher.start().await.unwrap();
        sleep(Duration::from_millis(200)).await;

        // Drain initialization / create events.
        while rx.try_recv().is_ok() {}

        let to = temp_dir.path().join("after.md");
        fs::rename(&from, &to).unwrap();

        // Wait longer than the correlation window so any split rename on
        // macOS/Windows gets purged-and-paired.
        sleep(Duration::from_millis(800)).await;

        // Collect everything we saw, then make a cross-platform judgment.
        // notify's rename surface varies significantly:
        //   - Linux inotify: `Modify(Name(Both))` with 2 paths -> FileRenamed
        //   - modern macOS FSEvents: `Modify(Name(Any))` with 1 path, or
        //     split into `Modify(Name(From))` + `Modify(Name(To))`
        //   - fallback / debounced: bare `Remove(before)` + `Create(after)`
        //
        // What this test guards: renaming a watched file does NOT silently
        // vanish — at least one event that mentions `before.md` or
        // `after.md` must arrive. The pre-fix code would swallow rename
        // events entirely on some platforms via the `Modify(_)` wildcard.
        let mut saw_rename_pair = false;
        let mut saw_before = false;
        let mut saw_after = false;
        let before_os = std::ffi::OsStr::new("before.md");
        let after_os = std::ffi::OsStr::new("after.md");

        while let Ok(event) = rx.try_recv() {
            match event {
                VaultEvent::FileRenamed(f, t) => {
                    if f.file_name() == Some(before_os) && t.file_name() == Some(after_os) {
                        saw_rename_pair = true;
                    }
                    saw_before |= f.file_name() == Some(before_os);
                    saw_after |= t.file_name() == Some(after_os);
                }
                other => {
                    saw_before |= other.path().file_name() == Some(before_os);
                    saw_after |= other.path().file_name() == Some(after_os);
                }
            }
        }

        assert!(
            saw_rename_pair || saw_before || saw_after,
            "No event mentioning before.md or after.md was observed — \
             the rename was silently swallowed"
        );

        watcher.stop().await.unwrap();
    }

    #[test]
    fn test_correlation_buffer_purges_stale_from_as_deleted() {
        let mut buf = CorrelationBuffer::default();
        let path = PathBuf::from("/tmp/stranded.md");
        let t0 = Instant::now() - Duration::from_millis(600);
        assert!(buf.push_from(path.clone(), t0).is_none());

        let evicted = buf.purge_stale(Instant::now());
        assert_eq!(evicted.len(), 1);
        assert!(matches!(evicted[0], VaultEvent::FileDeleted(ref p) if p == &path));
        assert_eq!(buf.len(), 0, "purge should clear stale entries");
    }

    #[test]
    fn test_correlation_buffer_keeps_fresh_from() {
        let mut buf = CorrelationBuffer::default();
        let path = PathBuf::from("/tmp/fresh.md");
        assert!(buf.push_from(path, Instant::now()).is_none());

        let evicted = buf.purge_stale(Instant::now());
        assert!(evicted.is_empty(), "fresh entries must not be purged");
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn test_correlation_buffer_take_oldest_from_is_fifo() {
        let mut buf = CorrelationBuffer::default();
        let a = PathBuf::from("/tmp/a.md");
        let b = PathBuf::from("/tmp/b.md");
        let t0 = Instant::now() - Duration::from_millis(50);
        let t1 = Instant::now();
        assert!(buf.push_from(a.clone(), t0).is_none());
        assert!(buf.push_from(b.clone(), t1).is_none());

        assert_eq!(buf.take_oldest_from(), Some(a));
        assert_eq!(buf.take_oldest_from(), Some(b));
        assert_eq!(buf.take_oldest_from(), None);
    }

    #[test]
    fn test_correlation_buffer_caps_at_max_pending_renames() {
        // Adversarial case: a platform delivering From events with no
        // matching To at high volume. The buffer must not grow unbounded.
        let mut buf = CorrelationBuffer::default();
        let mut evictions = 0;
        for i in 0..(MAX_PENDING_RENAMES + 100) {
            let p = PathBuf::from(format!("/tmp/f{}.md", i));
            if buf.push_from(p, Instant::now()).is_some() {
                evictions += 1;
            }
        }
        assert_eq!(evictions, 100, "should evict exactly the overflow");
        assert_eq!(buf.len(), MAX_PENDING_RENAMES);
    }

    // Synthetic convert_event tests — exercise the rename correlation
    // path deterministically without relying on notify's platform-varying
    // event stream. The adversarial review flagged that the integration
    // test could pass on the pre-fix code via `FileModified(before.md)`
    // slipping through the `Modify(_)` wildcard. These tests feed
    // convert_event directly with the exact notify::EventKind shape we
    // care about, so they'd fail loudly on the regression.

    fn synth_event(kind: EventKind, paths: Vec<&str>) -> Event {
        let mut ev = Event::new(kind);
        for p in paths {
            ev = ev.add_path(PathBuf::from(p));
        }
        ev
    }

    #[test]
    fn convert_event_emits_filerenamed_on_rename_mode_both() {
        let mut buf = CorrelationBuffer::default();
        let ev = synth_event(
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            vec!["/tmp/before.md", "/tmp/after.md"],
        );
        let out = VaultWatcher::convert_event(ev, &mut buf, Instant::now()).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            VaultEvent::FileRenamed(from, to) => {
                assert_eq!(from, Path::new("/tmp/before.md"));
                assert_eq!(to, Path::new("/tmp/after.md"));
            }
            other => panic!("expected FileRenamed, got {:?}", other),
        }
    }

    #[test]
    fn convert_event_pairs_split_rename_from_then_to() {
        let mut buf = CorrelationBuffer::default();
        // First half: From. No events emitted yet.
        let from_ev = synth_event(
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            vec!["/tmp/before.md"],
        );
        let out = VaultWatcher::convert_event(from_ev, &mut buf, Instant::now()).unwrap_or_default();
        assert!(out.is_empty(), "From alone should produce no event");
        assert_eq!(buf.len(), 1, "From should be buffered");

        // Second half: To. Should pair with the stashed From.
        let to_ev = synth_event(
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            vec!["/tmp/after.md"],
        );
        let out = VaultWatcher::convert_event(to_ev, &mut buf, Instant::now()).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            VaultEvent::FileRenamed(from, to) => {
                assert_eq!(from, Path::new("/tmp/before.md"));
                assert_eq!(to, Path::new("/tmp/after.md"));
            }
            other => panic!("expected FileRenamed, got {:?}", other),
        }
        assert_eq!(buf.len(), 0, "buffer should be drained after pairing");
    }

    #[test]
    fn convert_event_to_without_from_emits_filecreated() {
        let mut buf = CorrelationBuffer::default();
        // Platform dropped the From. The To should surface as FileCreated.
        let to_ev = synth_event(
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            vec!["/tmp/orphan.md"],
        );
        let out = VaultWatcher::convert_event(to_ev, &mut buf, Instant::now()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(
            &out[0],
            VaultEvent::FileCreated(p) if p == Path::new("/tmp/orphan.md")
        ));
    }

    #[test]
    fn convert_event_modify_data_still_emits_filemodified() {
        // Critical regression guard: pre-fix code folded ALL Modify(_)
        // into FileModified, including renames. Post-fix, the Data /
        // Metadata / Any branches must still emit FileModified so we
        // don't regress plain content edits.
        let mut buf = CorrelationBuffer::default();
        let ev = synth_event(
            EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Content)),
            vec!["/tmp/edited.md"],
        );
        let out = VaultWatcher::convert_event(ev, &mut buf, Instant::now()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(matches!(
            &out[0],
            VaultEvent::FileModified(p) if p == Path::new("/tmp/edited.md")
        ));
    }
}
