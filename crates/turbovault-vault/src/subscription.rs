//! Subscription registry for [`VaultEvent`]s.
//!
//! Fans out a single [`VaultWatcher`]'s event stream to N filtered
//! subscribers. Designed to be driven by an MCP server that wants to
//! expose file-system change notifications to clients — the registry
//! itself is transport-agnostic so the same plumbing works for tests,
//! WebSocket notifications, Server-Sent Events, or any custom sink.
//!
//! # Design
//!
//! - **One watcher, many subscribers.** `notify::RecommendedWatcher`
//!   holds an OS-level handle per watched path. Running N watchers for
//!   the same vault would duplicate kernel notifications and is wasteful.
//!   Instead, a single central pump reads the watcher's event stream and
//!   delivers to matching subscribers.
//!
//! - **Per-subscription bounded channel.** Each subscription owns a
//!   `tokio::sync::mpsc::Sender<VaultEvent>` with capacity 256. On
//!   overflow the *newest* event is dropped and a per-subscription
//!   `AtomicU64` drop counter is bumped — tokio's mpsc doesn't expose
//!   a "pop oldest, push new" primitive and introducing an auxiliary
//!   buffer just to simulate drop-oldest is more moving parts than
//!   the correctness guarantee is worth. Consumers poll `dropped_count`
//!   (or read it off periodic overflow notifications in the transport
//!   adapter) and are expected to refresh vault state when a drop is
//!   observed. The channel capacity sizes comfortably above any
//!   realistic batch-edit burst, so drops under normal operation
//!   signal a stuck consumer rather than legitimate load.
//!
//! - **Client-supplied glob filter.** Patterns compile once via
//!   [`globset::GlobSet`]; matching is O(1) on the cached automaton.
//!   Inputs are capped at 32 globs / 4 KB total to prevent pathological
//!   client submissions.
//!
//! # Non-goals
//!
//! - This module does **not** perform MCP transport binding. A caller
//!   (e.g. the `turbovault` binary) consumes the per-subscription
//!   receiver and forwards events as MCP notifications; see the
//!   `Subscription::receiver` method.
//!
//! - This module does **not** provide persistence. Subscriptions are
//!   in-memory; a server restart drops them all. Clients are expected
//!   to re-subscribe on reconnect.

use crate::watcher::{VaultEvent, VaultWatcher};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, channel};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use turbovault_core::{Error, Result};
use uuid::Uuid;

/// Maximum number of glob patterns a single `EventFilter` may contain.
/// Prevents pathological client submissions from blowing up glob compilation.
pub const MAX_GLOB_PATTERNS: usize = 32;

/// Maximum total length (bytes) across all patterns in one filter.
pub const MAX_GLOB_TOTAL_BYTES: usize = 4096;

/// Per-subscription event queue capacity.
///
/// Sized so a reasonable bulk edit (e.g. 200-file batch apply) fits
/// without drops but a stalled consumer can't starve the server of
/// memory.
pub const SUBSCRIPTION_CHANNEL_CAP: usize = 256;

/// Default TTL for an unpolled subscription before the reaper removes it.
///
/// The pull-based `fetch_vault_events` tool updates each subscription's
/// `last_polled_at` on every call. If a client crashes or otherwise
/// stops polling, its subscription would otherwise live forever; the
/// reaper task evicts it after this idle window.
pub const DEFAULT_SUBSCRIPTION_FETCH_TTL: Duration = Duration::from_secs(15 * 60);

/// Interval between reaper sweeps. One sweep walks the full subscription
/// map under a write lock; a minute-granularity cadence keeps overhead
/// negligible (the map is tiny in practice) while bounding how long a
/// leaked subscription can linger past its TTL.
pub const REAPER_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Kinds of vault events a subscriber can filter on.
///
/// Mirrors [`VaultEvent`] but serializable as a compact tag, suitable
/// for JSON-over-MCP clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultEventKind {
    Created,
    Modified,
    Deleted,
    Renamed,
}

impl VaultEventKind {
    /// Project a [`VaultEvent`] onto its kind tag.
    pub fn from_event(event: &VaultEvent) -> Self {
        match event {
            VaultEvent::FileCreated(_) => Self::Created,
            VaultEvent::FileModified(_) => Self::Modified,
            VaultEvent::FileDeleted(_) => Self::Deleted,
            VaultEvent::FileRenamed(_, _) => Self::Renamed,
        }
    }
}

/// A dispatched [`VaultEvent`] tagged with a per-subscription sequence
/// number.
///
/// The sequence is monotonically increasing within one subscription and
/// starts at 1. Clients that resume a long-poll after a crash can pass
/// the last `seq` they observed as `since_seq` so they only receive
/// events they haven't processed yet.
///
/// The `seq` counter is strictly per-subscription; two subscriptions
/// may both deliver `seq=1` for different events. There is no global
/// ordering across subscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    /// Monotonically-increasing sequence number (per-subscription).
    pub seq: u64,
    /// The underlying vault event.
    pub event: VaultEvent,
}

/// Client-facing event filter. Default matches every markdown event.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EventFilter {
    /// Gitignore-style glob patterns. If empty, all paths match.
    /// Negation patterns (starting with `!`) exclude matches.
    #[serde(default)]
    pub globs: Vec<String>,

    /// If `Some`, only events whose kind is in the set are delivered.
    /// If `None`, all kinds match.
    #[serde(default)]
    pub kinds: Option<Vec<VaultEventKind>>,
}

impl EventFilter {
    /// Validate the filter's patterns against the server limits.
    /// Called by `SubscriptionRegistry::subscribe` before glob compilation.
    fn validate(&self) -> Result<()> {
        if self.globs.len() > MAX_GLOB_PATTERNS {
            return Err(Error::invalid_path(format!(
                "EventFilter has {} globs; max allowed is {}",
                self.globs.len(),
                MAX_GLOB_PATTERNS
            )));
        }
        let total: usize = self.globs.iter().map(|g| g.len()).sum();
        if total > MAX_GLOB_TOTAL_BYTES {
            return Err(Error::invalid_path(format!(
                "EventFilter globs total {} bytes; max allowed is {}",
                total, MAX_GLOB_TOTAL_BYTES
            )));
        }
        Ok(())
    }
}

/// A compiled filter: GlobSet for includes, GlobSet for excludes.
/// Exclusion takes priority over inclusion, matching gitignore semantics.
#[derive(Debug, Clone)]
struct CompiledFilter {
    include: Option<GlobSet>,
    exclude: Option<GlobSet>,
    kinds: Option<std::collections::HashSet<VaultEventKind>>,
}

impl CompiledFilter {
    fn compile(filter: &EventFilter) -> Result<Self> {
        let mut include_b = GlobSetBuilder::new();
        let mut exclude_b = GlobSetBuilder::new();
        let mut any_include = false;
        let mut any_exclude = false;

        for pat in &filter.globs {
            let (glob_str, is_exclude) = if let Some(rest) = pat.strip_prefix('!') {
                (rest, true)
            } else {
                (pat.as_str(), false)
            };
            // `literal_separator(true)` gives gitignore-like semantics:
            // `*` does not cross `/`. Without it, `00-neuro-link/*.md`
            // would also match `00-neuro-link/tasks/foo.md`, which is
            // never what a vault-path filter wants. Use `**` for
            // cross-segment wildcards (e.g. `02-KB-main/**/*.md`).
            let glob = GlobBuilder::new(glob_str)
                .literal_separator(true)
                .build()
                .map_err(|e| {
                    Error::invalid_path(format!("invalid glob {:?}: {}", pat, e))
                })?;
            if is_exclude {
                exclude_b.add(glob);
                any_exclude = true;
            } else {
                include_b.add(glob);
                any_include = true;
            }
        }

        let include = if any_include {
            Some(include_b.build().map_err(|e| {
                Error::invalid_path(format!("glob compile error: {}", e))
            })?)
        } else {
            None
        };
        let exclude = if any_exclude {
            Some(exclude_b.build().map_err(|e| {
                Error::invalid_path(format!("glob compile error: {}", e))
            })?)
        } else {
            None
        };

        let kinds = filter
            .kinds
            .as_ref()
            .map(|v| v.iter().copied().collect::<std::collections::HashSet<_>>());

        Ok(Self {
            include,
            exclude,
            kinds,
        })
    }

    /// Check a single path against include/exclude globs.
    fn path_matches(&self, path: &Path) -> bool {
        if let Some(ex) = &self.exclude {
            if ex.is_match(path) {
                return false;
            }
        }
        match &self.include {
            Some(inc) => inc.is_match(path),
            None => true, // no include patterns means "allow all"
        }
    }

    /// Does `event` pass this filter?
    ///
    /// For `FileRenamed(from, to)` the event matches if **either** the
    /// source OR the destination matches. Rationale (adversarial review
    /// Should-fix #9): if a subscriber watches `02-KB-main/**/*.md` and a
    /// file renames *out* of that prefix, the destination no longer
    /// matches but the subscriber still needs to know the source is
    /// gone. Emitting the rename with both paths lets the client
    /// synthesize the "source deleted" view locally.
    fn matches(&self, event: &VaultEvent) -> bool {
        if let Some(allowed) = &self.kinds {
            if !allowed.contains(&VaultEventKind::from_event(event)) {
                return false;
            }
        }

        match event {
            VaultEvent::FileRenamed(from, to) => {
                self.path_matches(from) || self.path_matches(to)
            }
            other => self.path_matches(other.path()),
        }
    }
}

/// Opaque handle returned to subscribers. UUID v4 string representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SubscriptionHandle(pub String);

impl SubscriptionHandle {
    fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

/// A single active subscription.
///
/// `receiver` is handed out once at creation time to the transport
/// adapter. The registry only retains the `Sender` half for dispatch.
#[derive(Debug)]
struct SubscriptionState {
    id: SubscriptionHandle,
    session_id: Option<String>,
    filter: CompiledFilter,
    sender: Sender<EventEnvelope>,
    /// Monotonic per-subscription sequence number. Incremented before
    /// each enqueue so clients always receive strictly increasing `seq`
    /// values even if events are dropped on backpressure.
    next_seq: std::sync::atomic::AtomicU64,
    /// Count of events dropped due to backpressure. The transport adapter
    /// can surface this to the client (e.g. via a periodic
    /// `notifications/vault/overflow` control message).
    dropped: std::sync::atomic::AtomicU64,
    /// Timestamp of the last `fetch_vault_events` call that targeted
    /// this subscription. Refreshed on every poll; the reaper task
    /// evicts subscriptions whose `last_polled_at` is older than
    /// [`DEFAULT_SUBSCRIPTION_FETCH_TTL`] so leaked subscriptions don't
    /// accumulate.
    last_polled_at: std::sync::Mutex<Instant>,
}

impl SubscriptionState {
    fn try_send(&self, event: VaultEvent) {
        // Assign a sequence number before enqueueing. We use Relaxed
        // because there is exactly one producer (the registry pump) per
        // subscription, so no inter-thread ordering is required — only
        // atomicity of the increment itself.
        let seq = self
            .next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        let envelope = EventEnvelope { seq, event };
        match self.sender.try_send(envelope) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // Channel full: drop the newest event and bump the
                // subscriber-visible drop counter. The module docstring
                // explains the choice — briefly: tokio mpsc doesn't expose
                // a "pop oldest" primitive and an auxiliary VecDeque would
                // cost a second lock per dispatch. With a 256-slot
                // capacity, a sustained-full channel means the consumer
                // is stuck; at that point what we report on resumption is
                // a counter, not a buffer.
                //
                // Note the `seq` we consumed above is intentionally not
                // reused: leaving a gap in the delivered sequence is
                // exactly the signal clients use (alongside `dropped`)
                // to detect that they missed at least one event.
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    subscription = %self.id.0,
                    "subscription queue full; dropped event (consumer likely stuck)"
                );
            }
            Err(TrySendError::Closed(_)) => {
                // Subscriber gone. The registry's maintenance pass
                // (see `SubscriptionRegistry::prune_closed`) will
                // reap this entry.
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Record that a fetcher just polled this subscription. Called from
    /// `SubscriptionRegistry::fetch` so the reaper knows the client is
    /// still live.
    #[allow(dead_code)] // used by fetch() once it lands in commit 2
    fn touch(&self) {
        // Poisoned mutex: recover inner — losing a timestamp update is
        // preferable to wedging the fetcher.
        let mut guard = match self.last_polled_at.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Instant::now();
    }

    /// Snapshot `last_polled_at`. Used by the reaper task.
    fn last_polled_at(&self) -> Instant {
        let guard = match self.last_polled_at.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard
    }
}

/// Central subscription registry.
///
/// Spawns one pump task on construction that consumes events from the
/// owned [`VaultWatcher`]'s stream and dispatches to matching subscribers.
/// Also spawns a reaper task that evicts subscriptions whose last
/// `fetch_vault_events` call is older than the configured TTL — the
/// pull-based design requires this safety net because a crashed client
/// leaves no TCP close to latch onto.
pub struct SubscriptionRegistry {
    inner: Arc<Inner>,
    pump_handle: Mutex<Option<JoinHandle<()>>>,
    reaper_handle: Mutex<Option<JoinHandle<()>>>,
}

/// Combined state under a single lock. Collapsing `subs` and `by_session`
/// into one `RwLock<State>` keeps subscribe/unsubscribe/unsubscribe_session
/// atomic with respect to each other — previously the two-step
/// `subs.write()` then `by_session.write()` could race across those
/// critical sections (adversarial review flagged this).
#[derive(Default)]
struct State {
    subs: HashMap<SubscriptionHandle, Arc<SubscriptionState>>,
    by_session: HashMap<String, std::collections::HashSet<SubscriptionHandle>>,
}

struct Inner {
    state: RwLock<State>,
    /// Keep the watcher alive for the registry's lifetime. Without this,
    /// the caller's `Arc<VaultWatcher>` was the sole owner — dropping it
    /// would silently tear down the notify stream and cause the pump to
    /// exit unseen (adversarial review Blocker #2).
    _watcher: Arc<VaultWatcher>,
    /// Idle window after which the reaper evicts an unpolled subscription.
    fetch_ttl: Duration,
}

impl SubscriptionRegistry {
    /// Build a registry wrapping a started [`VaultWatcher`] with the
    /// default fetch TTL ([`DEFAULT_SUBSCRIPTION_FETCH_TTL`]).
    ///
    /// The watcher's event receiver is drained by an internal pump task;
    /// the caller should not attempt to consume `event_rx` themselves.
    ///
    /// # Lifecycle
    ///
    /// The registry takes ownership of the `VaultWatcher`'s `Arc` (it is
    /// stored internally), so dropping the registry is sufficient to tear
    /// down the watcher and stop the notify subsystem. Dropping the
    /// registry also aborts the pump and reaper tasks and closes all
    /// active subscriptions' senders.
    pub fn new(
        watcher: Arc<VaultWatcher>,
        event_rx: UnboundedReceiver<VaultEvent>,
    ) -> Self {
        Self::with_fetch_ttl(watcher, event_rx, DEFAULT_SUBSCRIPTION_FETCH_TTL)
    }

    /// Build a registry with an explicit fetch TTL. Useful for tests
    /// that need to exercise the reaper without waiting 15 minutes.
    pub fn with_fetch_ttl(
        watcher: Arc<VaultWatcher>,
        mut event_rx: UnboundedReceiver<VaultEvent>,
        fetch_ttl: Duration,
    ) -> Self {
        let inner = Arc::new(Inner {
            state: RwLock::new(State::default()),
            _watcher: watcher,
            fetch_ttl,
        });

        let inner_pump = inner.clone();
        let pump = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                // Read-lock for dispatch; grab snapshot of matching subs.
                let state = inner_pump.state.read().await;
                for sub in state.subs.values() {
                    if sub.filter.matches(&event) {
                        sub.try_send(event.clone());
                    }
                }
                drop(state);
            }
            tracing::debug!("subscription pump exiting (watcher stream ended)");
        });

        // Reaper: periodically walk the subscription map and evict any
        // whose `last_polled_at` is older than the configured TTL. The
        // sweep cadence is fixed (one minute) while the eviction
        // threshold is configurable; this keeps the worst-case lag
        // between "exceeded TTL" and "actually gone" bounded at
        // ~REAPER_SWEEP_INTERVAL.
        //
        // We choose a wall-clock-independent sweep interval (tokio
        // interval, not sleep-until) so pausing at a breakpoint doesn't
        // cause the reaper to unleash a burst of evictions when
        // execution resumes.
        let inner_reaper = inner.clone();
        let reaper = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(REAPER_SWEEP_INTERVAL);
            // Skip the immediate first tick — a brand-new registry with
            // no subscriptions has nothing to reap, and the first
            // meaningful sweep should come ~REAPER_SWEEP_INTERVAL later.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let ttl = inner_reaper.fetch_ttl;
                let now = Instant::now();
                let mut state = inner_reaper.state.write().await;
                // Collect handles to evict; we can't mutate while
                // iterating.
                let stale: Vec<SubscriptionHandle> = state
                    .subs
                    .iter()
                    .filter_map(|(h, s)| {
                        if now.duration_since(s.last_polled_at()) >= ttl {
                            Some(h.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                for h in &stale {
                    if let Some(sub_state) = state.subs.remove(h) {
                        if let Some(sid) = &sub_state.session_id {
                            if let Some(set) = state.by_session.get_mut(sid) {
                                set.remove(h);
                                if set.is_empty() {
                                    state.by_session.remove(sid);
                                }
                            }
                        }
                    }
                }
                if !stale.is_empty() {
                    tracing::info!(
                        count = stale.len(),
                        ttl_secs = ttl.as_secs(),
                        "reaped stale subscriptions"
                    );
                }
            }
        });

        Self {
            inner,
            pump_handle: Mutex::new(Some(pump)),
            reaper_handle: Mutex::new(Some(reaper)),
        }
    }

    /// Register a new subscription.
    ///
    /// The returned `Receiver` carries sequenced envelopes (see
    /// [`EventEnvelope`]). The caller owns it and is responsible for
    /// draining; the registry only holds the paired sender.
    pub async fn subscribe(
        &self,
        filter: EventFilter,
        session_id: Option<String>,
    ) -> Result<(SubscriptionHandle, Receiver<EventEnvelope>)> {
        filter.validate()?;
        let compiled = CompiledFilter::compile(&filter)?;
        let (tx, rx) = channel::<EventEnvelope>(SUBSCRIPTION_CHANNEL_CAP);
        let handle = SubscriptionHandle::new();
        let sub_state = Arc::new(SubscriptionState {
            id: handle.clone(),
            session_id: session_id.clone(),
            filter: compiled,
            sender: tx,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            dropped: std::sync::atomic::AtomicU64::new(0),
            // Initialize to "just polled" so a freshly-created
            // subscription isn't reaped on the next sweep.
            last_polled_at: std::sync::Mutex::new(Instant::now()),
        });

        // Single critical section — subs and by_session are mutated
        // atomically, so concurrent unsubscribe_session and dispatch
        // always see a consistent view.
        let mut state = self.inner.state.write().await;
        state.subs.insert(handle.clone(), sub_state);
        if let Some(sid) = session_id {
            state.by_session.entry(sid).or_default().insert(handle.clone());
        }
        drop(state);

        Ok((handle, rx))
    }

    /// Cancel a subscription. Returns `true` if a subscription with that
    /// handle existed.
    pub async fn unsubscribe(&self, handle: &SubscriptionHandle) -> bool {
        let mut state = self.inner.state.write().await;
        let removed = state.subs.remove(handle);
        if let Some(sub_state) = &removed {
            if let Some(sid) = &sub_state.session_id {
                if let Some(set) = state.by_session.get_mut(sid) {
                    set.remove(handle);
                    if set.is_empty() {
                        state.by_session.remove(sid);
                    }
                }
            }
        }
        removed.is_some()
    }

    /// Cancel every subscription owned by `session_id`.
    ///
    /// Transport adapters should wire this to their session-closed
    /// callback so subscriptions don't outlive their client.
    pub async fn unsubscribe_session(&self, session_id: &str) -> usize {
        let mut state = self.inner.state.write().await;
        let handles = state.by_session.remove(session_id).unwrap_or_default();
        let mut count = 0;
        for h in &handles {
            if state.subs.remove(h).is_some() {
                count += 1;
            }
        }
        count
    }

    /// Drop any subscriptions whose receiver has been dropped.
    ///
    /// Called periodically by the pump or by an explicit reaper task.
    /// Not strictly required (the send paths detect closed channels
    /// already) but keeps memory from accumulating orphans.
    pub async fn prune_closed(&self) -> usize {
        let mut state = self.inner.state.write().await;
        let before = state.subs.len();
        // First collect the handles-to-drop, then also scrub by_session.
        let to_drop: Vec<SubscriptionHandle> = state
            .subs
            .iter()
            .filter_map(|(h, s)| if s.is_closed() { Some(h.clone()) } else { None })
            .collect();
        for h in &to_drop {
            if let Some(sub_state) = state.subs.remove(h) {
                if let Some(sid) = &sub_state.session_id {
                    if let Some(set) = state.by_session.get_mut(sid) {
                        set.remove(h);
                        if set.is_empty() {
                            state.by_session.remove(sid);
                        }
                    }
                }
            }
        }
        before - state.subs.len()
    }

    /// Number of active subscriptions. O(1).
    pub async fn len(&self) -> usize {
        self.inner.state.read().await.subs.len()
    }

    /// Total dropped events across all active subscriptions. Useful for
    /// health metrics.
    pub async fn total_dropped(&self) -> u64 {
        let state = self.inner.state.read().await;
        state
            .subs
            .values()
            .map(|s| s.dropped.load(std::sync::atomic::Ordering::Relaxed))
            .sum()
    }
}

impl Drop for SubscriptionRegistry {
    fn drop(&mut self) {
        if let Ok(mut g) = self.pump_handle.try_lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
        if let Ok(mut g) = self.reaper_handle.try_lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::sync::mpsc::unbounded_channel;

    fn ev_created(p: &str) -> VaultEvent {
        VaultEvent::FileCreated(PathBuf::from(p))
    }

    fn ev_modified(p: &str) -> VaultEvent {
        VaultEvent::FileModified(PathBuf::from(p))
    }

    fn ev_deleted(p: &str) -> VaultEvent {
        VaultEvent::FileDeleted(PathBuf::from(p))
    }

    fn ev_renamed(from: &str, to: &str) -> VaultEvent {
        VaultEvent::FileRenamed(PathBuf::from(from), PathBuf::from(to))
    }

    #[test]
    fn test_filter_default_matches_all() {
        let f = CompiledFilter::compile(&EventFilter::default()).unwrap();
        assert!(f.matches(&ev_created("anywhere.md")));
        assert!(f.matches(&ev_modified("deep/nested/file.md")));
    }

    #[test]
    fn test_filter_include_glob() {
        let f = CompiledFilter::compile(&EventFilter {
            globs: vec!["00-neuro-link/*.md".into()],
            kinds: None,
        })
        .unwrap();
        assert!(f.matches(&ev_created("00-neuro-link/plan.md")));
        assert!(!f.matches(&ev_created("02-KB-main/math/x.md")));
        // Nested under 00-neuro-link should NOT match single-segment pattern
        assert!(!f.matches(&ev_created("00-neuro-link/tasks/foo.md")));
    }

    #[test]
    fn test_filter_exclude_glob() {
        let f = CompiledFilter::compile(&EventFilter {
            globs: vec!["**/*.md".into(), "!trash/**".into()],
            kinds: None,
        })
        .unwrap();
        assert!(f.matches(&ev_created("02-KB-main/note.md")));
        assert!(!f.matches(&ev_created("trash/old.md")));
    }

    #[test]
    fn test_filter_kind() {
        let f = CompiledFilter::compile(&EventFilter {
            globs: vec![],
            kinds: Some(vec![VaultEventKind::Created, VaultEventKind::Renamed]),
        })
        .unwrap();
        assert!(f.matches(&ev_created("x.md")));
        assert!(f.matches(&ev_renamed("a.md", "b.md")));
        assert!(!f.matches(&ev_modified("x.md")));
        assert!(!f.matches(&ev_deleted("x.md")));
    }

    #[test]
    fn test_filter_rename_matches_either_endpoint() {
        // Renaming INTO the watched prefix should match (dest hits).
        let f = CompiledFilter::compile(&EventFilter {
            globs: vec!["02-KB-main/**/*.md".into()],
            kinds: None,
        })
        .unwrap();
        assert!(f.matches(&ev_renamed("01-raw/draft.md", "02-KB-main/math/new.md")));
        // Renaming OUT of watched prefix should also match (src hits).
        // This lets the subscriber observe the source's disappearance.
        assert!(f.matches(&ev_renamed("02-KB-main/math/x.md", "01-raw/x.md")));
        // Rename between two unrelated locations: no match.
        assert!(!f.matches(&ev_renamed("misc/a.md", "misc/b.md")));
    }

    #[test]
    fn test_filter_rename_exclude_wins_on_both_endpoints() {
        let f = CompiledFilter::compile(&EventFilter {
            globs: vec!["**/*.md".into(), "!trash/**".into()],
            kinds: None,
        })
        .unwrap();
        // If EITHER endpoint is excluded, we still want to deliver so
        // the client knows the file moved (include-or semantics).
        // But: if BOTH endpoints are excluded, clearly don't deliver.
        assert!(f.matches(&ev_renamed("docs/a.md", "trash/a.md")));
        assert!(!f.matches(&ev_renamed("trash/a.md", "trash/b.md")));
    }

    #[test]
    fn test_filter_rejects_too_many_globs() {
        let filter = EventFilter {
            globs: (0..100).map(|i| format!("p{}/*.md", i)).collect(),
            kinds: None,
        };
        assert!(filter.validate().is_err());
    }

    #[test]
    fn test_filter_rejects_oversize_patterns() {
        let huge = "a".repeat(5000);
        let filter = EventFilter {
            globs: vec![huge],
            kinds: None,
        };
        assert!(filter.validate().is_err());
    }

    #[test]
    fn test_filter_rejects_invalid_glob() {
        let res = CompiledFilter::compile(&EventFilter {
            globs: vec!["[[[invalid".into()],
            kinds: None,
        });
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_subscribe_receives_matching_event() {
        // Build a registry with a fake watcher — we never call .start()
        // so the mpsc channel just carries our hand-fed events.
        let (tx, rx) = unbounded_channel::<VaultEvent>();
        let (dummy_watcher, _unused_rx) = VaultWatcher::new(
            PathBuf::from("/tmp/nonexistent"),
            crate::watcher::WatcherConfig::default(),
        )
        .unwrap();
        let reg = SubscriptionRegistry::new(Arc::new(dummy_watcher), rx);

        let (_handle, mut sub_rx) = reg
            .subscribe(
                EventFilter {
                    globs: vec!["00-neuro-link/*.md".into()],
                    kinds: None,
                },
                Some("session-1".into()),
            )
            .await
            .unwrap();

        tx.send(ev_created("00-neuro-link/plan.md")).unwrap();
        tx.send(ev_created("02-KB-main/ignored.md")).unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            sub_rx.recv(),
        )
        .await
        .expect("timed out")
        .expect("stream closed");
        assert_eq!(received.seq, 1, "first delivered event should be seq=1");
        assert!(matches!(
            received.event,
            VaultEvent::FileCreated(ref p) if p == Path::new("00-neuro-link/plan.md")
        ));

        // The unmatched event should NOT come through.
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sub_rx.recv(),
        )
        .await;
        assert!(timed_out.is_err(), "unmatched event leaked");
    }

    #[tokio::test]
    async fn test_unsubscribe_stops_delivery() {
        let (tx, rx) = unbounded_channel::<VaultEvent>();
        let (dummy_watcher, _unused) = VaultWatcher::new(
            PathBuf::from("/tmp/nonexistent"),
            crate::watcher::WatcherConfig::default(),
        )
        .unwrap();
        let reg = SubscriptionRegistry::new(Arc::new(dummy_watcher), rx);

        let (handle, mut sub_rx) = reg
            .subscribe(EventFilter::default(), None)
            .await
            .unwrap();

        assert_eq!(reg.len().await, 1);
        assert!(reg.unsubscribe(&handle).await);
        assert_eq!(reg.len().await, 0);

        // Dispatching an event after unsubscribe should not deliver.
        tx.send(ev_created("x.md")).unwrap();
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            sub_rx.recv(),
        )
        .await;
        // recv may return None (channel closed via Drop) or time out.
        match timed_out {
            Err(_) => {} // timed out — fine
            Ok(None) => {} // channel closed — also fine
            Ok(Some(_)) => panic!("event leaked after unsubscribe"),
        }
    }

    #[tokio::test]
    async fn test_overflow_bumps_drop_counter() {
        // Sustained-full channel: consumer never reads, producer pushes
        // past capacity. `try_send` should return Full and the registry
        // should count every dropped event in `total_dropped`.
        let (tx, rx) = unbounded_channel::<VaultEvent>();
        let (dummy, _) = VaultWatcher::new(
            PathBuf::from("/tmp/nonexistent"),
            crate::watcher::WatcherConfig::default(),
        )
        .unwrap();
        let reg = SubscriptionRegistry::new(Arc::new(dummy), rx);
        // Subscribe with a filter that matches everything. We deliberately
        // DON'T drain the receiver, forcing backpressure.
        let (_handle, _sub_rx) = reg
            .subscribe(EventFilter::default(), None)
            .await
            .unwrap();

        let overflow_count = SUBSCRIPTION_CHANNEL_CAP + 50;
        for i in 0..overflow_count {
            tx.send(ev_created(&format!("test-{}.md", i))).unwrap();
        }

        // Give the pump time to process.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let dropped = reg.total_dropped().await;
        assert!(
            dropped > 0,
            "expected some drops under sustained overflow, got 0"
        );
        assert!(
            dropped <= overflow_count as u64,
            "drop counter should not exceed attempted sends"
        );
    }

    #[tokio::test]
    async fn test_prune_closed_removes_dead_subscriptions() {
        let (_tx, rx) = unbounded_channel::<VaultEvent>();
        let (dummy, _) = VaultWatcher::new(
            PathBuf::from("/tmp/nonexistent"),
            crate::watcher::WatcherConfig::default(),
        )
        .unwrap();
        let reg = SubscriptionRegistry::new(Arc::new(dummy), rx);

        // Create two subscriptions, drop one's receiver.
        let (_h_alive, _alive_rx) = reg
            .subscribe(EventFilter::default(), Some("sess-alive".into()))
            .await
            .unwrap();
        let (h_dead, dead_rx) = reg
            .subscribe(EventFilter::default(), Some("sess-dead".into()))
            .await
            .unwrap();
        drop(dead_rx);

        assert_eq!(reg.len().await, 2);
        let pruned = reg.prune_closed().await;
        assert_eq!(pruned, 1, "expected exactly one dead sub pruned");
        assert_eq!(reg.len().await, 1);
        // by_session should also be cleaned up.
        assert_eq!(
            reg.unsubscribe(&h_dead).await,
            false,
            "dead sub should have been removed by prune"
        );
    }

    #[tokio::test]
    async fn test_unsubscribe_session_cancels_all() {
        let (_tx, rx) = unbounded_channel::<VaultEvent>();
        let (dummy, _) = VaultWatcher::new(
            PathBuf::from("/tmp/nonexistent"),
            crate::watcher::WatcherConfig::default(),
        )
        .unwrap();
        let reg = SubscriptionRegistry::new(Arc::new(dummy), rx);

        let (_h1, _rx1) = reg
            .subscribe(EventFilter::default(), Some("sess-a".into()))
            .await
            .unwrap();
        let (_h2, _rx2) = reg
            .subscribe(EventFilter::default(), Some("sess-a".into()))
            .await
            .unwrap();
        let (_h3, _rx3) = reg
            .subscribe(EventFilter::default(), Some("sess-b".into()))
            .await
            .unwrap();

        assert_eq!(reg.len().await, 3);
        assert_eq!(reg.unsubscribe_session("sess-a").await, 2);
        assert_eq!(reg.len().await, 1);
    }
}
