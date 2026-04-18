//! End-to-end integration test for subscribe/fetch/unsubscribe_vault_events.
//!
//! Spawns `turbovault --transport stdio` as a subprocess and drives it
//! over JSON-RPC. STDIO (rather than WebSocket) is used because the
//! pull model has no transport-specific requirements and STDIO is the
//! lowest-friction path for CI.
//!
//! Skip behavior: setting `TV_SKIP_INTEGRATION_TESTS=1` makes the test
//! exit early as `ok`. This matches the pattern used by other TurboVault
//! CI tiers that cannot afford subprocess spawning.

use std::process::Stdio;
use std::time::Duration;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimal JSON-RPC wrapper. Holds the child process and its piped
/// stdio so the test can send newline-delimited frames and await
/// responses by request id.
struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpClient {
    /// Spawn `turbovault` in stdio mode against the given vault path.
    async fn spawn(vault_path: &std::path::Path, bin_path: &std::path::Path) -> Self {
        let mut cmd = Command::new(bin_path);
        cmd.arg("--transport")
            .arg("stdio")
            .arg("--vault")
            .arg(vault_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Route the server's structured logs to /dev/null. They
            // would otherwise interleave with test output and make
            // failures harder to read. Errors we care about surface as
            // JSON-RPC responses anyway.
            .stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .expect("failed to spawn turbovault binary; did `cargo build` run?");
        let stdin = child.stdin.take().expect("child stdin missing");
        let stdout = child.stdout.take().expect("child stdout missing");
        Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        }
    }

    /// Send a JSON-RPC request and await the matching response, keyed
    /// by id. Unsolicited notifications (e.g. logging) are skipped.
    async fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&req).expect("serialize request");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write to child stdin");
        self.stdin.flush().await.expect("flush stdin");

        // Read frames until we see one with our id.
        loop {
            let frame = timeout(REQUEST_TIMEOUT, self.read_frame())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for response to {}", method));
            if let Some(resp_id) = frame.get("id").and_then(|v| v.as_u64()) {
                if resp_id == id {
                    return frame;
                }
            }
            // Non-matching frame (notification or interleaved id);
            // drop and keep reading.
        }
    }

    async fn read_frame(&mut self) -> serde_json::Value {
        let mut buf = String::new();
        let n = self
            .stdout
            .read_line(&mut buf)
            .await
            .expect("read child stdout");
        assert!(n > 0, "turbovault stdout closed unexpectedly");
        serde_json::from_str(buf.trim_end()).unwrap_or_else(|e| {
            panic!("malformed JSON frame: {} ({:?})", e, buf)
        })
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Best-effort cleanup; the process is a test subprocess so we
        // don't care about orderly shutdown. `start_kill` is the
        // non-blocking equivalent usable from a sync Drop.
        let _ = self.child.start_kill();
    }
}

fn skip_if_requested() -> bool {
    std::env::var("TV_SKIP_INTEGRATION_TESTS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Locate the compiled turbovault binary. Cargo sets
/// `CARGO_BIN_EXE_<name>` for integration tests, which is the
/// canonical lookup for this scenario.
fn binary_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_turbovault"))
}

#[tokio::test]
async fn test_subscribe_fetch_unsubscribe_end_to_end() {
    if skip_if_requested() {
        eprintln!("TV_SKIP_INTEGRATION_TESTS=1 → skipping subprocess integration test");
        return;
    }

    // Fresh temp vault with a seed file so the VaultManager has
    // something to scan on startup.
    let vault = TempDir::new().expect("tempdir");
    tokio::fs::write(vault.path().join("seed.md"), "# seed\n")
        .await
        .expect("write seed");

    let bin = binary_path();
    let mut client = McpClient::spawn(vault.path(), &bin).await;

    // 1. initialize handshake per MCP.
    let init = client
        .call(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "fetch-vault-events-test", "version": "0.1.0" }
            }),
        )
        .await;
    assert!(
        init.get("result").is_some(),
        "initialize failed: {}",
        init
    );

    // Many MCP servers require the initialized notification before
    // accepting tool calls. Send it as a fire-and-forget — no id, no
    // response expected.
    let init_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    let mut line = serde_json::to_string(&init_notif).unwrap();
    line.push('\n');
    client.stdin.write_all(line.as_bytes()).await.unwrap();
    client.stdin.flush().await.unwrap();

    // 2. Subscribe with a filter that matches markdown files in the
    // vault root. Pull the handle out of the tool response envelope.
    let sub_resp = client
        .call(
            "tools/call",
            serde_json::json!({
                "name": "subscribe_vault_events",
                "arguments": {
                    "filter": { "globs": ["**/*.md"] }
                }
            }),
        )
        .await;
    let handle = extract_tool_json_field(&sub_resp, "handle")
        .as_str()
        .expect("handle field should be a string")
        .to_string();
    assert!(!handle.is_empty(), "handle should be a UUID v4 string");

    // 3. Create a file inside the watched vault. Give notify a
    // moment to pick it up, observed latency on macOS/Linux is a few
    // hundred ms under normal load.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let created = vault.path().join("probe.md");
    tokio::fs::write(&created, "# probe\n")
        .await
        .expect("write probe file");

    // 4. Fetch with a short long-poll. One file-created event is the
    // minimum we expect; bulk platform activity may add more.
    let fetch_resp = client
        .call(
            "tools/call",
            serde_json::json!({
                "name": "fetch_vault_events",
                "arguments": {
                    "handle": handle,
                    "timeout_ms": 2000
                }
            }),
        )
        .await;
    let events = extract_tool_json_field(&fetch_resp, "events")
        .as_array()
        .expect("events must be an array")
        .clone();
    assert!(
        !events.is_empty(),
        "expected at least one event after writing probe.md, got: {}",
        fetch_resp
    );

    // At least one delivered event should be a "created" for our
    // probe file. Matching by suffix tolerates platform
    // canonicalization (e.g. /private/tmp vs /tmp on macOS).
    let saw_created = events.iter().any(|e| {
        let kind = e.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let path = e.get("path").and_then(|v| v.as_str()).unwrap_or("");
        kind == "created" && path.ends_with("probe.md")
    });
    assert!(
        saw_created,
        "expected a created event for probe.md in: {:?}",
        events
    );

    // 5. Unsubscribe.
    let unsub_resp = client
        .call(
            "tools/call",
            serde_json::json!({
                "name": "unsubscribe_vault_events",
                "arguments": { "handle": handle }
            }),
        )
        .await;
    let removed = extract_tool_json_field(&unsub_resp, "removed")
        .as_bool()
        .expect("removed must be a bool");
    assert!(removed, "unsubscribe must report removed=true");
}

/// Reach into a StandardResponse tool payload and yank a named field
/// from its `data` object. The tool layer wraps everything in
/// `{ vault, operation, data: {...}, ... }` and `tools/call` nests
/// that inside JSON-serialized MCP content, which has shifted shape
/// across TurboMCP versions. This helper tries the common layouts
/// (content[0].text parsed as JSON, content[0].json, content as value)
/// and panics with a helpful diagnostic if the field can't be found.
fn extract_tool_json_field(resp: &serde_json::Value, field: &str) -> serde_json::Value {
    let result = resp
        .get("result")
        .unwrap_or_else(|| panic!("no result in response: {}", resp));

    // Most recent TurboMCP shapes wrap tool output as
    // { content: [ { type: "text", text: "<json>" } ], ... }.
    if let Some(content) = result.get("content").and_then(|v| v.as_array()) {
        for item in content {
            if let Some(text) = item.get("text").and_then(|v| v.as_str()) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(text) {
                    if let Some(v) = find_field(&parsed, field) {
                        return v;
                    }
                }
            }
            if let Some(json) = item.get("json") {
                if let Some(v) = find_field(json, field) {
                    return v;
                }
            }
        }
    }

    // Fallback: maybe result itself has the shape.
    if let Some(v) = find_field(result, field) {
        return v;
    }
    panic!("could not find field {:?} in response: {}", field, resp);
}

fn find_field(v: &serde_json::Value, field: &str) -> Option<serde_json::Value> {
    // Handle StandardResponse { data: { <field>: ... } } and direct.
    if let Some(direct) = v.get(field) {
        return Some(direct.clone());
    }
    if let Some(data) = v.get("data") {
        if let Some(nested) = data.get(field) {
            return Some(nested.clone());
        }
    }
    None
}
