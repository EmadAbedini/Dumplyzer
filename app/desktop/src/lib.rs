use serde::Serialize;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("{0}")]
    Message(String),
}

impl Serialize for EngineError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

fn repo_root() -> Result<PathBuf, EngineError> {
    // app/desktop/src -> app/desktop -> app -> repo
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| EngineError::Message("cannot resolve repo root".into()))?
        .to_path_buf())
}

fn engine_python(root: &Path) -> Result<PathBuf, EngineError> {
    let candidates = [
        root.join("engine").join(".venv").join("Scripts").join("python.exe"),
        root.join("engine").join(".venv").join("bin").join("python"),
    ];
    for c in candidates {
        if c.is_file() {
            return Ok(c);
        }
    }
    Err(EngineError::Message(
        "engine venv python not found (engine/.venv)".into(),
    ))
}

fn call_engine(method: &str, params: Value) -> Result<Value, EngineError> {
    let root = repo_root()?;
    let python = engine_python(&root)?;
    let engine_dir = root.join("engine");

    let mut child = Command::new(&python)
        .arg("-m")
        .arg("memscope_engine")
        .current_dir(&engine_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PYTHONUTF8", "1")
        .env("PYTHONIOENCODING", "utf-8")
        // Do not use shell.
        .spawn()
        .map_err(|e| EngineError::Message(format!("spawn engine failed: {e}")))?;

    let request = json!({
        "jsonrpc": "2.0",
        "id": "smoke-1",
        "method": method,
        "params": params,
    });

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| EngineError::Message("engine stdin missing".into()))?;
        writeln!(stdin, "{request}")
            .map_err(|e| EngineError::Message(format!("write request failed: {e}")))?;
        // Close stdin by dropping after this block ends — drop child.stdin
    }
    drop(child.stdin.take());

    // Bounded wait: read one NDJSON response line.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| EngineError::Message("engine stdout missing".into()))?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    // Simple timeout loop using try_wait + short reads is complex without threads;
    // use a helper thread with channel timeout.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = reader.read_line(&mut line).map(|_| line);
        let _ = tx.send(res);
    });

    let line = rx
        .recv_timeout(Duration::from_secs(60))
        .map_err(|_| EngineError::Message("engine response timed out (60s)".into()))?
        .map_err(|e| EngineError::Message(format!("read engine stdout failed: {e}")))?;

    let _ = child.kill();
    let _ = child.wait();

    let response: Value = serde_json::from_str(line.trim()).map_err(|e| {
        // Include stderr if available later; for now surface parse context.
        EngineError::Message(format!(
            "invalid engine JSON: {e}; line={}",
            line.chars().take(500).collect::<String>()
        ))
    })?;

    if let Some(err) = response.get("error") {
        return Err(EngineError::Message(format!("engine error: {err}")));
    }

    response
        .get("result")
        .cloned()
        .ok_or_else(|| EngineError::Message(format!("engine response missing result: {response}")))
}

#[tauri::command]
fn smoke_e2e() -> Result<Value, EngineError> {
    let engine = call_engine("smoke.e2e", json!({}))?;
    let vol_ok = engine
        .pointer("/volatility/ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(json!({
        "ok": vol_ok,
        "engine": engine,
    }))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![smoke_e2e])
        .run(tauri::generate_context!())
        .expect("error while running MemScope");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_volatility_init_via_ipc() {
        let result = call_engine("smoke.e2e", json!({})).expect("engine IPC");
        assert_eq!(result.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            result
                .pointer("/volatility/ok")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        let ver = result
            .pointer("/volatility/volatility3_version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(!ver.is_empty(), "missing volatility3 version");
    }
}
