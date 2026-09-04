use serde::Serialize;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};
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

#[allow(dead_code)]
struct EngineProcess {
    child: Child, // kept for future kill/timeout
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

pub struct EngineState {
    inner: Mutex<Option<EngineProcess>>,
    next_id: AtomicU64,
    data_dir: Mutex<Option<PathBuf>>,
}

impl EngineState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            next_id: AtomicU64::new(1),
            data_dir: Mutex::new(None),
        }
    }
}

fn repo_root() -> Result<PathBuf, EngineError> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| EngineError::Message("cannot resolve repo root".into()))?
        .to_path_buf())
}

fn engine_python(root: &Path) -> Result<PathBuf, EngineError> {
    let candidates = [
        root.join("engine")
            .join(".venv")
            .join("Scripts")
            .join("python.exe"),
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

fn spawn_engine(data_dir: &Path) -> Result<EngineProcess, EngineError> {
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
        .env("MEMSCOPE_DATA_DIR", data_dir.as_os_str())
        .spawn()
        .map_err(|e| EngineError::Message(format!("spawn engine failed: {e}")))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| EngineError::Message("engine stdin missing".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| EngineError::Message("engine stdout missing".into()))?;

    let mut proc = EngineProcess {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    };

    // Engine auto-inits on start; ensure data_dir via explicit app.init
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "app.init",
        "params": { "data_dir": data_dir.to_string_lossy() },
    });
    writeln!(proc.stdin, "{init_req}")
        .map_err(|e| EngineError::Message(format!("engine init write failed: {e}")))?;
    let mut line = String::new();
    proc.stdout
        .read_line(&mut line)
        .map_err(|e| EngineError::Message(format!("engine init read failed: {e}")))?;
    let resp: Value = serde_json::from_str(line.trim()).map_err(|e| {
        EngineError::Message(format!("engine init bad JSON: {e}; line={line}"))
    })?;
    if resp.get("error").is_some() {
        return Err(EngineError::Message(format!("engine init error: {resp}")));
    }
    Ok(proc)
}

fn ensure_engine(state: &EngineState, data_dir: &Path) -> Result<(), EngineError> {
    let mut guard = state
        .inner
        .lock()
        .map_err(|_| EngineError::Message("engine lock poisoned".into()))?;
    if guard.is_none() {
        *guard = Some(spawn_engine(data_dir)?);
    }
    Ok(())
}

fn call_engine_locked(
    state: &EngineState,
    method: &str,
    params: Value,
    timeout_secs: u64,
) -> Result<Value, EngineError> {
    let data_dir = state
        .data_dir
        .lock()
        .map_err(|_| EngineError::Message("data_dir lock poisoned".into()))?
        .clone()
        .ok_or_else(|| EngineError::Message("app data directory not set".into()))?;

    ensure_engine(state, &data_dir)?;

    let id = state.next_id.fetch_add(1, Ordering::SeqCst);
    let request = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });

    let mut guard = state
        .inner
        .lock()
        .map_err(|_| EngineError::Message("engine lock poisoned".into()))?;
    let proc = guard
        .as_mut()
        .ok_or_else(|| EngineError::Message("engine not running".into()))?;

    if let Err(e) = writeln!(proc.stdin, "{request}") {
        *guard = None;
        return Err(EngineError::Message(format!("write request failed: {e}")));
    }

    // Read response with timeout on a helper thread holding the line buffer only —
    // we keep the lock because stdio is not Sync across concurrent callers yet.
    let mut line = String::new();
    // Blocking read; callers pass method-appropriate timeout_secs for long work.
    // A hard wall-clock kill will be added with a dedicated reader thread later.
    let _timeout_secs = timeout_secs;
    loop {
        line.clear();
        match proc.stdout.read_line(&mut line) {
            Ok(0) => {
                *guard = None;
                return Err(EngineError::Message("engine closed stdout".into()));
            }
            Ok(_) => break,
            Err(e) => {
                *guard = None;
                return Err(EngineError::Message(format!("read engine stdout failed: {e}")));
            }
        }
    }
    drop(guard);

    let response: Value = serde_json::from_str(line.trim()).map_err(|e| {
        EngineError::Message(format!(
            "invalid engine JSON: {e}; line={}",
            line.chars().take(500).collect::<String>()
        ))
    })?;

    if let Some(err) = response.get("error") {
        // Prefer structured app error message for UI
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("engine error");
        let detail = err
            .get("data")
            .map(|d| d.to_string())
            .unwrap_or_default();
        return Err(EngineError::Message(if detail.is_empty() {
            msg.to_string()
        } else {
            format!("{msg} | {detail}")
        }));
    }

    response
        .get("result")
        .cloned()
        .ok_or_else(|| EngineError::Message(format!("engine response missing result: {response}")))
}

/// One-shot helper for tests (spawns, calls, kills).
#[cfg(test)]
fn call_engine_oneshot(method: &str, params: Value) -> Result<Value, EngineError> {
    use std::time::Duration;
    let root = repo_root()?;
    let python = engine_python(&root)?;
    let engine_dir = root.join("engine");
    let tmp = std::env::temp_dir().join(format!(
        "memscope-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp)
        .map_err(|e| EngineError::Message(format!("temp dir: {e}")))?;

    let mut child = Command::new(&python)
        .arg("-m")
        .arg("memscope_engine")
        .current_dir(&engine_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("PYTHONUTF8", "1")
        .env("MEMSCOPE_DATA_DIR", &tmp)
        .spawn()
        .map_err(|e| EngineError::Message(format!("spawn engine failed: {e}")))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| EngineError::Message("stdin missing".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| EngineError::Message("stdout missing".into()))?;
    let mut reader = BufReader::new(stdout);

    let request = json!({
        "jsonrpc": "2.0",
        "id": "t1",
        "method": method,
        "params": params,
    });
    writeln!(stdin, "{request}")
        .map_err(|e| EngineError::Message(format!("write failed: {e}")))?;
    drop(stdin);

    let mut line = String::new();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let res = reader.read_line(&mut line).map(|_| line);
        let _ = tx.send(res);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(60))
        .map_err(|_| EngineError::Message("timeout".into()))?
        .map_err(|e| EngineError::Message(format!("read: {e}")))?;
    let _ = child.kill();
    let _ = child.wait();

    let response: Value = serde_json::from_str(line.trim())
        .map_err(|e| EngineError::Message(format!("json: {e}")))?;
    if let Some(err) = response.get("error") {
        return Err(EngineError::Message(format!("engine error: {err}")));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| EngineError::Message("missing result".into()))
}

#[tauri::command]
fn get_app_paths(app: AppHandle, state: State<'_, EngineState>) -> Result<Value, EngineError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| EngineError::Message(format!("app_data_dir: {e}")))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| EngineError::Message(format!("create app data dir: {e}")))?;
    *state
        .data_dir
        .lock()
        .map_err(|_| EngineError::Message("lock".into()))? = Some(dir.clone());
    ensure_engine(&state, &dir)?;
    call_engine_locked(&state, "app.paths", json!({}), 30)
}

#[tauri::command]
fn engine_call(
    state: State<'_, EngineState>,
    method: String,
    params: Option<Value>,
    timeout_secs: Option<u64>,
) -> Result<Value, EngineError> {
    let timeout = timeout_secs.unwrap_or(match method.as_str() {
        "evidence.analyze_basic" => 600,
        "evidence.import" => 600,
        _ => 120,
    });
    call_engine_locked(&state, &method, params.unwrap_or_else(|| json!({})), timeout)
}

#[tauri::command]
fn smoke_e2e(state: State<'_, EngineState>) -> Result<Value, EngineError> {
    let engine = call_engine_locked(&state, "smoke.e2e", json!({}), 60)?;
    let vol_ok = engine
        .pointer("/volatility/ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(json!({ "ok": vol_ok, "engine": engine }))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(EngineState::new())
        .setup(|app| {
            let dir = app
                .path()
                .app_data_dir()
                .map_err(|e| std::io::Error::other(format!("app_data_dir: {e}")))?;
            std::fs::create_dir_all(&dir)?;
            let state = app.state::<EngineState>();
            *state
                .data_dir
                .lock()
                .map_err(|_| std::io::Error::other("lock"))? = Some(dir.clone());
            // Best-effort warm start; UI can retry via get_app_paths
            let _ = ensure_engine(&state, &dir);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_paths,
            engine_call,
            smoke_e2e
        ])
        .run(tauri::generate_context!())
        .expect("error while running MemScope");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_volatility_init_via_ipc() {
        let result = call_engine_oneshot("smoke.e2e", json!({})).expect("engine IPC");
        assert_eq!(result.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            result.pointer("/volatility/ok").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn engine_app_init_and_schema() {
        let result = call_engine_oneshot("app.paths", json!({})).expect("paths");
        assert!(result.get("db_path").is_some());
    }
}
