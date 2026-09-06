use serde::Serialize;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tauri::{Manager, RunEvent, State};
use thiserror::Error;

mod engine;

use engine::{
    configure_engine_command, memscope_data_dir, resolve_engine, resolve_inputs_from_env,
    EngineLaunchPlan,
};

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

impl From<String> for EngineError {
    fn from(value: String) -> Self {
        EngineError::Message(value)
    }
}

#[allow(dead_code)]
struct EngineProcess {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct EngineState {
    inner: Mutex<Option<EngineProcess>>,
    next_id: AtomicU64,
    data_dir: Mutex<Option<PathBuf>>,
    exe_dir: Mutex<Option<PathBuf>>,
    resource_dir: Mutex<Option<PathBuf>>,
}

impl EngineState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            next_id: AtomicU64::new(1),
            data_dir: Mutex::new(None),
            exe_dir: Mutex::new(None),
            resource_dir: Mutex::new(None),
        }
    }

    fn shutdown(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
    }

    fn launch_dirs(&self) -> (Option<PathBuf>, Option<PathBuf>) {
        let exe = self.exe_dir.lock().ok().and_then(|g| g.clone());
        let resource = self.resource_dir.lock().ok().and_then(|g| g.clone());
        (exe, resource)
    }
}

fn drain_stderr(stderr: std::process::ChildStderr, log_path: PathBuf) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let cleaned = line.replace('\0', "").trim_end().to_string();
                    if let Some(ref mut f) = file {
                        let _ = writeln!(f, "{cleaned}");
                    }
                }
                Err(_) => break,
            }
        }
    });
}

fn launch_plan_for_state(state: &EngineState) -> Result<EngineLaunchPlan, EngineError> {
    let (exe_dir, resource_dir) = state.launch_dirs();
    resolve_engine(&resolve_inputs_from_env(exe_dir, resource_dir)).map_err(EngineError::from)
}

fn spawn_engine(state: &EngineState, data_dir: &Path) -> Result<EngineProcess, EngineError> {
    let plan = launch_plan_for_state(state)?;
    std::fs::create_dir_all(data_dir.join("logs"))
        .map_err(|e| EngineError::Message(format!("create log dir: {e}")))?;
    std::fs::create_dir_all(data_dir.join("tmp"))
        .map_err(|e| EngineError::Message(format!("create tmp dir: {e}")))?;

    let mut cmd = Command::new(&plan.python);
    configure_engine_command(&mut cmd, &plan, data_dir);

    let mut child = cmd
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
    if let Some(stderr) = child.stderr.take() {
        drain_stderr(stderr, data_dir.join("logs").join("engine-stderr.log"));
    }

    let mut proc = EngineProcess {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    };

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
        *guard = Some(spawn_engine(state, data_dir)?);
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

    let _timeout_secs = timeout_secs;
    let mut line = String::new();
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
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("engine error");
        let detail = err.get("data").map(|d| d.to_string()).unwrap_or_default();
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
    let plan = resolve_engine(&resolve_inputs_from_env(None, None))?;
    let tmp = std::env::temp_dir().join(format!(
        "memscope-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).map_err(|e| EngineError::Message(format!("temp dir: {e}")))?;
    std::fs::create_dir_all(tmp.join("logs"))
        .map_err(|e| EngineError::Message(format!("log dir: {e}")))?;
    std::fs::create_dir_all(tmp.join("tmp"))
        .map_err(|e| EngineError::Message(format!("tmp dir: {e}")))?;

    let mut cmd = Command::new(&plan.python);
    configure_engine_command(&mut cmd, &plan, &tmp);
    let mut child = cmd
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
    if let Some(stderr) = child.stderr.take() {
        drain_stderr(stderr, tmp.join("logs").join("engine-stderr.log"));
    }
    let mut reader = BufReader::new(stdout);

    let request = json!({
        "jsonrpc": "2.0",
        "id": "t1",
        "method": method,
        "params": params,
    });
    writeln!(stdin, "{request}").map_err(|e| EngineError::Message(format!("write failed: {e}")))?;
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

fn bind_data_dir(state: &EngineState, dir: PathBuf) -> Result<PathBuf, EngineError> {
    std::fs::create_dir_all(&dir)
        .map_err(|e| EngineError::Message(format!("create app data dir: {e}")))?;
    *state
        .data_dir
        .lock()
        .map_err(|_| EngineError::Message("lock".into()))? = Some(dir.clone());
    Ok(dir)
}

#[tauri::command]
fn get_app_paths(state: State<'_, EngineState>) -> Result<Value, EngineError> {
    let dir = bind_data_dir(&state, memscope_data_dir()?)?;
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
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(EngineState::new())
        .setup(|app| {
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(Path::to_path_buf));
            let resource_dir = app.path().resource_dir().ok();
            let state = app.state::<EngineState>();
            *state
                .exe_dir
                .lock()
                .map_err(|_| std::io::Error::other("lock"))? = exe_dir;
            *state
                .resource_dir
                .lock()
                .map_err(|_| std::io::Error::other("lock"))? = resource_dir;
            let dir = memscope_data_dir().map_err(std::io::Error::other)?;
            std::fs::create_dir_all(&dir)?;
            *state
                .data_dir
                .lock()
                .map_err(|_| std::io::Error::other("lock"))? = Some(dir.clone());
            let _ = ensure_engine(&state, &dir);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_paths,
            engine_call,
            smoke_e2e
        ])
        .build(tauri::generate_context!())
        .expect("error while running MemScope");

    app.run(|app_handle, event| {
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
            app_handle.state::<EngineState>().shutdown();
        }
    });
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
        assert_eq!(
            result
                .pointer("/volatility/engine_version")
                .and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn engine_app_init_and_schema() {
        let result = call_engine_oneshot("app.paths", json!({})).expect("paths");
        assert!(result.get("db_path").is_some());
        let db = result.get("db_path").and_then(|v| v.as_str()).unwrap();
        assert!(
            db.contains("memscope-test-"),
            "oneshot IPC must use an isolated temp data dir: {db}"
        );
    }

    #[test]
    fn repo_root_is_workspace() {
        let root = engine::repo_root_from_manifest().expect("repo");
        assert!(root.join("engine").join("pyproject.toml").is_file());
        assert!(root.join("app").join("desktop").join("tauri.conf.json").is_file());
    }
}
