use serde::Serialize;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{Manager, RunEvent, State, WebviewEvent, WindowEvent};
use thiserror::Error;

mod engine;
mod drag_drop;

use engine::{
    cleanup_session_temp, configure_engine_command, memscope_data_dir, resolve_engine,
    resolve_inputs_from_env, user_data_subdir, EngineLaunchPlan,
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
        if let Ok(dir_guard) = self.data_dir.lock() {
            if let Some(dir) = dir_guard.as_ref() {
                cleanup_session_temp(dir);
            }
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

const SPLASH_MS: u64 = 2000;
/// Minimum time the native splash window stays visible before the main UI is shown.
static SPLASH_PHASE: AtomicBool = AtomicBool::new(true);

const MAIN_MIN_WIDTH: f64 = 900.0;
/// Sidebar at the default 13px font: top bar + evidence + 16 nav items + one
/// extra item of space below About (~625px). 640px covers DPI rounding.
const MAIN_MIN_HEIGHT: f64 = 640.0;

fn reveal_main_window(app: &tauri::AppHandle) {
    if let Some(main) = app.get_webview_window("main") {
        let _ = main.set_min_size(Some(tauri::LogicalSize::new(MAIN_MIN_WIDTH, MAIN_MIN_HEIGHT)));
        let _ = main.unminimize();
        apply_windows_shell_icons(&main);
        disable_default_context_menu(&main);
        let _ = main.show();
        let _ = main.maximize();
        let _ = main.set_focus();
        drag_drop::attach_after_show(app, &main);
    }
    SPLASH_PHASE.store(false, Ordering::SeqCst);
    if let Some(splash) = app.get_webview_window("splash") {
        let _ = splash.hide();
        let _ = splash.close();
    }
}

/// Taskbar / Alt+Tab use ICON_BIG. Tauri only sets ICON_SMALL, and historically
/// that bitmap was the first ICO frame (16×16), which Windows then stretched.
#[cfg(windows)]
fn apply_windows_shell_icons(window: &tauri::WebviewWindow) {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetAncestor, GetSystemMetrics, LoadImageW, SendMessageW, GA_ROOT, ICON_BIG, ICON_SMALL,
        IDI_APPLICATION, IMAGE_ICON, LR_DEFAULTCOLOR, SM_CXSMICON, WM_SETICON,
    };

    let Ok(hwnd) = window.hwnd() else {
        return;
    };
    let hwnd = HWND(hwnd.0 as *mut c_void);
    unsafe {
        let root = GetAncestor(hwnd, GA_ROOT);
        let target = if root.is_invalid() { hwnd } else { root };
        let Ok(hinst) = GetModuleHandleW(PCWSTR::null()) else {
            return;
        };
        // Caption icons are drawn at SM_CXSMICON (16×16 at 96 DPI). A larger
        // HICON makes Windows reserve extra width before the title while still
        // painting a tiny glyph — the logo looks small and a gap appears.
        let small = GetSystemMetrics(SM_CXSMICON).max(16);
        if let Ok(handle) = LoadImageW(
            Some(hinst.into()),
            IDI_APPLICATION,
            IMAGE_ICON,
            small,
            small,
            LR_DEFAULTCOLOR,
        ) {
            SendMessageW(
                target,
                WM_SETICON,
                Some(WPARAM(ICON_SMALL as usize)),
                Some(LPARAM(handle.0 as isize)),
            );
        }
        if let Ok(handle) = LoadImageW(
            Some(hinst.into()),
            IDI_APPLICATION,
            IMAGE_ICON,
            256,
            256,
            LR_DEFAULTCOLOR,
        ) {
            SendMessageW(
                target,
                WM_SETICON,
                Some(WPARAM(ICON_BIG as usize)),
                Some(LPARAM(handle.0 as isize)),
            );
        }
    }
}

#[cfg(not(windows))]
fn apply_windows_shell_icons(_window: &tauri::WebviewWindow) {}

fn disable_default_context_menu(window: &tauri::WebviewWindow) {
    #[cfg(windows)]
    {
        let _ = window.with_webview(|webview| unsafe {
            if let Ok(core) = webview.controller().CoreWebView2() {
                if let Ok(settings) = core.Settings() {
                    let _ = settings.SetAreDefaultContextMenusEnabled(false);
                }
            }
        });
    }
    #[cfg(not(windows))]
    let _ = window;
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
    let dead = match guard.as_mut() {
        Some(proc) => !matches!(proc.child.try_wait(), Ok(None)),
        None => false,
    };
    if dead {
        *guard = None;
    }
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
async fn get_app_paths(state: State<'_, EngineState>) -> Result<Value, EngineError> {
    let dir = bind_data_dir(&state, memscope_data_dir()?)?;
    ensure_engine(&state, &dir)?;
    call_engine_locked(&state, "app.paths", json!({}), 30)
}

/// Must stay in sync with About links in `app/frontend/src/lib/about.ts`.
const ALLOWED_EXTERNAL_URLS: &[&str] = &[
    "https://github.com/EmadAbedini/Dumplyzer",
    "https://www.linkedin.com/in/emad-abedini",
    "https://www.apache.org/licenses/LICENSE-2.0",
    "https://github.com/EmadAbedini/Dumplyzer/blob/main/THIRD_PARTY_NOTICES.md",
];

#[tauri::command]
fn open_external_url(url: String) -> Result<(), EngineError> {
    if !ALLOWED_EXTERNAL_URLS.contains(&url.as_str()) {
        return Err(EngineError::Message("URL is not allowed.".into()));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| EngineError::Message(format!("open url: {e}")))?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        Err(EngineError::Message(
            "Opening links is only implemented on Windows.".into(),
        ))
    }
}

#[tauri::command]
fn open_user_folder(kind: String) -> Result<(), EngineError> {
    let root = memscope_data_dir()?;
    let target = user_data_subdir(&kind).map_err(EngineError::from)?;
    std::fs::create_dir_all(&target)
        .map_err(|e| EngineError::Message(format!("create folder: {e}")))?;
    let root_abs = root.canonicalize().unwrap_or(root);
    let target_abs = target.canonicalize().unwrap_or(target);
    if !target_abs.starts_with(&root_abs) {
        return Err(EngineError::Message(
            "Folder is outside the Dumplyzer data directory.".into(),
        ));
    }
    #[cfg(windows)]
    {
        std::process::Command::new("explorer.exe")
            .arg(&target_abs)
            .spawn()
            .map_err(|e| EngineError::Message(format!("open folder: {e}")))?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        Err(EngineError::Message(
            "Opening folders is only implemented on Windows.".into(),
        ))
    }
}

#[tauri::command]
fn open_local_folder(path: String) -> Result<(), EngineError> {
    let requested = PathBuf::from(path.trim());
    if requested.as_os_str().is_empty() {
        return Err(EngineError::Message("Folder path is empty.".into()));
    }
    let root = memscope_data_dir()?;
    let root_abs = root.canonicalize().unwrap_or(root);
    let target = if requested.is_file() {
        requested
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| EngineError::Message("Folder path is empty.".into()))?
    } else {
        requested
    };
    if !target.exists() {
        return Err(EngineError::Message("Folder was not found.".into()));
    }
    let target_abs = target
        .canonicalize()
        .map_err(|e| EngineError::Message(format!("open folder: {e}")))?;
    if !path_is_within(&target_abs, &root_abs) {
        return Err(EngineError::Message(
            "Folder is outside the Dumplyzer data directory.".into(),
        ));
    }
    let to_open = if target_abs.is_dir() {
        target_abs
    } else {
        target_abs
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| EngineError::Message("Folder was not found.".into()))?
    };
    #[cfg(windows)]
    {
        std::process::Command::new("explorer.exe")
            .arg(&to_open)
            .spawn()
            .map_err(|e| EngineError::Message(format!("open folder: {e}")))?;
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        Err(EngineError::Message(
            "Opening folders is only implemented on Windows.".into(),
        ))
    }
}

fn path_is_within(child: &Path, parent: &Path) -> bool {
    child.starts_with(parent)
}

/// Copy a generated export ZIP (under application data / exports) to a user Save As path.

#[tauri::command]
fn copy_export_file(source: String, destination: String) -> Result<(), EngineError> {
    let dest = PathBuf::from(destination.trim());
    if dest.as_os_str().is_empty() {
        return Err(EngineError::Message("Save location is empty.".into()));
    }
    if !dest.is_absolute() {
        return Err(EngineError::Message("Save location must be an absolute path.".into()));
    }
    let dest_name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !dest_name.ends_with(".zip") {
        return Err(EngineError::Message("Save location must be a .zip file.".into()));
    }
    if dest.is_dir() {
        return Err(EngineError::Message("Save location is a folder.".into()));
    }
    let parent = dest.parent().ok_or_else(|| {
        EngineError::Message("Save location has no parent folder.".into())
    })?;
    if !parent.is_dir() {
        return Err(EngineError::Message("Save folder does not exist.".into()));
    }

    let data = memscope_data_dir()?;
    let exports = data.join("exports");
    std::fs::create_dir_all(&exports)
        .map_err(|e| EngineError::Message(format!("create exports folder: {e}")))?;
    let exports_abs = exports.canonicalize().unwrap_or(exports);
    let src = PathBuf::from(source.trim());
    let src_abs = src
        .canonicalize()
        .map_err(|e| EngineError::Message(format!("export file not found: {e}")))?;
    if !src_abs.is_file() {
        return Err(EngineError::Message("Export file is missing.".into()));
    }
    if !path_is_within(&src_abs, &exports_abs) {
        return Err(EngineError::Message(
            "Refusing to copy a file outside the exports directory.".into(),
        ));
    }
    let src_ext = src_abs
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .eq_ignore_ascii_case("zip");
    if !src_ext {
        return Err(EngineError::Message("Export file is not a ZIP archive.".into()));
    }
    if let Ok(dest_abs) = dest.canonicalize() {
        if dest_abs == src_abs {
            return Ok(());
        }
    }
    std::fs::copy(&src_abs, &dest)
        .map_err(|e| EngineError::Message(format!("save copy failed: {e}")))?;
    Ok(())
}

fn write_job_cancel_marker(state: &EngineState, job_id: &str) -> Result<(), EngineError> {
    if job_id.is_empty()
        || job_id.len() > 80
        || !job_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(EngineError::Message("Invalid job id.".into()));
    }
    let data_dir = state
        .data_dir
        .lock()
        .map_err(|_| EngineError::Message("data_dir lock poisoned".into()))?
        .clone()
        .ok_or_else(|| EngineError::Message("app data directory not set".into()))?;
    let dir = data_dir.join("tmp").join("job-cancel");
    std::fs::create_dir_all(&dir)
        .map_err(|e| EngineError::Message(format!("create cancel marker dir: {e}")))?;
    std::fs::write(dir.join(job_id), b"1")
        .map_err(|e| EngineError::Message(format!("write cancel marker: {e}")))?;
    Ok(())
}

#[tauri::command]
async fn engine_call(
    app: tauri::AppHandle,
    method: String,
    params: Option<Value>,
    timeout_secs: Option<u64>,
) -> Result<Value, EngineError> {
    // Import and analysis are queued as engine jobs and return immediately.
    // Long timeouts remain only for methods that still wait on the RPC result.
    let params = params.unwrap_or_else(|| json!({}));
    let timeout = timeout_secs.unwrap_or(match method.as_str() {
        "smoke.e2e" => 90,
        _ => 120,
    });
    // Marker is visible to the Python worker without waiting for the GIL-bound RPC loop.
    if method == "jobs.cancel" {
        if let Some(job_id) = params.get("job_id").and_then(|v| v.as_str()) {
            let state = app.state::<EngineState>();
            let _ = write_job_cancel_marker(&state, job_id);
        }
    }
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<EngineState>();
        call_engine_locked(&state, &method, params, timeout)
    })
    .await
    .map_err(|e| EngineError::Message(format!("engine worker failed: {e}")))?
}

#[tauri::command]
async fn smoke_e2e(state: State<'_, EngineState>) -> Result<Value, EngineError> {
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
        .on_window_event(|window, event| {
            if window.label().starts_with("plugin-output-") {
                if matches!(event, WindowEvent::Focused(true)) {
                    if let Some(webview) = window.app_handle().get_webview_window(window.label()) {
                        apply_windows_shell_icons(&webview);
                        disable_default_context_menu(&webview);
                    }
                }
                return;
            }
            if window.label() != "main" {
                return;
            }
            match event {
                WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed => {
                    drag_drop::teardown();
                }
                WindowEvent::DragDrop(drag) => {
                    drag_drop::emit_tauri_drag(window.app_handle(), drag);
                }
                _ => {}
            }
        })
        .on_webview_event(|webview, event| {
            if webview.label() != "main" {
                return;
            }
            if let WebviewEvent::DragDrop(drag) = event {
                drag_drop::emit_tauri_drag(webview.app_handle(), drag);
            }
        })
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
            if let Some(main) = app.get_webview_window("main") {
                let _ = main.set_min_size(Some(tauri::LogicalSize::new(MAIN_MIN_WIDTH, MAIN_MIN_HEIGHT)));
                let _ = main.hide();
                apply_windows_shell_icons(&main);
                disable_default_context_menu(&main);
            }
            if let Some(splash) = app.get_webview_window("splash") {
                let _ = splash.set_decorations(false);
                let _ = splash.set_shadow(false);
                let _ = splash.set_always_on_top(true);
                let _ = splash.center();
                disable_default_context_menu(&splash);
                let _ = splash.show();
                let _ = splash.set_focus();
            }
            let engine_handle = app.handle().clone();
            let engine_dir = dir.clone();
            std::thread::spawn(move || {
                let state = engine_handle.state::<EngineState>();
                let _ = ensure_engine(&state, &engine_dir);
            });
            let splash_handle = app.handle().clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(SPLASH_MS));
                let handle = splash_handle.clone();
                let _ = splash_handle.run_on_main_thread(move || {
                    reveal_main_window(&handle);
                });
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_paths,
            open_user_folder,
            open_local_folder,
            open_external_url,
            copy_export_file,
            engine_call,
            smoke_e2e
        ])
        .build(tauri::generate_context!())
        .expect("error while running Dumplyzer");

    app.run(|app_handle, event| match event {
        RunEvent::ExitRequested { api, .. } => {
            if SPLASH_PHASE.load(Ordering::SeqCst) {
                api.prevent_exit();
                reveal_main_window(app_handle);
                return;
            }
            drag_drop::teardown();
            app_handle.state::<EngineState>().shutdown();
        }
        RunEvent::Exit => {
            drag_drop::teardown();
            app_handle.state::<EngineState>().shutdown();
        }
        RunEvent::WindowEvent {
            label,
            event: WindowEvent::Destroyed,
            ..
        } => {
            if label == "splash" && SPLASH_PHASE.load(Ordering::SeqCst) {
                reveal_main_window(app_handle);
            }
            if label == "main" {
                for window in app_handle.webview_windows().values() {
                    if window.label().starts_with("plugin-output-") {
                        let _ = window.close();
                    }
                }
            }
        }
        _ => {}
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
        let conf = std::fs::read_to_string(root.join("app").join("desktop").join("tauri.conf.json"))
            .expect("tauri.conf.json");
        assert!(
            conf.contains("\"minWidth\": 900") && conf.contains("\"minHeight\": 640"),
            "main window must declare a native minimum size"
        );
        assert!(
            conf.contains("\"theme\": \"Light\""),
            "main window default theme must be Light"
        );
        let frontend = root.join("app").join("frontend");
        assert!(frontend.join("splash.html").is_file(), "missing splash.html");
        assert!(
            frontend
                .join("src")
                .join("assets")
                .join("dumplyzer-splash.jpg")
                .is_file(),
            "missing dumplyzer-splash.jpg"
        );
    }

    #[test]
    fn windows_icon_assets_are_present() {
        let root = engine::repo_root_from_manifest().expect("repo");
        let icons = root.join("app").join("desktop").join("icons");
        for name in ["32x32.png", "128x128.png", "128x128@2x.png", "icon.ico", "icon.icns", "Dumplyzer.png"] {
            let path = icons.join(name);
            assert!(path.is_file(), "missing {}", path.display());
        }
        let ico = std::fs::read(icons.join("icon.ico")).expect("icon.ico");
        assert!(ico.len() > 64, "icon.ico too small");
        assert_eq!(&ico[0..4], &[0, 0, 1, 0], "icon.ico must be a Windows ICO");
        let png32 = std::fs::read(icons.join("32x32.png")).expect("32 png");
        assert_eq!(&png32[0..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(png32[25], 6, "32x32.png must be RGBA");
        assert!(ico.len() > 64);
        let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
        assert!(
            count >= 9,
            "icon.ico needs 16/20/24/32/40/48/64/128/256 frames, got {count}"
        );
        let first_width = ico[6];
        assert_eq!(first_width, 0, "first ICO frame must be 256 PNG for Tauri window icon");
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..count {
            let entry = 6 + 16 * i;
            let width = ico[entry];
            let offset = u32::from_le_bytes(ico[entry + 12..entry + 16].try_into().unwrap()) as usize;
            if width == 0 {
                seen.insert(256u32);
                assert_eq!(&ico[offset..offset + 8], b"\x89PNG\r\n\x1a\n");
            } else {
                seen.insert(width as u32);
                let header = u32::from_le_bytes(ico[offset..offset + 4].try_into().unwrap());
                assert_eq!(header, 40, "small ICO frames must be 32bpp BMP, not PNG");
            }
        }
        for size in [16u32, 20, 24, 32, 40, 48, 64, 128, 256] {
            assert!(seen.contains(&size), "icon.ico missing {size}x{size} frame");
        }
    }

    #[test]
    fn about_external_urls_are_allowlisted() {
        let root = engine::repo_root_from_manifest().expect("repo");
        let about = std::fs::read_to_string(
            root.join("app")
                .join("frontend")
                .join("src")
                .join("lib")
                .join("about.ts"),
        )
        .expect("about.ts");
        let mut found = 0usize;
        let mut rest = about.as_str();
        while let Some(idx) = rest.find("https://") {
            rest = &rest[idx..];
            let end = rest.find('"').expect("unterminated About URL");
            let url = &rest[..end];
            found += 1;
            assert!(
                ALLOWED_EXTERNAL_URLS.contains(&url),
                "About link {url} is missing from ALLOWED_EXTERNAL_URLS"
            );
            rest = &rest[end..];
        }
        assert!(found >= 4, "expected About external URLs, found {found}");
    }
}
