//! Python engine process location and spawn policy for packaged vs developer layouts.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone)]
pub struct EngineLaunchPlan {
    pub python: PathBuf,
    pub cwd: PathBuf,
    pub packaged: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ResolveInputs {
    pub env_python: Option<PathBuf>,
    pub exe_dir: Option<PathBuf>,
    pub resource_dir: Option<PathBuf>,
    pub repo_root: Option<PathBuf>,
}

pub fn repo_root_from_manifest() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot resolve repository root".into())
}

pub fn memscope_data_dir() -> Result<PathBuf, String> {
    for key in ["DUMPLYZER_DATA_DIR", "MEMSCOPE_DATA_DIR"] {
        if let Ok(v) = env::var(key) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed));
            }
        }
    }
    let local = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is not set".to_string())?;
    Ok(local.join("Dumplyzer"))
}

/// WebView2 profile directory. Program Files is read-only for a normal user;
/// Chromium cache belongs next to other Dumplyzer user data, not a second
/// `%LOCALAPPDATA%\com.dumplyzer.workbench` tree.
pub fn apply_webview2_user_data_folder() -> Result<PathBuf, String> {
    if let Ok(existing) = env::var("WEBVIEW2_USER_DATA_FOLDER") {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
            return Ok(path);
        }
    }
    let dir = memscope_data_dir()?.join("webview");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    env::set_var("WEBVIEW2_USER_DATA_FOLDER", &dir);
    Ok(dir)
}

pub fn user_data_subdir(kind: &str) -> Result<PathBuf, String> {
    let root = memscope_data_dir()?;
    let rel = match kind {
        "yara_rules" | "yara" => PathBuf::from("rules").join("yara"),
        "yara_rules_custom" | "yara_custom" => PathBuf::from("rules").join("yara").join("custom"),
        "symbols" => PathBuf::from("symbols"),
        _ => return Err("Unknown folder.".into()),
    };
    Ok(root.join(rel))
}

/// Remove Dumplyzer-created session temp files. Never the original evidence,
/// exports, artifacts, cache, SQLite, config, logs, rules, or tools.
pub fn cleanup_session_temp(data_dir: &Path) {
    let tmp = data_dir.join("tmp");
    if tmp.is_dir() {
        let _ = fs::remove_dir_all(&tmp);
    }
    let _ = fs::create_dir_all(&tmp);
    remove_named_dirs(&data_dir.join("analysis"), "_dumpfiles_tmp");
}

fn remove_named_dirs(root: &Path, name: &str) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some(name) {
            let _ = fs::remove_dir_all(&path);
        } else {
            remove_named_dirs(&path, name);
        }
    }
}

pub fn python_candidates(inputs: &ResolveInputs) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = &inputs.env_python {
        if !p.as_os_str().is_empty() {
            out.push(p.clone());
        }
    }
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(d) = &inputs.exe_dir {
        roots.push(d.clone());
    }
    if let Some(d) = &inputs.resource_dir {
        roots.push(d.clone());
        roots.push(d.join("resources"));
    }
    for root in &roots {
        out.push(root.join("runtime").join("python.exe"));
        out.push(root.join("runtime").join("python"));
        out.push(root.join("engine-runtime").join("python.exe"));
        out.push(root.join("engine-runtime").join("python"));
    }
    if let Some(repo) = &inputs.repo_root {
        // `tauri dev` does not copy bundle resources next to target/debug.
        // Prefer the existing source-tree embeddable runtime over engine/.venv
        // so UI work uses the same Python engine as release without a venv.
        let src_runtime = repo
            .join("app")
            .join("desktop")
            .join("resources")
            .join("runtime");
        out.push(src_runtime.join("python.exe"));
        out.push(src_runtime.join("python"));
        out.push(
            repo.join("engine")
                .join(".venv")
                .join("Scripts")
                .join("python.exe"),
        );
        out.push(repo.join("engine").join(".venv").join("bin").join("python"));
    }
    out
}

pub fn is_packaged_python(python: &Path) -> bool {
    let Some(dir) = python.parent() else {
        return false;
    };
    if dir.join("python312._pth").is_file() {
        return true;
    }
    matches!(dir.file_name().and_then(|n| n.to_str()), Some("runtime" | "engine-runtime"))
}

fn engine_cwd(python: &Path, packaged: bool, repo_root: Option<&Path>) -> PathBuf {
    if packaged {
        return python
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
    }
    if let Some(root) = repo_root {
        let engine = root.join("engine");
        if engine.is_dir() {
            return engine;
        }
    }
    python
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn bundled_bulk_extractor_dir(python: &Path) -> Option<PathBuf> {
    let mut cands = Vec::new();
    if let Some(runtime) = python.parent() {
        cands.push(runtime.join("tools").join("bulk_extractor"));
        if let Some(parent) = runtime.parent() {
            cands.push(parent.join("tools").join("bulk_extractor"));
            cands.push(parent.join("resources").join("tools").join("bulk_extractor"));
        }
    }
    // Compile-time source tree (tauri dev on the build machine). Does not exist
    // on a clean install, so it cannot override the packaged sibling path.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cands.push(manifest.join("resources").join("tools").join("bulk_extractor"));
    if let Ok(root) = repo_root_from_manifest() {
        cands.push(
            root.join("app")
                .join("desktop")
                .join("resources")
                .join("tools")
                .join("bulk_extractor"),
        );
    }
    for cand in cands {
        if cand.join("bulk_extractor64.exe").is_file() {
            return Some(cand);
        }
    }
    None
}

pub fn bundled_tools_dir(python: &Path) -> Option<PathBuf> {
    if let Some(be) = bundled_bulk_extractor_dir(python) {
        if let Some(parent) = be.parent() {
            return Some(parent.to_path_buf());
        }
        return Some(be);
    }
    let mut cands = Vec::new();
    if let Some(runtime) = python.parent() {
        cands.push(runtime.join("tools"));
        if let Some(parent) = runtime.parent() {
            cands.push(parent.join("tools"));
            cands.push(parent.join("resources").join("tools"));
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cands.push(manifest.join("resources").join("tools"));
    if let Ok(root) = repo_root_from_manifest() {
        cands.push(
            root.join("app")
                .join("desktop")
                .join("resources")
                .join("tools"),
        );
    }
    for cand in cands {
        if cand.is_dir() {
            return Some(cand);
        }
    }
    None
}

pub fn bundled_rules_dir(python: &Path) -> Option<PathBuf> {
    let mut cands = Vec::new();
    if let Some(runtime) = python.parent() {
        if let Some(parent) = runtime.parent() {
            cands.push(parent.join("rules").join("yara").join("bundled"));
            cands.push(parent.join("resources").join("rules").join("yara").join("bundled"));
            cands.push(parent.join("rules"));
            cands.push(parent.join("resources").join("rules"));
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cands.push(manifest.join("resources").join("rules").join("yara").join("bundled"));
    cands.push(manifest.join("resources").join("rules"));
    if let Ok(root) = repo_root_from_manifest() {
        cands.push(
            root.join("app")
                .join("desktop")
                .join("resources")
                .join("rules")
                .join("yara")
                .join("bundled"),
        );
        cands.push(root.join("app").join("desktop").join("resources").join("rules"));
    }
    for cand in cands {
        if cand.join("memory").is_dir() {
            return Some(cand);
        }
        if cand.join("yara").join("bundled").join("memory").is_dir() {
            return Some(cand);
        }
        if cand.join("bundled").join("memory").is_dir() {
            return Some(cand);
        }
    }
    None
}

pub fn resolve_engine(inputs: &ResolveInputs) -> Result<EngineLaunchPlan, String> {
    for candidate in python_candidates(inputs) {
        if candidate.is_file() {
            let packaged = is_packaged_python(&candidate);
            let cwd = engine_cwd(&candidate, packaged, inputs.repo_root.as_deref());
            return Ok(EngineLaunchPlan {
                python: candidate,
                cwd,
                packaged,
            });
        }
    }
    Err(
        "engine Python runtime not found (bundled runtime/python.exe or engine/.venv)"
            .into(),
    )
}

pub fn resolve_inputs_from_env(
    exe_dir: Option<PathBuf>,
    resource_dir: Option<PathBuf>,
) -> ResolveInputs {
    let env_python = env::var_os("DUMPLYZER_ENGINE_PYTHON")
        .or_else(|| env::var_os("MEMSCOPE_ENGINE_PYTHON"))
        .map(PathBuf::from);
    let repo_root = repo_root_from_manifest().ok();
    ResolveInputs {
        env_python,
        exe_dir,
        resource_dir,
        repo_root,
    }
}

pub fn apply_python_env(cmd: &mut Command, data_dir: &Path, packaged: bool) {
    cmd.env_remove("PYTHONPATH");
    cmd.env_remove("PYTHONHOME");
    cmd.env_remove("PYTHONSTARTUP");
    cmd.env_remove("PYTHONUSERBASE");
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("PYTHONNOUSERSITE", "1");
    cmd.env("PYTHONUTF8", "1");
    cmd.env("PYTHONIOENCODING", "utf-8");
    cmd.env("PYTHONDONTWRITEBYTECODE", "1");
    cmd.env("DUMPLYZER_DATA_DIR", data_dir.as_os_str());
    cmd.env("MEMSCOPE_DATA_DIR", data_dir.as_os_str());
    let tmp = data_dir.join("tmp");
    cmd.env("TEMP", &tmp);
    cmd.env("TMP", &tmp);
    cmd.env("TMPDIR", &tmp);
    if packaged {
        cmd.env("MEMSCOPE_PACKAGED", "1");
        if let Ok(root) = env::var("SystemRoot") {
            cmd.env("PATH", format!("{root}\\System32;{root}"));
        }
    } else {
        cmd.env_remove("MEMSCOPE_PACKAGED");
    }
}

/// When `tauri dev` uses the in-tree embeddable runtime (or a cargo-target
/// copy of `resources/runtime`), load `memscope_engine` from the source tree
/// so IPC methods match the checkout, not a stale snapshot.
pub fn source_engine_overlay(python: &Path) -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let engine = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("engine"))?;
    if !engine.join("memscope_engine").is_dir() {
        return None;
    }
    let py = python.canonicalize().ok()?;
    let runtime_dir = py.parent()?;
    if runtime_dir.file_name().and_then(|n| n.to_str()) != Some("runtime") {
        return None;
    }
    let src_runtime = manifest.join("resources").join("runtime");
    if let Ok(src) = src_runtime.canonicalize() {
        if py.starts_with(&src) {
            return Some(engine);
        }
    }
    let resources = runtime_dir.parent()?;
    if resources.file_name().and_then(|n| n.to_str()) == Some("resources") {
        return Some(engine);
    }
    None
}

fn python_json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Embeddable CPython honors `python312._pth` and often ignores `PYTHONPATH`.
/// Inject the source engine onto `sys.path` before `-m` equivalent import.
fn overlay_engine_bootstrap(engine_src: &Path) -> String {
    let path = engine_src.to_string_lossy().replace('\\', "/");
    format!(
        "import sys; p={}; sys.path.insert(0, p); import runpy; runpy.run_module('memscope_engine', run_name='__main__')",
        python_json_string(&path)
    )
}

pub fn configure_engine_command(cmd: &mut Command, plan: &EngineLaunchPlan, data_dir: &Path) {
    let overlay = source_engine_overlay(&plan.python);
    if let Some(engine_src) = &overlay {
        cmd.arg("-c").arg(overlay_engine_bootstrap(engine_src));
    } else {
        cmd.arg("-m").arg("memscope_engine");
    }
    cmd.current_dir(&plan.cwd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    apply_python_env(cmd, data_dir, plan.packaged);
    if let Some(engine_src) = overlay {
        cmd.env("PYTHONPATH", engine_src);
    }
    if let Some(tools) = bundled_tools_dir(&plan.python) {
        cmd.env("DUMPLYZER_BUNDLE_TOOLS", tools);
    }
    if let Some(rules) = bundled_rules_dir(&plan.python) {
        cmd.env("DUMPLYZER_BUNDLE_RULES", rules);
    }
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_file(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, b"").unwrap();
    }

    #[test]
    fn packaged_runtime_wins_over_venv() {
        let tmp = env::temp_dir().join(format!(
            "memscope-launch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let resource = tmp.join("resource");
        let repo = tmp.join("repo");
        let packaged = resource.join("runtime").join("python.exe");
        let venv = repo
            .join("engine")
            .join(".venv")
            .join("Scripts")
            .join("python.exe");
        write_file(&packaged);
        fs::write(resource.join("runtime").join("python312._pth"), b".\n").unwrap();
        write_file(&venv);

        let plan = resolve_engine(&ResolveInputs {
            env_python: None,
            exe_dir: Some(resource.clone()),
            resource_dir: Some(resource.clone()),
            repo_root: Some(repo),
        })
        .expect("plan");
        assert_eq!(plan.python, packaged);
        assert!(plan.packaged);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn source_tree_runtime_used_when_debug_exe_has_no_runtime() {
        let tmp = env::temp_dir().join(format!(
            "memscope-src-runtime-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(2)
        ));
        let exe_dir = tmp.join("target").join("debug");
        fs::create_dir_all(&exe_dir).unwrap();
        let repo = tmp.join("repo");
        let src_runtime = repo
            .join("app")
            .join("desktop")
            .join("resources")
            .join("runtime")
            .join("python.exe");
        let venv = repo
            .join("engine")
            .join(".venv")
            .join("Scripts")
            .join("python.exe");
        write_file(&src_runtime);
        fs::write(
            src_runtime.parent().unwrap().join("python312._pth"),
            b".\n",
        )
        .unwrap();
        write_file(&venv);

        let plan = resolve_engine(&ResolveInputs {
            env_python: None,
            exe_dir: Some(exe_dir),
            resource_dir: Some(tmp.join("target").join("debug")),
            repo_root: Some(repo),
        })
        .expect("plan");
        assert_eq!(plan.python, src_runtime);
        assert!(plan.packaged);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn source_engine_overlay_only_for_in_tree_runtime() {
        let tmp = env::temp_dir().join(format!(
            "memscope-overlay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(3)
        ));
        let packaged = tmp.join("runtime").join("python.exe");
        write_file(&packaged);
        assert!(source_engine_overlay(&packaged).is_none());
        let copied = tmp
            .join("debug")
            .join("resources")
            .join("runtime")
            .join("python.exe");
        write_file(&copied);
        let copied_overlay = source_engine_overlay(&copied).expect("cargo-target copy");
        assert!(copied_overlay.ends_with("engine"));
        let _ = fs::remove_dir_all(&tmp);

        let in_tree = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("runtime")
            .join("python.exe");
        if in_tree.is_file() {
            let overlay = source_engine_overlay(&in_tree).expect("source engine");
            assert!(overlay.ends_with("engine"));
            assert!(overlay.join("memscope_engine").is_dir());
        }
    }

    #[test]
    fn cargo_target_runtime_bootstraps_source_engine() {
        let tmp = env::temp_dir().join(format!(
            "memscope-overlay-cmd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(4)
        ));
        let copied = tmp
            .join("debug")
            .join("resources")
            .join("runtime")
            .join("python.exe");
        write_file(&copied);
        let plan = EngineLaunchPlan {
            python: copied.clone(),
            cwd: tmp.clone(),
            packaged: true,
        };
        let mut cmd = Command::new(&copied);
        configure_engine_command(&mut cmd, &plan, &tmp);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.first().map(String::as_str), Some("-c"));
        let boot = args.get(1).expect("bootstrap");
        assert!(boot.contains("sys.path.insert"));
        assert!(boot.contains("memscope_engine"));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn env_override_is_first_candidate() {
        let tmp = env::temp_dir().join(format!(
            "memscope-envpy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(1)
        ));
        let override_py = tmp.join("custom").join("python.exe");
        write_file(&override_py);
        let plan = resolve_engine(&ResolveInputs {
            env_python: Some(override_py.clone()),
            exe_dir: None,
            resource_dir: None,
            repo_root: None,
        })
        .expect("plan");
        assert_eq!(plan.python, override_py);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn data_dir_uses_localappdata_memscope() {
        let previous = env::var_os("MEMSCOPE_DATA_DIR");
        let previous_new = env::var_os("DUMPLYZER_DATA_DIR");
        env::remove_var("MEMSCOPE_DATA_DIR");
        env::remove_var("DUMPLYZER_DATA_DIR");
        let dir = memscope_data_dir().expect("data dir");
        assert!(dir.ends_with("Dumplyzer"));
        let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert_eq!(name, "Dumplyzer");
        let s = dir.to_string_lossy();
        assert!(
            !s.contains(r"\Programs\Dumplyzer") && !s.contains(r"\Program Files\Dumplyzer"),
            "user data must not be the install directory: {s}"
        );
        match previous {
            Some(v) => env::set_var("MEMSCOPE_DATA_DIR", v),
            None => env::remove_var("MEMSCOPE_DATA_DIR"),
        }
        match previous_new {
            Some(v) => env::set_var("DUMPLYZER_DATA_DIR", v),
            None => env::remove_var("DUMPLYZER_DATA_DIR"),
        }
    }

    #[test]
    fn webview2_user_data_lives_under_dumplyzer() {
        let previous_data = env::var_os("DUMPLYZER_DATA_DIR");
        let previous_legacy = env::var_os("MEMSCOPE_DATA_DIR");
        let previous_wv = env::var_os("WEBVIEW2_USER_DATA_FOLDER");
        let tmp = env::temp_dir().join(format!(
            "memscope-wv-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        env::set_var("DUMPLYZER_DATA_DIR", &tmp);
        env::remove_var("MEMSCOPE_DATA_DIR");
        env::remove_var("WEBVIEW2_USER_DATA_FOLDER");
        let dir = apply_webview2_user_data_folder().expect("webview dir");
        assert_eq!(dir, tmp.join("webview"));
        assert!(dir.is_dir());
        assert_eq!(
            env::var("WEBVIEW2_USER_DATA_FOLDER").expect("env"),
            dir.to_string_lossy().as_ref()
        );
        let _ = fs::remove_dir_all(&tmp);
        match previous_data {
            Some(v) => env::set_var("DUMPLYZER_DATA_DIR", v),
            None => env::remove_var("DUMPLYZER_DATA_DIR"),
        }
        match previous_legacy {
            Some(v) => env::set_var("MEMSCOPE_DATA_DIR", v),
            None => env::remove_var("MEMSCOPE_DATA_DIR"),
        }
        match previous_wv {
            Some(v) => env::set_var("WEBVIEW2_USER_DATA_FOLDER", v),
            None => env::remove_var("WEBVIEW2_USER_DATA_FOLDER"),
        }
    }

    #[test]
    fn bundled_bulk_extractor_dir_is_beside_runtime() {
        let tmp = env::temp_dir().join(format!(
            "memscope-be-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let runtime = tmp.join("resources").join("runtime");
        let tools = tmp.join("resources").join("tools").join("bulk_extractor");
        fs::create_dir_all(&runtime).unwrap();
        fs::create_dir_all(&tools).unwrap();
        write_file(&runtime.join("python.exe"));
        write_file(&tools.join("bulk_extractor64.exe"));
        let found = bundled_bulk_extractor_dir(&runtime.join("python.exe")).expect("tools");
        assert_eq!(found, tools);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bundled_rules_dir_is_beside_runtime() {
        let tmp = env::temp_dir().join(format!(
            "memscope-rules-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let runtime = tmp.join("resources").join("runtime");
        let rules = tmp
            .join("resources")
            .join("rules")
            .join("yara")
            .join("bundled")
            .join("memory");
        fs::create_dir_all(&runtime).unwrap();
        fs::create_dir_all(&rules).unwrap();
        write_file(&runtime.join("python.exe"));
        write_file(&rules.join("demo.yar"));
        let found = bundled_rules_dir(&runtime.join("python.exe")).expect("rules");
        assert_eq!(
            found,
            tmp.join("resources")
                .join("rules")
                .join("yara")
                .join("bundled")
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn yara_rules_subdir_is_under_data_root() {
        let previous = env::var_os("MEMSCOPE_DATA_DIR");
        let previous_new = env::var_os("DUMPLYZER_DATA_DIR");
        env::remove_var("MEMSCOPE_DATA_DIR");
        env::remove_var("DUMPLYZER_DATA_DIR");
        let dir = user_data_subdir("yara_rules").expect("yara dir");
        assert!(dir.ends_with(Path::new("rules").join("yara")));
        assert!(dir.to_string_lossy().contains("Dumplyzer"));
        let custom = user_data_subdir("yara_rules_custom").expect("custom yara dir");
        assert!(custom.ends_with(Path::new("rules").join("yara").join("custom")));
        assert!(custom.starts_with(&dir));
        let symbols = user_data_subdir("symbols").expect("symbols dir");
        assert!(symbols.ends_with("symbols"));
        match previous {
            Some(v) => env::set_var("MEMSCOPE_DATA_DIR", v),
            None => env::remove_var("MEMSCOPE_DATA_DIR"),
        }
        match previous_new {
            Some(v) => env::set_var("DUMPLYZER_DATA_DIR", v),
            None => env::remove_var("DUMPLYZER_DATA_DIR"),
        }
    }

    #[test]
    fn cleanup_session_temp_removes_tmp_not_exports() {
        let tmp = env::temp_dir().join(format!(
            "dumplyzer-session-temp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let data = tmp.join("data");
        fs::create_dir_all(data.join("tmp").join("plugin_files")).unwrap();
        fs::write(data.join("tmp").join("scratch.bin"), b"tmp").unwrap();
        fs::create_dir_all(data.join("exports")).unwrap();
        fs::write(data.join("exports").join("report.html"), b"keep").unwrap();
        fs::create_dir_all(
            data.join("analysis")
                .join("pe_extraction")
                .join("run1")
                .join("_dumpfiles_tmp"),
        )
        .unwrap();
        fs::write(
            data.join("analysis")
                .join("pe_extraction")
                .join("run1")
                .join("kept.pe"),
            b"pe",
        )
        .unwrap();
        cleanup_session_temp(&data);
        assert!(data.join("tmp").is_dir());
        assert!(!data.join("tmp").join("scratch.bin").exists());
        assert!(data.join("exports").join("report.html").is_file());
        assert!(
            data.join("analysis")
                .join("pe_extraction")
                .join("run1")
                .join("kept.pe")
                .is_file()
        );
        assert!(!data
            .join("analysis")
            .join("pe_extraction")
            .join("run1")
            .join("_dumpfiles_tmp")
            .exists());
        let _ = fs::remove_dir_all(&tmp);
    }
}
