//! Python engine process location and spawn policy for packaged vs developer layouts.

use std::env;
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
    if let Ok(v) = env::var("MEMSCOPE_DATA_DIR") {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let local = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is not set".to_string())?;
    Ok(local.join("MemScope"))
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
    let env_python = env::var_os("MEMSCOPE_ENGINE_PYTHON").map(PathBuf::from);
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
    cmd.env("MEMSCOPE_DATA_DIR", data_dir.as_os_str());
    let tmp = data_dir.join("tmp");
    cmd.env("TEMP", &tmp);
    cmd.env("TMP", &tmp);
    if packaged {
        cmd.env("MEMSCOPE_PACKAGED", "1");
        if let Ok(root) = env::var("SystemRoot") {
            cmd.env("PATH", format!("{root}\\System32;{root}"));
        }
    } else {
        cmd.env_remove("MEMSCOPE_PACKAGED");
    }
}

pub fn configure_engine_command(cmd: &mut Command, plan: &EngineLaunchPlan, data_dir: &Path) {
    cmd.arg("-m")
        .arg("memscope_engine")
        .current_dir(&plan.cwd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    apply_python_env(cmd, data_dir, plan.packaged);
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
        env::remove_var("MEMSCOPE_DATA_DIR");
        let dir = memscope_data_dir().expect("data dir");
        assert!(dir.ends_with("MemScope"));
        match previous {
            Some(v) => env::set_var("MEMSCOPE_DATA_DIR", v),
            None => env::remove_var("MEMSCOPE_DATA_DIR"),
        }
    }
}
