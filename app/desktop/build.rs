fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let skip = std::env::var("MEMSCOPE_SKIP_RUNTIME_RESOURCE").ok().as_deref() == Some("1");
    if profile == "release" && !skip {
        let python = manifest
            .join("resources")
            .join("runtime")
            .join("python.exe");
        if !python.is_file() {
            panic!(
                "Bundled engine runtime is missing at {}. Run scripts/windows/prepare-engine-runtime.ps1 before a release build.",
                python.display()
            );
        }
    }
    tauri_build::build()
}
