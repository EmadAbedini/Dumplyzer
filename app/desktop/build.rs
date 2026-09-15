fn main() {
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=icons/32x32.png");
    println!("cargo:rerun-if-changed=icons/128x128.png");
    println!("cargo:rerun-if-changed=icons/128x128@2x.png");
    println!("cargo:rerun-if-changed=icons/Dumplyzer.png");
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
        let bulk_extractor = manifest
            .join("resources")
            .join("tools")
            .join("bulk_extractor")
            .join("bulk_extractor64.exe");
        if !bulk_extractor.is_file() {
            panic!(
                "Bundled bulk_extractor64.exe is missing at {}. Run scripts/windows/prepare-bulk-extractor.ps1 before a release build.",
                bulk_extractor.display()
            );
        }
        let capa = manifest
            .join("resources")
            .join("tools")
            .join("capa")
            .join("capa.exe");
        if !capa.is_file() {
            panic!(
                "Bundled capa.exe is missing at {}. Run scripts/windows/prepare-capa.ps1 before a release build.",
                capa.display()
            );
        }
        let floss = manifest
            .join("resources")
            .join("tools")
            .join("floss")
            .join("floss.exe");
        if !floss.is_file() {
            panic!(
                "Bundled floss.exe is missing at {}. Run scripts/windows/prepare-floss.ps1 before a release build.",
                floss.display()
            );
        }
    }
    tauri_build::build()
}
