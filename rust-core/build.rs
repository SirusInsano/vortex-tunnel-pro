use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" && Path::new("app.rc").exists() && Path::new("dragon.ico").exists() {
        let out_dir = env::var("OUT_DIR").unwrap();
        let res_path = format!("{}\\app.lib", out_dir);

        // Try standard Windows Kits x64 rc.exe or PATH rc.exe
        let rc_candidates = [
            r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\rc.exe",
            "rc.exe",
        ];

        for rc in rc_candidates {
            if let Ok(status) = Command::new(rc)
                .args(["/fo", &res_path, "app.rc"])
                .status()
            {
                if status.success() {
                    println!("cargo:rustc-link-arg-bins={}", res_path);
                    break;
                }
            }
        }
    }
}
