//! Records the build identity the adapter reports: the commits of the implementation and of its
//! evm2 fork as checked out under vendor/, and the compiler.

use std::process::Command;

fn head(dir: &str) -> String {
    Command::new("git")
        .args(["-C", dir, "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn main() {
    for dir in ["../../vendor/mega-evm/.git/HEAD", "../../vendor/evm2/.git/HEAD"] {
        println!("cargo:rerun-if-changed={dir}");
    }
    println!("cargo:rustc-env=ADAPTER_IMPL_COMMIT={}", head("../../vendor/mega-evm"));
    println!("cargo:rustc-env=ADAPTER_FORK_COMMIT={}", head("../../vendor/evm2"));
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let version = Command::new(rustc)
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=ADAPTER_RUSTC={}", version.trim());
    println!("cargo:rustc-env=ADAPTER_PROFILE={}", std::env::var("PROFILE").unwrap_or_default());
}
