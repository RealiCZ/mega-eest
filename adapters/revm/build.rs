//! Records the build identity the adapter reports: the implementation's commit as Cargo.lock
//! resolved it, and the compiler.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    let lock = std::fs::read_to_string("Cargo.lock").expect("Cargo.lock");
    // The resolved source of the implementation: `git+<repository>?rev=<rev>#<commit>`.
    let mut commit = String::from("unknown");
    let mut in_package = false;
    for line in lock.lines() {
        if line == "name = \"mega-evm\"" {
            in_package = true;
        } else if line.starts_with("[[package]]") {
            in_package = false;
        } else if in_package && line.starts_with("source = ") {
            if let Some((_, c)) = line.trim_end_matches('"').rsplit_once('#') {
                commit = c.to_string();
            }
        }
    }
    println!("cargo:rustc-env=ADAPTER_IMPL_COMMIT={commit}");
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
