//! Command-line front end of the format crate.
//!
//! ```text
//! mega-fixture check  [--specs DIR] FILE...   validate fixtures; print digests or the error
//! mega-fixture canon  FILE                    write the canonical bytes of strict JSON to stdout
//! mega-fixture digest FILE                    print the SHA-256 of the canonical bytes
//! mega-fixture manifest FILE                  validate a manifest and print its digest
//! ```

use mega_fixture_format::{canonicalize, sha256_digest, Case, Manifest, SpecStore};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: mega-fixture check [--specs DIR] FILE... | canon FILE | digest FILE | manifest FILE");
    ExitCode::from(2)
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else { return usage() };
    match command.as_str() {
        "check" => {
            let mut specs = PathBuf::from("specs");
            let mut files = Vec::new();
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--specs" && i + 1 < args.len() {
                    specs = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    files.push(args[i].clone());
                    i += 1;
                }
            }
            let store = match SpecStore::load_dir(&specs) {
                Ok(store) => store,
                Err(e) => {
                    eprintln!("specs: {e}");
                    return ExitCode::from(2);
                }
            };
            let mut failed = false;
            for file in files {
                match read(&file).map_err(|e| e.to_string()).and_then(|b| Case::from_bytes(&b, &store).map_err(|e| e.to_string())) {
                    Ok(case) => println!("ok {file} file={} semantic={}", case.file_digest(), case.semantic_digest()),
                    Err(e) => {
                        failed = true;
                        println!("reject {file} {e}");
                    }
                }
            }
            if failed { ExitCode::from(1) } else { ExitCode::SUCCESS }
        }
        "canon" | "digest" if args.len() == 2 => match read(&args[1]).and_then(|b| canonicalize(&b).map_err(|e| e.to_string())) {
            Ok(bytes) => {
                if command == "canon" {
                    std::io::stdout().write_all(&bytes).expect("stdout");
                } else {
                    println!("{}", sha256_digest(&bytes));
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("reject {e}");
                ExitCode::from(1)
            }
        },
        "manifest" if args.len() == 2 => match read(&args[1]).and_then(|b| Manifest::from_bytes(&b).map_err(|e| e.to_string())) {
            Ok(m) => {
                println!("{}", m.digest());
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("reject {e}");
                ExitCode::from(1)
            }
        },
        _ => usage(),
    }
}
