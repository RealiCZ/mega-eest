//! Command-line front end of the format crate.
//!
//! ```text
//! mega-fixture check  [--specs DIR] FILE...   validate fixtures; print digests or the error
//! mega-fixture canon  FILE                    write the canonical bytes of strict JSON to stdout
//! mega-fixture digest FILE                    print the SHA-256 of the canonical bytes
//! mega-fixture manifest FILE                  validate a manifest and print its digest
//! mega-fixture consume --adapter PROG [--instrumented] [--specs DIR] [--report FILE] PATH...
//!                                             run cases on an adapter and compare, read-only
//! mega-fixture fill --adapter PROG --out DIR [--instrumented] [--specs DIR] FILE...
//!                                             fill candidate expectations into DIR
//! ```
//!
//! `consume` takes fixture files or directories (searched for `*.json`, in path order) and prints
//! one line per case and a summary line; it exits 1 when a case is not a pass. `fill` takes
//! authoring documents (fixtures without `requires` and `expected`) and writes each filled
//! candidate to `DIR/<caseId>.json`; it refuses an examples or release directory.

use mega_fixture_format::consume::{self, Adapter as _, Capabilities, ProcessAdapter, Status};
use mega_fixture_format::{canonicalize, json, sha256_digest, Case, Manifest, SpecStore};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage: mega-fixture check [--specs DIR] FILE... | canon FILE | digest FILE | manifest FILE\n       \
         mega-fixture consume --adapter PROG [--instrumented] [--specs DIR] [--report FILE] PATH...\n       \
         mega-fixture fill --adapter PROG --out DIR [--instrumented] [--specs DIR] FILE..."
    );
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
        "consume" => match Options::parse(&args[1..]) {
            Some(o) => run_consume(o),
            None => usage(),
        },
        "fill" => match Options::parse(&args[1..]) {
            Some(o) if o.out.is_some() => run_fill(o),
            _ => usage(),
        },
        _ => usage(),
    }
}

/// The options of `consume` and `fill`.
struct Options {
    adapter: PathBuf,
    instrumented: bool,
    specs: PathBuf,
    report: Option<PathBuf>,
    out: Option<PathBuf>,
    paths: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Option<Options> {
        let mut o = Options { adapter: PathBuf::new(), instrumented: false, specs: PathBuf::from("specs"), report: None, out: None, paths: Vec::new() };
        let mut i = 0;
        while i < args.len() {
            let value = || args.get(i + 1).map(PathBuf::from);
            match args[i].as_str() {
                "--adapter" => o.adapter = value()?,
                "--specs" => o.specs = value()?,
                "--report" => o.report = Some(value()?),
                "--out" => o.out = Some(value()?),
                "--instrumented" => {
                    o.instrumented = true;
                    i += 1;
                    continue;
                }
                p => {
                    o.paths.push(p.to_string());
                    i += 1;
                    continue;
                }
            }
            i += 2;
        }
        (!o.adapter.as_os_str().is_empty() && !o.paths.is_empty()).then_some(o)
    }
}

/// The fixture files of `paths`: each file, and every `*.json` under each directory, sorted.
fn case_files(paths: &[String]) -> Result<Vec<PathBuf>, String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
        let mut entries: Vec<PathBuf> =
            std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.extension().is_some_and(|x| x == "json") {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    for p in paths {
        let path = PathBuf::from(p);
        if path.is_dir() {
            walk(&path, &mut out)?;
        } else {
            out.push(path);
        }
    }
    Ok(out)
}

fn load(o: &Options) -> Result<(SpecStore, ProcessAdapter, Capabilities), String> {
    let store = SpecStore::load_dir(&o.specs).map_err(|e| format!("specs: {e}"))?;
    let adapter = ProcessAdapter { program: o.adapter.clone() };
    let caps = Capabilities::from_value(adapter.capabilities()?)?;
    Ok((store, adapter, caps))
}

fn run_consume(o: Options) -> ExitCode {
    let (store, adapter, caps) = match load(&o) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("consume: {e}");
            return ExitCode::from(2);
        }
    };
    let files = match case_files(&o.paths) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("consume: {e}");
            return ExitCode::from(2);
        }
    };
    let mode = if o.instrumented { "instrumented" } else { "plain" };
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut reports = Vec::new();
    for file in &files {
        let name = file.display().to_string();
        let report = match std::fs::read(file) {
            Ok(bytes) => consume::consume_case(&name, &bytes, &store, &adapter, &caps, o.instrumented),
            Err(e) => {
                let mut r = consume::consume_case(&name, b"", &store, &adapter, &caps, o.instrumented);
                r.status = Status::Error { message: format!("{name}: {e}") };
                r
            }
        };
        *counts.entry(report.status.name()).or_default() += 1;
        let id = report.case_id.clone().unwrap_or_else(|| name.clone());
        let input = report.input_digest.clone().unwrap_or_default();
        println!("{} {id} input={input}", report.status.name());
        match &report.status {
            Status::Fail { path, expected, actual, rules } => {
                let show = |v: &Option<json::Value>| v.as_ref().map_or("(absent)".to_string(), |v| String::from_utf8_lossy(&json::to_canonical(v)).into_owned());
                println!("  first difference at {path}: expected {} actual {}", show(expected), show(actual));
                println!("  rules: {}", if rules.is_empty() { "(none)".to_string() } else { rules.join(", ") });
                println!("  case file={} semantic={}", report.file_digest.clone().unwrap_or_default(), report.semantic_digest.clone().unwrap_or_default());
                println!("  observations={}", report.observations_digest.clone().unwrap_or_default());
            }
            Status::Unsupported { missing } => println!("  missing: {}", missing.join(", ")),
            Status::Error { message } => println!("  {message}"),
            Status::Pass => {}
        }
        reports.push(report);
    }
    let get = |k: &str| counts.get(k).copied().unwrap_or(0);
    println!(
        "CONSUME adapter={} mode={mode} cases={} pass={} fail={} unsupported={} error={}",
        caps.name,
        files.len(),
        get("pass"),
        get("fail"),
        get("unsupported"),
        get("error")
    );
    if let Some(path) = &o.report {
        let mut m = std::collections::BTreeMap::new();
        m.insert("format".to_string(), json::Value::String("mega-fixture-run-report".into()));
        m.insert("mode".to_string(), json::Value::String(mode.into()));
        m.insert("adapter".to_string(), caps.value.clone());
        m.insert("cases".to_string(), json::Value::Array(reports.iter().map(|r| r.to_value()).collect()));
        let mut bytes = json::to_canonical(&json::Value::Object(m));
        bytes.push(b'\n');
        if let Err(e) = std::fs::write(path, bytes) {
            eprintln!("consume: {}: {e}", path.display());
            return ExitCode::from(2);
        }
    }
    if get("pass") == files.len() { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

fn run_fill(o: Options) -> ExitCode {
    let out = o.out.clone().expect("checked");
    if consume::is_forbidden_fill_dir(&out) {
        eprintln!("fill: {} is an examples or release directory; candidates go elsewhere", out.display());
        return ExitCode::from(2);
    }
    let (store, adapter, caps) = match load(&o) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("fill: {e}");
            return ExitCode::from(2);
        }
    };
    let filler = {
        let mut m = std::collections::BTreeMap::new();
        for key in ["adapter", "implementation", "build"] {
            if let Some(v) = caps.value.get(key) {
                m.insert(key.to_string(), v.clone());
            }
        }
        m.insert("mode".to_string(), json::Value::String(if o.instrumented { "instrumented" } else { "plain" }.into()));
        json::Value::Object(m)
    };
    let mut failed = 0usize;
    let mut written = 0usize;
    for file in &o.paths {
        let result = read(file)
            .and_then(|b| json::parse(&b).map_err(|e| e.to_string()))
            .and_then(|authoring| {
                let mut request = std::collections::BTreeMap::new();
                request.insert("format".to_string(), json::Value::String(consume::RUN_FORMAT.into()));
                request.insert("schemaVersion".to_string(), json::Value::String("1.0".into()));
                for key in ["caseId", "specRef", "profile", "input"] {
                    let v = authoring.get(key).ok_or_else(|| format!("authoring document has no {key}"))?;
                    request.insert(key.to_string(), v.clone());
                }
                request.insert("requires".to_string(), json::Value::Array(Vec::new()));
                let response = adapter.run(&json::Value::Object(request), o.instrumented)?;
                if response.get("status").and_then(json::Value::as_str) != Some("ok") {
                    return Err(format!("adapter: {}", String::from_utf8_lossy(&json::to_canonical(&response))));
                }
                let observations = response.get("observations").ok_or("adapter: no observations")?;
                consume::fill(&authoring, observations, &filler, &store).map_err(|e| e.to_string())
            });
        match result {
            Ok(case) => {
                let target = out.join(format!("{}.json", case.fixture.case_id));
                if let Some(parent) = target.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut bytes = case.canonical_bytes();
                bytes.push(b'\n');
                match std::fs::write(&target, bytes) {
                    Ok(()) => {
                        written += 1;
                        println!("candidate {} -> {} file={}", case.fixture.case_id, target.display(), case.file_digest());
                    }
                    Err(e) => {
                        failed += 1;
                        println!("reject {file} {}: {e}", target.display());
                    }
                }
            }
            Err(e) => {
                failed += 1;
                println!("reject {file} {e}");
            }
        }
    }
    println!("FILL adapter={} written={written} rejected={failed}", caps.name);
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
