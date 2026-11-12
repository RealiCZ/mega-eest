//! The consumer loop and the filler, at their public seam: a case's bytes and an adapter in,
//! a status out; an authoring document and observations in, a candidate fixture out.

mod common;

use mega_fixture_format::consume::{self, Adapter, Capabilities, Status};
use mega_fixture_format::{json, sha256_digest, Case, Value};
use std::cell::RefCell;
use std::path::Path;

const EXAMPLE: &str = "examples/state-transition-sstore-fresh-slot.json";

/// A test double standing in for an implementation: it answers every run with fixed
/// observations, and records the requests it was sent.
struct Scripted {
    observations: Value,
    digest: Option<String>,
    requests: RefCell<Vec<Value>>,
}

impl Adapter for Scripted {
    fn capabilities(&self) -> Result<Value, String> {
        Ok(capabilities(&[
            "group:gas-ledgers",
            "group:limit",
            "group:outcome",
            "group:reads",
            "group:receipts",
            "group:resources",
            "group:state",
            "feature:salt",
        ]))
    }
    fn run(&self, request: &Value, _instrumented: bool) -> Result<Value, String> {
        self.requests.borrow_mut().push(request.clone());
        let digest = self.digest.clone().unwrap_or_else(|| sha256_digest(&json::to_canonical(request.get("input").unwrap())));
        Ok(object(vec![("status", Value::String("ok".into())), ("inputDigest", Value::String(digest)), ("observations", self.observations.clone())]))
    }
}

fn object(members: Vec<(&str, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.to_string())).collect())
}

fn capabilities(requires: &[&str]) -> Value {
    object(vec![
        ("format", Value::String("mega-fixture-adapter".into())),
        ("adapter", object(vec![("name", Value::String("scripted".into()))])),
        ("specs", strings(&["megaeth/Satin"])),
        ("profiles", strings(&["state-transition"])),
        ("requires", strings(requires)),
        ("modes", strings(&["plain"])),
    ])
}

fn example() -> (Vec<u8>, Value) {
    let bytes = common::read(EXAMPLE);
    let expected = json::parse(&bytes).unwrap().get("expected").unwrap().clone();
    (bytes, expected)
}

fn consume_with(adapter: &Scripted) -> consume::CaseReport {
    let caps = Capabilities::from_value(adapter.capabilities().unwrap()).unwrap();
    consume::consume_case(EXAMPLE, &example().0, &common::store(), adapter, &caps, false)
}

#[test]
fn matching_observations_pass_and_the_request_carries_no_expectation() {
    let (_, expected) = example();
    let adapter = Scripted { observations: expected, digest: None, requests: RefCell::new(Vec::new()) };
    let report = consume_with(&adapter);
    assert_eq!(report.status, Status::Pass);
    let requests = adapter.requests.borrow();
    let Value::Object(request) = &requests[0] else { panic!("an object") };
    let keys: Vec<&str> = request.keys().map(String::as_str).collect();
    assert_eq!(keys, ["caseId", "format", "input", "profile", "requires", "schemaVersion", "specRef"]);
}

#[test]
fn a_wrong_value_fails_with_its_path_and_rules() {
    let (_, mut observations) = example();
    // The example expects one state-growth unit; an implementation reporting two fails there.
    common::set(&mut observations, "/resources/stateGrowth/reported", Value::String("0x2".into()));
    let adapter = Scripted { observations, digest: None, requests: RefCell::new(Vec::new()) };
    match consume_with(&adapter).status {
        Status::Fail { path, expected, actual, rules } => {
            assert_eq!(path, "/expected/resources/stateGrowth/reported");
            assert_eq!(expected, Some(Value::String("0x1".into())));
            assert_eq!(actual, Some(Value::String("0x2".into())));
            // No assertion of the example covers resources.
            assert!(rules.is_empty(), "{rules:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_adapter_that_ran_other_input_is_an_error() {
    let (_, expected) = example();
    let adapter = Scripted { observations: expected, digest: Some(sha256_digest(b"other")), requests: RefCell::new(Vec::new()) };
    assert!(matches!(consume_with(&adapter).status, Status::Error { .. }));
}

#[test]
fn a_missing_capability_is_unsupported_and_nothing_runs() {
    let (bytes, expected) = example();
    let adapter = Scripted { observations: expected, digest: None, requests: RefCell::new(Vec::new()) };
    let caps = Capabilities::from_value(capabilities(&["group:outcome"])).unwrap();
    let report = consume::consume_case(EXAMPLE, &bytes, &common::store(), &adapter, &caps, false);
    match report.status {
        Status::Unsupported { missing } => assert!(missing.contains(&"group:reads".to_string()), "{missing:?}"),
        other => panic!("{other:?}"),
    }
    assert!(adapter.requests.borrow().is_empty());
}

#[test]
fn an_invalid_case_is_an_error_of_the_release() {
    let (_, expected) = example();
    let adapter = Scripted { observations: expected, digest: None, requests: RefCell::new(Vec::new()) };
    let caps = Capabilities::from_value(adapter.capabilities().unwrap()).unwrap();
    let report = consume::consume_case("x.json", b"{\"format\":1}", &common::store(), &adapter, &caps, false);
    assert!(matches!(report.status, Status::Error { .. }));
    assert!(adapter.requests.borrow().is_empty());
}

#[test]
fn candidates_never_go_to_examples_or_a_release() {
    assert!(consume::is_forbidden_fill_dir(Path::new("examples")));
    assert!(consume::is_forbidden_fill_dir(Path::new("a/examples/b")));
    assert!(consume::is_forbidden_fill_dir(Path::new("release-1.0")));
    assert!(!consume::is_forbidden_fill_dir(Path::new("candidates/filled/revm")));
}

#[test]
fn fill_writes_a_valid_candidate_with_derived_requirements() {
    let (bytes, expected) = example();
    let Value::Object(mut authoring) = json::parse(&bytes).unwrap() else { panic!() };
    authoring.remove("expected");
    authoring.remove("requires");
    let filler = object(vec![("adapter", Value::String("scripted".into()))]);
    let case: Case = consume::fill(&Value::Object(authoring.clone()), &expected, &filler, &common::store()).unwrap();
    let provenance = case.value.get("provenance").unwrap();
    assert_eq!(provenance.get("status").and_then(Value::as_str), Some("candidate"));
    assert_eq!(provenance.get("filler"), Some(&filler));
    // The derived requirements are the example's own.
    let original = json::parse(&bytes).unwrap();
    assert_eq!(case.value.get("requires"), original.get("requires"));
    // An authoring document that already has an expectation is refused.
    authoring.insert("expected".into(), expected.clone());
    assert!(consume::fill(&Value::Object(authoring), &expected, &filler, &common::store()).is_err());
}

#[cfg(unix)]
mod process {
    use super::*;
    use mega_fixture_format::consume::ProcessAdapter;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::time::{Duration, Instant};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let out = Command::new("mktemp").arg("-d").output().expect("mktemp is available");
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            Self(PathBuf::from(String::from_utf8(out.stdout).unwrap().trim()))
        }

        fn adapter(&self, body: &str) -> ProcessAdapter {
            let program = self.0.join("adapter.py");
            fs::write(&program, format!("#!/usr/bin/env python3\nimport json, os, pathlib, signal, sys, time\nroot = pathlib.Path(__file__).parent\n{body}\n"))
                .unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
            let mut adapter = ProcessAdapter::new(program);
            adapter.timeout = Duration::from_secs(10);
            adapter
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn large_stdout_completes_while_the_adapter_is_running() {
        let scratch = Scratch::new();
        let adapter = scratch.adapter("json.load(sys.stdin)\njson.dump('x' * (4 * 1024 * 1024), sys.stdout)");

        let value = adapter.run(&Value::Null, false).unwrap();

        assert_eq!(value.as_str().unwrap().len(), 4 * 1024 * 1024);
    }

    #[test]
    fn large_stderr_is_drained_while_the_adapter_is_running() {
        let scratch = Scratch::new();
        let adapter = scratch.adapter("json.load(sys.stdin)\nsys.stderr.write('x' * (4 * 1024 * 1024))\nprint('null')");

        let value = adapter.run(&Value::Null, false).unwrap();

        assert_eq!(value, Value::Null);
    }

    #[test]
    fn large_stdin_does_not_deadlock_an_adapter_that_writes_first() {
        let scratch = Scratch::new();
        let adapter = scratch.adapter(
            "sys.stdout.write(' ' * (4 * 1024 * 1024))\nsys.stdout.flush()\nsys.stderr.write('x' * (4 * 1024 * 1024))\nsys.stderr.flush()\nrequest = json.load(sys.stdin)\njson.dump(str(len(request)), sys.stdout)",
        );

        let value = adapter.run(&Value::String("x".repeat(4 * 1024 * 1024)), false).unwrap();

        assert_eq!(value.as_str(), Some("4194304"));
    }

    fn assert_reaped(scratch: &Scratch) {
        let pid = fs::read_to_string(scratch.0.join("pid")).unwrap();
        let status = Command::new("python3")
            .args(["-c", "import os, sys\ntry: os.kill(int(sys.argv[1]), 0)\nexcept ProcessLookupError: sys.exit(0)\nsys.exit(1)", &pid])
            .status()
            .unwrap();
        assert!(status.success(), "adapter {pid} must be killed and reaped");
    }

    #[test]
    fn timeout_kills_and_reaps_a_hanging_adapter_and_reports_error() {
        let scratch = Scratch::new();
        let mut adapter = scratch.adapter("(root / 'pid').write_text(str(os.getpid()))\njson.load(sys.stdin)\nsignal.pause()");
        adapter.timeout = Duration::from_secs(3);
        let caps = Capabilities::from_value(capabilities(&[
            "group:gas-ledgers",
            "group:limit",
            "group:outcome",
            "group:reads",
            "group:receipts",
            "group:resources",
            "group:state",
            "feature:salt",
        ]))
        .unwrap();
        let start = Instant::now();

        let report = consume::consume_case(EXAMPLE, &example().0, &common::store(), &adapter, &caps, false);

        assert_eq!(report.status, Status::Error { message: "adapter timed out after 3s".into() });
        assert!(start.elapsed() < Duration::from_secs(10), "timeout must bound the entire invocation");
        assert_reaped(&scratch);
    }

    #[test]
    fn timeout_also_covers_a_blocked_stdin_writer() {
        let scratch = Scratch::new();
        let mut adapter = scratch.adapter("(root / 'pid').write_text(str(os.getpid()))\nsignal.pause()");
        adapter.timeout = Duration::from_secs(3);
        let start = Instant::now();

        let error = adapter.run(&Value::String("x".repeat(4 * 1024 * 1024)), false).unwrap_err();

        assert_eq!(error, "adapter timed out after 3s");
        assert!(start.elapsed() < Duration::from_secs(10), "blocked input must not delay timeout");
        assert_reaped(&scratch);
    }

    #[test]
    fn timeout_still_applies_after_all_pipes_close() {
        let scratch = Scratch::new();
        let mut adapter =
            scratch.adapter("(root / 'pid').write_text(str(os.getpid()))\njson.load(sys.stdin)\nos.close(0)\nos.close(1)\nos.close(2)\nsignal.pause()");
        adapter.timeout = Duration::from_secs(3);
        let start = Instant::now();

        let error = adapter.run(&Value::Null, false).unwrap_err();

        assert_eq!(error, "adapter timed out after 3s");
        assert!(start.elapsed() < Duration::from_secs(10), "EOF is not process exit");
        assert_reaped(&scratch);
    }

    #[test]
    fn malformed_output_keeps_the_exit_code_and_last_stderr_lines() {
        let scratch = Scratch::new();
        let adapter = scratch.adapter("json.load(sys.stdin)\nprint('not JSON')\nsys.stderr.write('first\\nsecond\\nthird\\nfourth\\n')\nsys.exit(7)");

        let error = adapter.run(&Value::Null, false).unwrap_err();

        assert!(error.starts_with("adapter output is not a strict JSON document ("), "{error}");
        assert!(error.ends_with("exit Some(7); stderr: fourth | third | second"), "{error}");
    }

    #[test]
    fn valid_json_from_a_nonzero_exit_keeps_existing_response_semantics() {
        let scratch = Scratch::new();
        let adapter = scratch.adapter("json.load(sys.stdin)\nprint('{\"status\":\"error\",\"error\":\"execution failed\"}')\nsys.exit(7)");

        let response = adapter.run(&Value::Null, false).unwrap();

        assert_eq!(response.get("error").and_then(Value::as_str), Some("execution failed"));
    }

    fn jobs_fixture() -> (Scratch, ProcessAdapter) {
        let scratch = Scratch::new();
        let (bytes, expected) = example();
        let mut caps = capabilities(&[
            "group:gas-ledgers",
            "group:limit",
            "group:outcome",
            "group:reads",
            "group:receipts",
            "group:resources",
            "group:state",
            "feature:salt",
        ]);
        common::set(&mut caps, "/modes", strings(&["plain", "instrumented"]));
        fs::write(scratch.0.join("caps.json"), json::to_canonical(&caps)).unwrap();
        fs::write(scratch.0.join("expected.json"), json::to_canonical(&expected)).unwrap();
        fs::create_dir(scratch.0.join("cases")).unwrap();
        fs::create_dir(scratch.0.join("authoring")).unwrap();
        for n in 0..8 {
            let mut case = json::parse(&bytes).unwrap();
            common::set(&mut case, "/caseId", Value::String(format!("satin/consume/jobs/case-{n}")));
            fs::write(scratch.0.join(format!("cases/{n}.json")), json::to_canonical(&case)).unwrap();
            let Value::Object(mut authoring) = case else { panic!("fixture object") };
            authoring.remove("expected");
            authoring.remove("requires");
            fs::write(scratch.0.join(format!("authoring/{n}.json")), json::to_canonical(&Value::Object(authoring))).unwrap();
        }
        let adapter = scratch.adapter(
            r#"
import fcntl, hashlib
if sys.argv[1] == 'capabilities':
    print((root / 'caps.json').read_text())
    sys.exit(0)
request = json.load(sys.stdin)
with (root / 'lock').open('w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    state = json.loads((root / 'state.json').read_text())
    state['active'] += 1
    state['peak'] = max(state['peak'], state['active'])
    (root / 'peak').write_text(str(state['peak']))
    (root / 'state.json').write_text(json.dumps(state))
n = int(request['caseId'].rsplit('-', 1)[1])
time.sleep(0.15 if n % 3 == 0 else 0.03)
observations = json.loads((root / 'expected.json').read_text())
response = {'status': 'ok', 'observations': observations,
            'inputDigest': 'sha256:' + hashlib.sha256(json.dumps(request['input'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
if (root / 'mixed').exists():
    if n == 1:
        response = {'status': 'unsupported', 'reason': 'test capability'}
    elif n == 2:
        response = {'status': 'error', 'error': 'test error'}
    elif n == 3:
        observations['resources']['stateGrowth']['reported'] = '0x2'
with (root / 'lock').open('w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    state = json.loads((root / 'state.json').read_text())
    state['active'] -= 1
    (root / 'state.json').write_text(json.dumps(state))
print(json.dumps(response))
"#,
        );
        (scratch, adapter)
    }

    fn run_jobs(scratch: &Scratch, adapter: &ProcessAdapter, command: &str, jobs: Option<&str>, instrumented: bool) -> (Output, Vec<u8>, usize) {
        fs::write(scratch.0.join("state.json"), b"{\"active\":0,\"peak\":0}").unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mega-fixture"));
        cmd.arg(command).arg("--adapter").arg(&adapter.program).arg("--specs").arg(common::root().join("specs"));
        if let Some(jobs) = jobs {
            cmd.args(["--jobs", jobs]);
        }
        if instrumented {
            cmd.arg("--instrumented");
        }
        if command == "consume" {
            cmd.arg("--report").arg(scratch.0.join("report.json")).arg(scratch.0.join("cases"));
        } else {
            cmd.arg("--out").arg(scratch.0.join("filled"));
            for n in 0..8 {
                cmd.arg(scratch.0.join(format!("authoring/{n}.json")));
            }
        }
        let output = cmd.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if scratch.0.join("mixed").exists() { 1 } else { 0 }),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = if command == "consume" {
            fs::read(scratch.0.join("report.json")).unwrap()
        } else {
            (0..8).flat_map(|n| fs::read(scratch.0.join(format!("filled/satin/consume/jobs/case-{n}.json"))).unwrap()).collect()
        };
        let peak =
            fs::read_to_string(scratch.0.join("peak")).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&output.stdout))).parse::<usize>().unwrap();
        (output, bytes, peak)
    }

    #[test]
    fn jobs_consume_output_and_report_are_byte_identical_in_both_modes() {
        let (scratch, adapter) = jobs_fixture();
        fs::write(scratch.0.join("mixed"), b"").unwrap();

        for instrumented in [false, true] {
            let (serial, serial_report, peak) = run_jobs(&scratch, &adapter, "consume", None, instrumented);
            assert_eq!(serial.status.code(), Some(1), "mode={instrumented}");
            assert_eq!(peak, 1, "default is serial; mode={instrumented}");
            assert!(String::from_utf8_lossy(&serial.stdout).contains("cases=8 pass=5 fail=1 unsupported=1 error=1"));
            for jobs in ["1", "3", "32"] {
                let (parallel, parallel_report, peak) = run_jobs(&scratch, &adapter, "consume", Some(jobs), instrumented);
                assert_eq!(parallel.status.code(), serial.status.code(), "jobs={jobs} mode={instrumented}");
                assert_eq!(parallel.stdout, serial.stdout, "stdout; jobs={jobs} mode={instrumented}");
                assert_eq!(parallel.stderr, serial.stderr, "stderr; jobs={jobs} mode={instrumented}");
                assert_eq!(parallel_report, serial_report, "report; jobs={jobs} mode={instrumented}");
                assert!(peak <= jobs.parse::<usize>().unwrap(), "bounded concurrency; jobs={jobs} peak={peak}");
                assert_eq!(peak > 1, jobs != "1", "actual concurrency; jobs={jobs} peak={peak}");
            }
        }
    }

    #[test]
    fn jobs_fill_output_and_candidate_bytes_are_identical() {
        let (scratch, adapter) = jobs_fixture();
        let (serial, serial_files, _) = run_jobs(&scratch, &adapter, "fill", None, false);
        assert!(serial.status.success(), "{}", String::from_utf8_lossy(&serial.stdout));

        let (parallel, parallel_files, peak) = run_jobs(&scratch, &adapter, "fill", Some("3"), false);

        assert!(parallel.status.success(), "{}", String::from_utf8_lossy(&parallel.stdout));
        assert_eq!(parallel.stdout, serial.stdout);
        assert_eq!(parallel.stderr, serial.stderr);
        assert_eq!(parallel_files, serial_files);
        assert!(peak > 1 && peak <= 3, "peak={peak}");
    }

    #[test]
    fn jobs_rejects_zero_negative_nonnumeric_and_missing_values() {
        for args in [vec!["--jobs", "0"], vec!["--jobs", "-1"], vec!["--jobs", "many"], vec!["--jobs"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_mega-fixture")).args(["consume", "--adapter", "unused", "unused.json"]).args(&args).output().unwrap();
            assert_eq!(output.status.code(), Some(2), "args={args:?}");
            assert!(String::from_utf8_lossy(&output.stderr).starts_with("usage:"), "args={args:?}");
        }
    }
}
