//! The consumer loop of docs/adapter-protocol.md, and the candidate filler.
//!
//! An implementation is reached through an [`Adapter`]: in production a separate process
//! ([`ProcessAdapter`]) that speaks the adapter process interface, so this crate never links an
//! engine. The loop is read-only: it builds a run request that carries no expected value, runs the
//! adapter, compares its observations with the case ([`crate::compare`]) and reports a status.
//! It never writes a fixture.
//!
//! The filler is the one place that turns observations into expectations, and it writes a
//! candidate: a new fixture with `provenance.status` `candidate`, into a directory that is not an
//! examples or release directory ([`fill`], [`is_forbidden_fill_dir`]).

use crate::compare::{compare, Verdict};
use crate::error::{Error, ErrorCode};
use crate::json::{self, Value};
use crate::model::Requirement;
use crate::registry::SpecStore;
use crate::{sha256_digest, Case};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The format of a run request, the only document an adapter receives.
pub const RUN_FORMAT: &str = "mega-fixture-run";
/// The format of an adapter's capability declaration.
pub const ADAPTER_FORMAT: &str = "mega-fixture-adapter";

/// How long one adapter run may take before it is an `error`.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(300);

/// An implementation's adapter.
pub trait Adapter {
    /// The capability declaration (`<adapter> capabilities`).
    fn capabilities(&self) -> Result<Value, String>;
    /// One run of `request`, plain or instrumented: the adapter's response document.
    fn run(&self, request: &Value, instrumented: bool) -> Result<Value, String>;
}

/// An adapter that is a separate program: `<program> capabilities` and
/// `<program> run [--instrumented]` with the request on standard input.
#[derive(Clone, Debug)]
pub struct ProcessAdapter {
    /// The executable that implements the adapter process interface.
    pub program: PathBuf,
    /// The deadline for one invocation, including its standard input and output.
    pub timeout: Duration,
}

impl ProcessAdapter {
    /// Creates an adapter with the default [`RUN_TIMEOUT`] deadline.
    pub fn new(program: PathBuf) -> Self {
        Self { program, timeout: RUN_TIMEOUT }
    }

    fn exec(&self, args: &[&str], stdin: &[u8]) -> Result<Value, String> {
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{}: {e}", self.program.display()))?;
        let start = Instant::now();
        let mut input = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let stdin = stdin.to_vec();
        let (send, recv) = mpsc::channel();
        let writer = send.clone();
        std::thread::spawn(move || {
            let result = input.write_all(&stdin).map_err(|e| format!("adapter stdin: {e}"));
            drop(input);
            let _ = writer.send(result.map(|()| PipeEvent::Input));
        });
        for (mut pipe, is_stdout) in [(Box::new(stdout) as Box<dyn Read + Send>, true), (Box::new(stderr) as Box<dyn Read + Send>, false)] {
            let send = send.clone();
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let result = pipe.read_to_end(&mut bytes).map_err(|e| e.to_string());
                let _ = send.send(result.map(|_| if is_stdout { PipeEvent::Stdout(bytes) } else { PipeEvent::Stderr(bytes) }));
            });
        }
        // Observe exit without reaping: the child keeps its PID until this thread kills or
        // waits for it, so a timeout cannot signal an unrelated process with a recycled PID.
        let exit = exit_notification(&child);
        let waiter = std::thread::spawn(move || {
            let _ = send.send(exit().map(|()| PipeEvent::Exited));
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = (|| {
            for _ in 0..4 {
                match recv.recv_timeout(self.timeout.saturating_sub(start.elapsed())) {
                    Ok(Ok(PipeEvent::Input | PipeEvent::Exited)) => {}
                    Ok(Ok(PipeEvent::Stdout(bytes))) => stdout = bytes,
                    Ok(Ok(PipeEvent::Stderr(bytes))) => stderr = bytes,
                    Ok(Err(e)) => return Err(e),
                    Err(mpsc::RecvTimeoutError::Timeout) => return Err(format!("adapter timed out after {}s", self.timeout.as_secs())),
                    Err(mpsc::RecvTimeoutError::Disconnected) => return Err("adapter transport disconnected".into()),
                }
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = child.kill();
        }
        // Only the exit observer is joined on failure. Descendants may have inherited pipes;
        // waiting for those readers would let them defeat the adapter's deadline.
        let _ = waiter.join();
        let status = child.wait().map_err(|e| e.to_string());
        result?;
        let status = status?;
        json::parse(&stdout).map_err(|e| {
            let stderr = String::from_utf8_lossy(&stderr);
            let tail: String = stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | ");
            format!("adapter output is not a strict JSON document ({e}); exit {:?}; stderr: {tail}", status.code())
        })
    }
}

enum PipeEvent {
    Input,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited,
}

// The standard Child API cannot wait and kill concurrently. These observers leave reaping
// to Child::wait, and use no process-wide signal handler or polling interval.
#[cfg(unix)]
fn exit_notification(child: &Child) -> impl FnOnce() -> Result<(), String> + Send + 'static {
    let pid = child.id();
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    let pid = i64::from(pid);
    move || {
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        type Id = i64;
        #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly")))]
        type Id = u32;
        extern "C" {
            fn waitid(id_type: i32, id: Id, info: *mut std::ffi::c_void, options: i32) -> i32;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const WNOWAIT: i32 = 0x01000000;
        #[cfg(target_vendor = "apple")]
        const WNOWAIT: i32 = 0x20;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        const WNOWAIT: i32 = 8;
        #[cfg(target_os = "netbsd")]
        const WNOWAIT: i32 = 0x10000;
        #[cfg(target_os = "openbsd")]
        const WNOWAIT: i32 = 0x10;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        const P_PID: i32 = 0;
        #[cfg(target_os = "openbsd")]
        const P_PID: i32 = 2;
        #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd")))]
        const P_PID: i32 = 1;
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        const WEXITED: i32 = 16;
        #[cfg(target_os = "netbsd")]
        const WEXITED: i32 = 32;
        #[cfg(not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd")))]
        const WEXITED: i32 = 4;
        // siginfo_t is at most 128 bytes on these platforms, aligned at most like u64.
        let mut info = [0u64; 16];
        loop {
            // SAFETY: P_PID selects our unreaped child, WEXITED | WNOWAIT only observes exit,
            // and info provides aligned writable storage for siginfo_t for this call.
            if unsafe { waitid(P_PID, pid, info.as_mut_ptr().cast(), WEXITED | WNOWAIT) } == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.to_string());
            }
        }
    }
}

#[cfg(windows)]
fn exit_notification(child: &Child) -> impl FnOnce() -> Result<(), String> + Send + 'static {
    use std::os::windows::io::AsRawHandle;
    let handle = child.as_raw_handle() as usize;
    move || {
        #[link(name = "kernel32")]
        extern "system" {
            fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
        }
        // SAFETY: Child owns this process handle and outlives the observer thread.
        match unsafe { WaitForSingleObject(handle as *mut _, u32::MAX) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error().to_string()),
        }
    }
}

impl Adapter for ProcessAdapter {
    fn capabilities(&self) -> Result<Value, String> {
        self.exec(&["capabilities"], b"")
    }

    fn run(&self, request: &Value, instrumented: bool) -> Result<Value, String> {
        let args: &[&str] = if instrumented { &["run", "--instrumented"] } else { &["run"] };
        self.exec(args, &json::to_canonical(request))
    }
}

/// What an adapter declares it can run.
#[derive(Clone, Debug)]
pub struct Capabilities {
    pub value: Value,
    pub name: String,
    pub specs: BTreeSet<String>,
    pub profiles: BTreeSet<String>,
    pub requires: BTreeSet<Requirement>,
    pub modes: BTreeSet<String>,
}

fn strings(v: Option<&Value>, what: &str) -> Result<BTreeSet<String>, String> {
    match v {
        Some(Value::Array(items)) => {
            items.iter().map(|i| i.as_str().map(str::to_string).ok_or_else(|| format!("capabilities: {what}: not a string"))).collect()
        }
        _ => Err(format!("capabilities: {what}: missing")),
    }
}

impl Capabilities {
    /// Reads a capability declaration. An unknown requirement is an error of the adapter.
    pub fn from_value(value: Value) -> Result<Capabilities, String> {
        if value.get("format").and_then(Value::as_str) != Some(ADAPTER_FORMAT) {
            return Err(format!("capabilities: not a {ADAPTER_FORMAT} declaration"));
        }
        let name = value.get("adapter").and_then(|a| a.get("name")).and_then(Value::as_str).unwrap_or_default().to_string();
        let requires = strings(value.get("requires"), "requires")?
            .iter()
            .map(|r| Requirement::parse(r).ok_or_else(|| format!("capabilities: unknown requirement {r}")))
            .collect::<Result<_, _>>()?;
        Ok(Capabilities {
            name,
            specs: strings(value.get("specs"), "specs")?,
            profiles: strings(value.get("profiles"), "profiles")?,
            requires,
            modes: strings(value.get("modes"), "modes")?,
            value,
        })
    }
}

/// The run request of a case: its identity, spec, profile, requirements and input. It carries no
/// expected value, rule or provenance, so an adapter cannot read the expectation it is held to.
pub fn run_request(case: &Case) -> Value {
    let mut m = BTreeMap::new();
    m.insert("format".to_string(), Value::String(RUN_FORMAT.into()));
    m.insert("schemaVersion".to_string(), Value::String("1.0".into()));
    for key in ["caseId", "specRef", "profile", "requires", "input"] {
        m.insert(key.to_string(), case.value.get(key).expect("decoded fixture").clone());
    }
    Value::Object(m)
}

/// The input digest: SHA-256 of the canonical bytes of the case's `input`.
pub fn input_digest(case: &Case) -> String {
    sha256_digest(&json::to_canonical(case.value.get("input").expect("decoded fixture")))
}

/// The status of one case on one consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    /// The first differing semantic path, both values (`None`: absent) and the rules the case
    /// pins.
    Fail {
        path: String,
        expected: Option<Value>,
        actual: Option<Value>,
        rules: Vec<String>,
    },
    Unsupported {
        missing: Vec<String>,
    },
    Error {
        message: String,
    },
}

impl Status {
    pub fn name(&self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail { .. } => "fail",
            Status::Unsupported { .. } => "unsupported",
            Status::Error { .. } => "error",
        }
    }
}

/// The record of one case on one consumer.
#[derive(Clone, Debug)]
pub struct CaseReport {
    pub file: String,
    pub case_id: Option<String>,
    pub file_digest: Option<String>,
    pub semantic_digest: Option<String>,
    pub input_digest: Option<String>,
    /// The digest of the input the adapter says it ran.
    pub adapter_input_digest: Option<String>,
    /// SHA-256 of the canonical bytes of the actual observations.
    pub observations_digest: Option<String>,
    pub status: Status,
}

impl CaseReport {
    fn error(file: &str, message: String) -> CaseReport {
        CaseReport {
            file: file.to_string(),
            case_id: None,
            file_digest: None,
            semantic_digest: None,
            input_digest: None,
            adapter_input_digest: None,
            observations_digest: None,
            status: Status::Error { message },
        }
    }

    /// The report as JSON.
    pub fn to_value(&self) -> Value {
        let opt = |v: &Option<String>| v.clone().map_or(Value::Null, Value::String);
        let mut m = BTreeMap::new();
        m.insert("file".into(), Value::String(self.file.clone()));
        m.insert("caseId".into(), opt(&self.case_id));
        m.insert("fileDigest".into(), opt(&self.file_digest));
        m.insert("semanticDigest".into(), opt(&self.semantic_digest));
        m.insert("inputDigest".into(), opt(&self.input_digest));
        m.insert("adapterInputDigest".into(), opt(&self.adapter_input_digest));
        m.insert("observationsDigest".into(), opt(&self.observations_digest));
        m.insert("status".into(), Value::String(self.status.name().into()));
        match &self.status {
            Status::Fail { path, expected, actual, rules } => {
                m.insert("path".into(), Value::String(path.clone()));
                m.insert("expected".into(), expected.clone().unwrap_or(Value::Null));
                m.insert("actual".into(), actual.clone().unwrap_or(Value::Null));
                m.insert("rules".into(), Value::Array(rules.iter().cloned().map(Value::String).collect()));
            }
            Status::Unsupported { missing } => {
                m.insert("missing".into(), Value::Array(missing.iter().cloned().map(Value::String).collect()));
            }
            Status::Error { message } => {
                m.insert("message".into(), Value::String(message.clone()));
            }
            Status::Pass => {}
        }
        Value::Object(m)
    }
}

/// Runs one case (its bytes as stored) on `adapter`: validate, check capabilities, run, compare.
pub fn consume_case(file: &str, bytes: &[u8], store: &SpecStore, adapter: &dyn Adapter, caps: &Capabilities, instrumented: bool) -> CaseReport {
    let case = match Case::from_bytes(bytes, store) {
        Ok(c) => c,
        Err(e) => return CaseReport::error(file, format!("the case does not validate: {e}")),
    };
    let mut report = CaseReport {
        file: file.to_string(),
        case_id: Some(case.fixture.case_id.clone()),
        file_digest: Some(case.file_digest()),
        semantic_digest: Some(case.semantic_digest()),
        input_digest: Some(input_digest(&case)),
        adapter_input_digest: None,
        observations_digest: None,
        status: Status::Pass,
    };
    let mut missing: Vec<String> = Vec::new();
    let profile = case.value.get("profile").and_then(Value::as_str).unwrap_or_default();
    if !caps.profiles.contains(profile) {
        missing.push(format!("profile:{profile}"));
    }
    let spec = case.value.get("specRef").and_then(|s| s.get("name")).and_then(Value::as_str).unwrap_or_default();
    if !caps.specs.contains(spec) {
        missing.push(format!("spec:{spec}"));
    }
    if instrumented && !caps.modes.contains("instrumented") {
        missing.push("mode:instrumented".into());
    }
    missing.extend(case.fixture.requires.iter().filter(|r| !caps.requires.contains(r)).map(|r| r.as_str().to_string()));
    if !missing.is_empty() {
        report.status = Status::Unsupported { missing };
        return report;
    }
    let response = match adapter.run(&run_request(&case), instrumented) {
        Ok(r) => r,
        Err(e) => {
            report.status = Status::Error { message: e };
            return report;
        }
    };
    match response.get("status").and_then(Value::as_str) {
        Some("ok") => {}
        Some("unsupported") => {
            let why = response.get("reason").and_then(Value::as_str).unwrap_or("unsupported").to_string();
            report.status = Status::Unsupported { missing: vec![why] };
            return report;
        }
        Some("error") => {
            let why = response.get("error").and_then(Value::as_str).unwrap_or("error").to_string();
            report.status = Status::Error { message: why };
            return report;
        }
        _ => {
            report.status = Status::Error { message: "the adapter's response has no status".into() };
            return report;
        }
    }
    report.adapter_input_digest = response.get("inputDigest").and_then(Value::as_str).map(str::to_string);
    if report.adapter_input_digest != report.input_digest {
        report.status = Status::Error { message: "the adapter reports running another input".into() };
        return report;
    }
    let Some(observations) = response.get("observations") else {
        report.status = Status::Error { message: "the adapter's response has no observations".into() };
        return report;
    };
    report.observations_digest = Some(sha256_digest(&json::to_canonical(observations)));
    report.status = match compare(&case, observations, &caps.requires) {
        Verdict::Pass => Status::Pass,
        Verdict::Fail { path, expected, actual } => {
            let rules = case.fixture.rules.iter().map(|r| r.to_string()).collect();
            Status::Fail { path, expected, actual, rules }
        }
        Verdict::Unsupported { missing } => Status::Unsupported { missing: missing.iter().map(|r| r.as_str().to_string()).collect() },
        Verdict::Error(e) => Status::Error { message: format!("malformed observations: {e}") },
    };
    report
}

/// Whether a fill must not write into `dir`: an `examples` directory, or a directory whose name
/// starts with `release`, anywhere on its path. Candidates never land in either.
pub fn is_forbidden_fill_dir(dir: &Path) -> bool {
    dir.components().any(|c| match c {
        Component::Normal(name) => {
            let name = name.to_string_lossy();
            name == "examples" || name.starts_with("release")
        }
        _ => false,
    })
}

/// Fills a candidate: `authoring` is a fixture without `requires` and `expected` (its input,
/// rules and authoring provenance); the adapter's `observations` become `expected`,
/// `requires` is derived, and the provenance records the filler and marks the fixture a
/// candidate. The result is validated before it is returned.
pub fn fill(authoring: &Value, observations: &Value, filler: &Value, store: &SpecStore) -> Result<Case, Error> {
    let Value::Object(members) = authoring else {
        return Err(Error::new(ErrorCode::InvalidValue, "", "an authoring document is an object"));
    };
    for key in ["requires", "expected"] {
        if members.contains_key(key) {
            return Err(Error::new(ErrorCode::InvalidValue, format!("/{key}"), "an authoring document has no requires or expected"));
        }
    }
    let mut fixture = members.clone();
    fixture.insert("expected".into(), observations.clone());
    let profile = crate::model::Profile::parse(members.get("profile").and_then(Value::as_str).unwrap_or_default())
        .ok_or_else(|| Error::new(ErrorCode::UnknownProfile, "/profile", "unknown profile"))?;
    let input = members.get("input").cloned().unwrap_or(Value::Null);
    let requires = crate::validate::derive_requirements(profile, &input, observations)?;
    fixture.insert("requires".into(), Value::Array(requires.into_iter().map(Value::String).collect()));
    let mut provenance = match members.get("provenance") {
        Some(Value::Object(p)) => p.clone(),
        _ => BTreeMap::new(),
    };
    provenance.insert("status".into(), Value::String("candidate".into()));
    provenance.insert("filler".into(), filler.clone());
    provenance.insert("observationsDigest".into(), Value::String(sha256_digest(&json::to_canonical(observations))));
    fixture.insert("provenance".into(), Value::Object(provenance));
    Case::from_value(Value::Object(fixture), store)
}
