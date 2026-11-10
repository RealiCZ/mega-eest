//! Release manifests (schema/manifest.json): the list of a release's cases, specs, shards, blobs
//! and bound files, each by digest. The manifest digest is the SHA-256 of the manifest's
//! canonical bytes; it is distributed outside the manifest, in consumer lockfiles and release
//! attestations.

use crate::decode::*;
use crate::error::{index, Error, ErrorCode};
use crate::json::{self, Value};
use crate::model::{case_id_ok, PROFILES, REQUIREMENTS};
use crate::sha256_digest;
use std::collections::BTreeSet;

/// One case entry of a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestCase {
    pub case_id: String,
    pub path: String,
    pub file: String,
    pub semantic: String,
}

/// A decoded, checked manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub value: Value,
    pub cases: Vec<ManifestCase>,
}

fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.contains('\\')
        && s.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}

fn semver_ok(s: &str) -> bool {
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let numeric = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && (p == "0" || !p.starts_with('0'));
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| numeric(p))
        && pre.map_or(true, |p| !p.is_empty() && p.split('.').all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_alphanumeric())))
}

fn count_matches(value: &Value, path: &str, n: usize) -> Result<()> {
    if u64q(value, path)? != n as u64 {
        return Err(Error::new(ErrorCode::InvalidReference, path, format!("the manifest lists {n}")));
    }
    Ok(())
}

impl Manifest {
    /// Parses, decodes and checks a manifest.
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Manifest, Error> {
        let value = json::parse(bytes)?;
        let mut o = Obj::new(&value, "")?;
        let names = ["format", "schemaVersion", "suite", "schemas", "specs", "cases", "shards", "blobs", "files", "counts"];
        o.shape(&names, &[])?;
        let (v, p) = o.req("format");
        constant(v, &p, "mega-execution-manifest", ErrorCode::UnsupportedFormat)?;
        let (v, p) = o.req("schemaVersion");
        patterned(v, &p, ErrorCode::UnsupportedSchemaVersion, |s| {
            s.strip_prefix("1.").is_some_and(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()) && (m == "0" || !m.starts_with('0')))
        })?;
        let (v, p) = o.req("suite");
        let mut suite = Obj::new(v, &p)?;
        suite.shape(&["name", "version"], &[])?;
        let (n, np) = suite.req("name");
        patterned(n, &np, ErrorCode::InvalidValue, |s| !s.is_empty() && s.split('-').all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())))?;
        let (ver, verp) = suite.req("version");
        patterned(ver, &verp, ErrorCode::InvalidValue, semver_ok)?;
        let (v, p) = o.req("schemas");
        map(v, &p, |k, kp| patterned(k, kp, ErrorCode::InvalidValue, safe_path).map(str::to_string), digest)?;
        let (v, p) = o.req("specs");
        map(v, &p, digest, |v, p| {
            let mut s = Obj::new(v, p)?;
            s.shape(&["name", "registry"], &[])?;
            let (n, np) = s.req("name");
            string(n, &np)?;
            let (r, rp) = s.req("registry");
            digest(r, &rp)
        })?;
        let (v, p) = o.req("cases");
        let cases = array(v, &p, 0, None, |v, p| {
            let mut c = Obj::new(v, p)?;
            c.shape(&["caseId", "profile", "requires", "path", "file", "semantic"], &[])?;
            let (id, idp) = c.req("caseId");
            let case_id = patterned(id, &idp, ErrorCode::InvalidCaseId, case_id_ok)?.to_string();
            let (pr, prp) = c.req("profile");
            one_of(pr, &prp, &PROFILES, ErrorCode::UnknownProfile)?;
            let (rq, rqp) = c.req("requires");
            array(rq, &rqp, 1, None, |v, p| one_of(v, p, &REQUIREMENTS, ErrorCode::UnknownRequirement))?;
            let (pa, pap) = c.req("path");
            let path = patterned(pa, &pap, ErrorCode::InvalidValue, safe_path)?.to_string();
            let (f, fp) = c.req("file");
            let (s, sp) = c.req("semantic");
            Ok(ManifestCase { case_id, path, file: digest(f, &fp)?, semantic: digest(s, &sp)? })
        })?;
        let (v, p) = o.req("shards");
        let shards = map(v, &p, |k, kp| patterned(k, kp, ErrorCode::InvalidValue, |s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')).map(str::to_string), |v, p| {
            array(v, p, 0, None, |v, p| patterned(v, p, ErrorCode::InvalidCaseId, case_id_ok).map(str::to_string))
        })?;
        let (v, p) = o.req("blobs");
        let blobs = map(v, &p, digest, |v, p| {
            let mut b = Obj::new(v, p)?;
            b.shape(&["size"], &[])?;
            let (s, sp) = b.req("size");
            u64q(s, &sp)
        })?;
        let (v, p) = o.req("files");
        map(v, &p, |k, kp| patterned(k, kp, ErrorCode::InvalidValue, safe_path).map(str::to_string), digest)?;
        let (v, p) = o.req("counts");
        let mut counts = Obj::new(v, &p)?;
        counts.shape(&["cases", "blobs"], &[])?;

        // Semantic checks.
        for (i, pair) in cases.windows(2).enumerate() {
            if pair[0].case_id >= pair[1].case_id {
                return Err(Error::new(ErrorCode::UnsortedSet, "/cases", format!("case {} is out of order or repeated", i + 1)));
            }
        }
        let ids: BTreeSet<&str> = cases.iter().map(|c| c.case_id.as_str()).collect();
        for (name, members) in &shards {
            let base = crate::error::child("/shards", name);
            for (i, pair) in members.windows(2).enumerate() {
                if pair[0] >= pair[1] {
                    return Err(Error::new(ErrorCode::UnsortedSet, &base, format!("member {} is out of order or repeated", i + 1)));
                }
            }
            for (i, member) in members.iter().enumerate() {
                if !ids.contains(member.as_str()) {
                    return Err(Error::new(ErrorCode::InvalidReference, index(&base, i), format!("{member} is not a case of the manifest")));
                }
            }
        }
        let (c, cp) = counts.req("cases");
        count_matches(c, &cp, cases.len())?;
        let (b, bp) = counts.req("blobs");
        count_matches(b, &bp, blobs.len())?;
        Ok(Manifest { value, cases })
    }

    /// The canonical bytes of the manifest.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        json::to_canonical(&self.value)
    }

    /// The manifest digest.
    pub fn digest(&self) -> String {
        sha256_digest(&self.canonical_bytes())
    }
}
