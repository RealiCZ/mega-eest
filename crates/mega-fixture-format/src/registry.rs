//! Spec descriptors and rule registries, resolved by content digest.
//!
//! A bundle holds `specs/<dir>/descriptor.json` and `specs/<dir>/rules.json`. A fixture's
//! `specRef.descriptor` is the SHA-256 of the descriptor's canonical bytes; the descriptor binds
//! the registry by the SHA-256 of the registry's canonical bytes. Where the files live is a
//! locator, never an identity.

use crate::error::{Error, ErrorCode};
use crate::json::{self, Value};
use crate::sha256_digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// One rule of a registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleInfo {
    /// Active (or retired) at the registry's spec.
    pub active: bool,
    /// Row names a citation may qualify the id with.
    pub rows: BTreeSet<String>,
    /// SHA-256 of the rule's text.
    pub text_digest: String,
}

/// A spec: its descriptor and its rule registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub name: String,
    pub descriptor_digest: String,
    pub registry_digest: String,
    pub rules: BTreeMap<String, RuleInfo>,
}

/// The specs a consumer has, by descriptor digest.
#[derive(Clone, Debug, Default)]
pub struct SpecStore {
    specs: BTreeMap<String, Spec>,
}

fn load_error(detail: String) -> Error {
    Error::new(ErrorCode::InvalidValue, "", detail)
}

fn str_member<'a>(value: &'a Value, key: &str, what: &str) -> Result<&'a str, Error> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| load_error(format!("{what}: missing string member {key:?}")))
}

impl SpecStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a spec from the bytes of its descriptor and registry, checking that the descriptor
    /// binds this registry.
    pub fn add(&mut self, descriptor: &[u8], registry: &[u8]) -> Result<&Spec, Error> {
        let d = json::parse(descriptor)?;
        let r = json::parse(registry)?;
        let descriptor_digest = sha256_digest(&json::to_canonical(&d));
        let registry_digest = sha256_digest(&json::to_canonical(&r));
        if str_member(&d, "format", "descriptor")? != "mega-spec-descriptor" {
            return Err(load_error("not a mega-spec-descriptor".into()));
        }
        if str_member(&r, "format", "registry")? != "mega-rule-registry" {
            return Err(load_error("not a mega-rule-registry".into()));
        }
        if str_member(&d, "registry", "descriptor")? != registry_digest {
            return Err(load_error(format!("the descriptor does not bind this registry ({registry_digest})")));
        }
        let name = str_member(&d, "name", "descriptor")?.to_string();
        if str_member(&r, "spec", "registry")? != name {
            return Err(load_error("the registry names another spec".into()));
        }
        let mut rules = BTreeMap::new();
        let Some(Value::Object(entries)) = r.get("rules") else {
            return Err(load_error("registry: missing rules".into()));
        };
        for (id, entry) in entries {
            let active = match str_member(entry, "status", id)? {
                "active" => true,
                "retired" => false,
                other => return Err(load_error(format!("{id}: unknown status {other:?}"))),
            };
            let rows = match entry.get("rows") {
                Some(Value::Array(rows)) => rows
                    .iter()
                    .map(|r| r.as_str().map(str::to_string).ok_or_else(|| load_error(format!("{id}: a row is not a string"))))
                    .collect::<Result<BTreeSet<String>, Error>>()?,
                _ => return Err(load_error(format!("{id}: missing rows"))),
            };
            let text_digest = str_member(entry, "textDigest", id)?.to_string();
            if sha256_digest(str_member(entry, "text", id)?.as_bytes()) != text_digest {
                return Err(load_error(format!("{id}: textDigest is not the digest of its text")));
            }
            rules.insert(id.clone(), RuleInfo { active, rows, text_digest });
        }
        let spec = Spec { name, descriptor_digest: descriptor_digest.clone(), registry_digest, rules };
        self.specs.insert(descriptor_digest.clone(), spec);
        Ok(&self.specs[&descriptor_digest])
    }

    /// Loads every `<dir>/*/descriptor.json` with its `rules.json`, checking that the descriptor
    /// binds both `rules.json` and `sources.json`.
    pub fn load_dir(dir: &Path) -> Result<SpecStore, Error> {
        let mut store = SpecStore::new();
        let entries = std::fs::read_dir(dir).map_err(|e| load_error(format!("{}: {e}", dir.display())))?;
        let mut paths: Vec<_> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        paths.sort();
        for path in paths {
            let descriptor = path.join("descriptor.json");
            if !descriptor.is_file() {
                continue;
            }
            let read = |p: &Path| std::fs::read(p).map_err(|e| load_error(format!("{}: {e}", p.display())));
            let descriptor_bytes = read(&descriptor)?;
            let sources = json::parse(&read(&path.join("sources.json"))?)?;
            let bound = json::parse(&descriptor_bytes)?;
            if str_member(&bound, "sources", "descriptor")? != sha256_digest(&json::to_canonical(&sources)) {
                return Err(load_error(format!("{}: the descriptor does not bind sources.json", path.display())));
            }
            store.add(&descriptor_bytes, &read(&path.join("rules.json"))?)?;
        }
        Ok(store)
    }

    /// The spec whose descriptor has this digest.
    pub fn get(&self, descriptor_digest: &str) -> Option<&Spec> {
        self.specs.get(descriptor_digest)
    }

    /// Every spec, by descriptor digest.
    pub fn specs(&self) -> impl Iterator<Item = &Spec> {
        self.specs.values()
    }
}
