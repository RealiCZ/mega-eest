# Canonicalization and digest vectors

Each vector is an exact input byte string and what a conforming reader must do with it.
`index.json` lists them:

| Member | Meaning |
| --- | --- |
| `id` | The vector's name |
| `kind` | `json` (strict JSON only), `case` (a full fixture, validated against `../specs`), `manifest` |
| `input` | The input file, read as exact bytes |
| `canonical` | For accepted vectors: the file holding the exact canonical bytes |
| `digest` | `json` and `manifest`: SHA-256 of the canonical bytes |
| `fileDigest`, `semanticDigest` | `case`: SHA-256 of the canonical bytes, and of the canonical bytes without `caseId` and `provenance` |
| `error` | For rejected vectors: the `code` and, below the JSON layer, the JSON Pointer `path` |

`accept/` holds accepted inputs (`*.in.json`, deliberately not canonical) and their canonical bytes
(`*.canonical.json`, no trailing newline). `reject/` holds inputs that must be rejected, each with a
single defect. [docs/canonical-json.md](../docs/canonical-json.md) defines the rules and codes.

The vectors cover member ordering by code point, string escapes, array order, empty and nested
values; duplicate members (also after unescaping), every kind of JSON number, `NaN`, byte-order
marks, invalid UTF-8, unpaired surrogates and syntax errors; non-minimal and overflowing quantities,
uppercase hex, odd-length bytes, wrong widths, missing prefixes, malformed digests and signed
integers; unknown required features and groups, unknown fields (schema 1's `assertions` among
them), formats, profiles, schema majors (schema 1 among them) and specs; unsorted sets; and manifests with unsorted cases, wrong counts, missing shard members
and unsafe paths. `case-same-semantics-other-name` shares its semantic digest with
`case-state-transition-sstore-fresh-slot` and differs in file digest.

To reproduce them with the second reader:

```bash
python3 -I tools/check_vectors.py vectors
```

The expected outputs were computed by the Rust crate (`tools/make_vectors.py`); the Python checker
recomputes them from the documents and schemas alone.
