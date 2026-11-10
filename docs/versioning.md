# Versions, releases and manifests

Four identities are kept apart:

| Identity | Form | Changes when |
| --- | --- | --- |
| Protocol spec | `specRef`: name and descriptor digest | the specification text or registry changes (a new commit is a new digest) |
| Fixture schema | `format` and `schemaVersion` (`mega-execution-fixture` 1.x) | major: incompatible meaning or shape; minor: additions behind a new `feature:` requirement |
| Suite release | `suite.name` and a semantic `suite.version` in the manifest, under a spec line | minor: reviewed cases added; patch: fixture corrections with a visible diff; major: an incompatible suite contract |
| Content | SHA-256 of canonical case bytes, blobs and the manifest | any byte |

Tags, file paths and download URLs are locators, not identities.

## Manifest

A release manifest (`schema/manifest.json`) lists:

- `schemas`: each schema file by the SHA-256 of its bytes;
- `specs`: each spec descriptor digest with its name and registry digest;
- `cases`: sorted by `caseId`, each with profile, `requires`, path, file digest and semantic digest;
- `shards`: named, sorted subsets of the case ids (for example `required`, `nightly`, `proof`);
- `blobs`: content-addressed attachments with their sizes;
- `files`: other bound files, such as `provenance.json` and `coverage.json`, by digest;
- `counts`: the number of cases and blobs, checked against the lists.

The manifest digest is the SHA-256 of the manifest's canonical bytes. It is not stored inside the
manifest; consumers pin it in a lockfile, and a release attestation signs it. Paths are relative
and may not contain empty, `.` or `..` segments.

A subset run reports the shard and its case count; it cannot claim coverage from cases outside the
shard. A correction never replaces bytes behind an existing release identity: it is a new release
with old and new digests and the affected case ids, and the old release is marked superseded.

The illustrative layout of a release bundle:

```text
manifest.json
schemas/<schema files>
specs/<dir>/descriptor.json, rules.json, sources.json
cases/<profile>/<file-digest>.json
blobs/<digest>
provenance.json
coverage.json
```

`vectors/accept/manifest-examples.in.json` is a manifest of the examples of this repository.
