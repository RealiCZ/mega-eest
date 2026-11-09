# Case identity

A case has two identities that answer different questions:

- **`caseId`**, its logical name: "which test is this?" Stable across releases, readable,
  independent of where the file lives, who hosts it and what its bytes hash to.
- **The semantic digest**: "what exactly does it test?" It changes whenever anything a consumer
  executes or compares changes, and only then.

A third value, the file digest, identifies the exact released bytes ([canonical-json.md](canonical-json.md#digests)).

## `caseId`

```text
<line>/<area>/<subject>[/<variant>...]
```

- Three to eight segments separated by `/`, at most 160 characters in all.
- Each segment is lowercase ASCII letters and digits in words joined by single hyphens
  (`[a-z0-9]+(-[a-z0-9]+)*`).
- `<line>` is the spec line the case belongs to: `satin`, `rex6`, or `rex6-satin` for cases that
  cross from Rex6 to Satin. It is not the spec's identity, which is `specRef`.
- `<area>` names the behaviour, normally the specification page or rule area in words
  (`state-gas`, `deposits`, `sequencer-registry`, `stateless-witness`), not a rule id: a case
  can cover several rules, and rule ids can retire while the case stays meaningful.
- The remaining segments say what distinguishes the case: the subject, then the boundary or
  variant (`sstore-fresh-slot/minimum-bucket`, `limit-stop/at-limit`, `below-limit`,
  `above-limit`).

A `caseId` must not contain a file name or extension, a repository, organization or person, a
digest or hash prefix, a date, an engine or backend name, or a generator seed. Generated cases
encode their variant in words or in a zero-padded ordinal that is stable for the case
(`satin/fuzz-pairs/detention-x-limit-stop/0042`); the generator, its revision and seed belong in
`provenance`, where an imported case also records its original name (for example a differential
scenario name or an EEST test id) as an alias.

Rules for releases:

1. A `caseId` is unique within a manifest.
2. A `caseId` keeps its meaning forever. A corrected expectation (a patch release) keeps the
   `caseId` and changes the semantic digest; the release diff shows the old and new digests.
3. A case whose input changes so that it tests something else gets a new `caseId`. The old one is
   retired, never reused.
4. The same `caseId` may appear under several specs (Satin and a later spec): identity is the pair
   of `caseId` and spec descriptor digest.

## The semantic digest

The semantic digest is the SHA-256 of the canonical bytes of the fixture with its `caseId` and
`provenance` members removed. It therefore binds `format`, `schemaVersion`, `specRef` (and through
it the rule registry), `profile`, `requires`, `rules`, `assertions`, `input` and `expected`.

- Renaming a case, moving its file, re-hosting the release or rewriting its provenance does not
  change it.
- Changing any input byte, any expected value, the set of required groups, a cited rule or the
  spec does.
- Two cases with the same semantic digest are duplicates under different names; a release keeps
  one.

Provenance is still bound: the file digest covers the whole fixture, and the manifest binds every
file digest and the provenance and coverage reports.
