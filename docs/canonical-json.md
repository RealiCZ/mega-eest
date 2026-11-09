# Canonical JSON, error codes and digests

Every fixture, manifest, descriptor and registry of this suite is JSON in a strict subset with
exactly one canonical byte form. Digests are taken over canonical bytes, so two readers in
different languages agree on identities without sharing code. The vectors under
[`vectors/`](../vectors/README.md) pin this page byte for byte.

## Accepted input

A document is accepted when all of these hold:

1. Its bytes are valid UTF-8 and do not start with a byte-order mark.
2. It is one JSON value (RFC 8259) with optional surrounding whitespace (space, tab, line feed,
   carriage return) and nothing after it.
3. It contains no number. Every quantity is a string ([Scalars](#scalars)); `1`, `1.5`, `-1` and
   `1e3` are all rejected. `NaN` and `Infinity` are not JSON and are rejected as syntax errors.
4. No object has two members with the same name after unescaping (`"a"` and `"a"` collide).
5. Every `\u` escape of a UTF-16 surrogate is part of a high-low pair.

Strings may use any JSON escape. At most 256 arrays and objects may nest; a deeper document is
rejected as `invalid-json`.

## Canonical form

The canonical bytes of an accepted value are written as follows, with no whitespace anywhere:

- `null`, `true`, `false` as themselves.
- A string as `"`, its characters, `"`. Characters are escaped exactly as: `"` → `\"`,
  `\` → `\\`, U+0008 → `\b`, U+000C → `\f`, U+000A → `\n`, U+000D → `\r`, U+0009 → `\t`, any
  other character below U+0020 → `\u00xx` with lowercase hex digits. Every other character,
  `/`, U+007F and all non-ASCII characters included, is written as its UTF-8 bytes.
- An array as `[`, its elements in order separated by `,`, `]`.
- An object as `{`, its members as `"name":value` separated by `,`, `}`, sorted by name in
  ascending Unicode code point order, which is the same as ascending byte order of the names'
  UTF-8 encodings. (This differs from RFC 8785, which sorts by UTF-16 code units; the vector
  `json-code-point-key-order` shows a case where the two orders disagree.)

Array order is significant and preserved. Where the format defines an array as a set, the
validator requires it sorted and duplicate-free instead of reordering it, so canonical bytes never
depend on a reordering step.

## Scalars

| Kind | Form | Example |
| --- | --- | --- |
| Quantity (`U64`, `U256`) | `0x` and minimal lowercase hex; zero is `0x0`; at most 16 or 64 digits | `0x5208` |
| Bytes | `0x` and even-length lowercase hex; empty is `0x` | `0x6001600055` |
| Fixed width (`Address`, `B256`, `B8`, `Bloom`) | `0x` and exactly 40, 64, 16 or 512 lowercase hex digits | full-width storage keys |
| Digest | `sha256:` and 64 lowercase hex digits | `sha256:4413…ff8a` |
| Signed integer | canonical decimal in [-2^127, 2^127-1]: no `+`, no leading zero, no `-0` | `-3` |

`null` always means a value the format specifies as absent (no receipt, no created address, an
account known to be absent). It never means "do not check".

## Error codes

A rejection carries a stable code and, below the JSON layer, the JSON Pointer (RFC 6901) of the
value at fault. For an input with exactly one defect, both codes and pointers are part of the
contract: every conforming reader reports the same ones. For inputs with several defects a reader
may report any of them. Pointers of JSON-layer errors are informative only.

### JSON layer

| Code | Meaning |
| --- | --- |
| `invalid-utf8` | The bytes are not UTF-8 |
| `byte-order-mark` | The input starts with EF BB BF |
| `invalid-json` | Syntax error, trailing content, control character in a string, `NaN`/`Infinity`, empty input, nesting deeper than 256 |
| `duplicate-key` | An object has two members with the same name |
| `number-not-allowed` | A JSON number appears anywhere |
| `invalid-unicode-escape` | An unpaired surrogate escape |

### Schema layer

| Code | Meaning |
| --- | --- |
| `unknown-field` | A member the schema does not define (outside `provenance`) |
| `missing-field` | A required member is absent; the pointer names the missing member |
| `wrong-type` | A value of the wrong JSON type, `null` where the schema allows none included |
| `invalid-value` | A value outside an enumeration, constant or pattern without a more specific code |
| `unsupported-format` | `format` is not this format |
| `unsupported-schema-version` | `schemaVersion` is not `1.<minor>` |
| `unknown-profile` | `profile` is not one of the five profiles |
| `unknown-requirement` | An entry of `requires` is unknown to the reader |
| `unknown-commitment` | A commitment kind is unknown |
| `invalid-case-id`, `invalid-rule-ref`, `invalid-signed-integer` | Malformed identifiers and signed integers |
| `too-few-items`, `too-many-items` | Array length bounds |
| `unbound-assertion` | An assertion path outside `/expected` (or, semantically, resolving to nothing) |
| hex codes | See below |

A malformed hex string is classified by the first failing check, in this order:

1. `invalid-digest`: a digest without the `sha256:` prefix; `missing-hex-prefix`: any other hex
   string without `0x`.
2. `invalid-hex`: a character outside `0-9a-fA-F` after the prefix.
3. `uppercase-hex`: any of `A-F`.
4. By kind: `non-minimal-quantity` (a quantity with no digit or a leading zero),
   `quantity-overflow` (more digits than the quantity's width), `odd-length-bytes`, `wrong-width`
   (fixed-width values and digests).

The schemas carry this classification as annotations: `x-hex` (`quantity`, `bytes`, `fixed`,
`digest`) with `x-bits` or `x-bytes`, `x-signed` for the signed-integer range, and `x-error` for
the code of a failed pattern, enumeration or constant. Standard JSON Schema validators ignore them
and still reject the same inputs, with less specific errors.

### Semantic layer

The checks of [format.md](format.md#semantic-checks), in their order, with codes
`unknown-spec`, `spec-name-mismatch`, `unsorted-set`, `unknown-rule`, `unknown-rule-row`,
`retired-rule`, `unbound-assertion`, `assertion-rule-not-cited`, `uncovered-rule`,
`requirement-mismatch`, `inconsistent-outcome`, `zero-slot-in-complete-state`,
`root-over-sparse-state` and `invalid-reference`.

## Digests

All digests are SHA-256, written `sha256:<hex>`.

| Digest | Over |
| --- | --- |
| File digest of a case | The canonical bytes of the whole fixture |
| Semantic digest of a case | The canonical bytes of the fixture without its `caseId` and `provenance` members |
| Manifest digest | The canonical bytes of the manifest; never stored inside it |
| Descriptor digest (`specRef.descriptor`) | The canonical bytes of the spec descriptor |
| Registry digest | The canonical bytes of the rule registry; bound by the descriptor |
| Rule text digest | The UTF-8 bytes of a rule's text ([spec-identity.md](spec-identity.md)) |
| Blob and schema-file digest | The exact bytes of the file (schema files contain JSON numbers, so they are hashed as blobs) |

Two fixtures with the same semantic digest test the same thing whatever they are called; renaming
a case or editing its provenance changes its file digest only (vector
`case-same-semantics-other-name`).

Validate before hashing: a digest is defined only for an accepted value.
