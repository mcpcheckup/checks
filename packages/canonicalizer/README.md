# @mcpcheckup/canonicalizer

Deterministic JSON canonicalization and SHA-256 fingerprinting for MCP Checkup's
published attestations.

Every fingerprint MCP Checkup ever publishes — `toolset_fingerprint`,
`schema_fingerprint`, and anything else that claims "this is what the server
returned" — is produced by this package. If two independent parties run the
same bytes through `canonicalize()`, they must get the same string, forever.
That's the entire point: a third party should be able to re-derive our
fingerprints from the raw protocol response and check our work, without
trusting us.

This package has no runtime dependencies and only uses standard Web APIs
(`crypto.subtle`, `TextEncoder`, `String.prototype.normalize`). It runs
unmodified on Cloudflare Workers, in Node, and in a browser.

## Why not just `JSON.stringify`?

`JSON.stringify` doesn't guarantee a stable key order, silently drops
`undefined` values and functions, mangles `-0`, and will call a `toJSON()`
method if one is present — meaning the same logical object can serialize to
different bytes depending on engine, insertion order, or an object's
prototype chain. None of that is acceptable for something a cryptographic
hash gets computed over.

## The scheme: `nfc-jcs/v1` — and why it isn't called "RFC 8785"

Every attestation this project publishes records which canonicalization
scheme produced its fingerprints, as a plain string. That string is
`nfc-jcs/v1`, not `"RFC 8785"` or `"JCS"` — on purpose, because calling it
RFC 8785 would be a false claim a third party could act on incorrectly.

[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (the JSON Canonicalization
Scheme) is explicit that nothing depending on it may touch the Unicode form
of a string. §3.1 says so directly:

> Although the Unicode standard offers the possibility of rearranging
> certain character sequences, referred to as "Unicode Normalization"
> [UCNORM], JCS-compliant string processing does not take this into
> consideration. That is, **all components involved in a scheme depending on
> JCS MUST preserve Unicode string data "as is"**.

We need normalization anyway — see [below](#why-nfc-on-top-of-jcs) — which
means the scheme this package implements is JCS plus a step JCS's own spec
forbids anything calling itself JCS-compliant from doing. So the *overall*
scheme gets its own name, `nfc-jcs/v1`, defined as exactly three steps:

1. NFC-normalize every object key and every string value.
2. If, after step 1, two keys of the same object have become identical,
   reject the input (`DUPLICATE_KEY_AFTER_NFC`).
3. Apply RFC 8785 (JCS) to the result.

Step 3, taken on its own, *is* strictly RFC 8785 — that's exactly what
`src/rfc8785-vectors.test.ts` proves against the official test vectors, four
of which pass through steps 1–2 unchanged and match the official output
byte-for-byte. Steps 1 and 2 are ours, and are the only part a JCS-only
implementation won't reproduce.

That also means a third party doesn't need our code to check a
`nfc-jcs/v1` fingerprint — any conformant JCS library plus one
`normalize('NFC')` pass gets there:

```js
const nfcNormalized = deepNormalizeToNFC(parsedPayload) // walk it, .normalize('NFC') every key/string
const canonicalBytes = anyRfc8785Library.canonicalize(nfcNormalized) // any conformant JCS implementation
sha256(canonicalBytes) === claimedFingerprint
```

(`deepNormalizeToNFC` is a few lines you write yourself, or read ours in
`src/canonicalize.ts` — it's not a fourth dependency to trust, it's one
`String.prototype.normalize('NFC')` call applied recursively.)

`CANONICALIZATION_PROFILE` exports this exact string (`'nfc-jcs/v1'`) so
that "which scheme produced this fingerprint" is a value you can read out of
this package, not a string you have to keep in sync by hand.

## Rules

### Object keys: UTF-16 code unit order

Keys are sorted using JavaScript's default `Array.prototype.sort()`, which
compares strings by UTF-16 code unit — this is exactly what RFC 8785 §3.2.3
requires. It is easy to get this subtly wrong by reaching for
`.sort((a, b) => a.localeCompare(b))` instead, which sorts by linguistic
collation rules and can disagree with code-unit order — and does, verifiably,
for the pair `"\u{1F600}"` (an astral character, U+1F600, encoded as the
surrogate pair `0xD83D 0xDE00`) versus `"ﬞ"` (a single BMP code unit,
`0xFB1E`): `keys.sort()` puts `U+1F600` first, because `0xD83D < 0xFB1E` as
raw code units; `localeCompare` puts it last. Whichever one you use, you'll
get a *different, equally plausible-looking* canonical form — which is
exactly the kind of divergence a fingerprinting scheme cannot tolerate. This
case is locked down by a test in `src/canonicalize.test.ts`.

Array order is never touched. Arrays are ordered data; only object keys are
canonicalized.

### Numbers

Formatted using ECMAScript's own `Number::toString` (i.e. plain
`String(n)`), which is what RFC 8785 §3.2.2.3 specifies. Two things need
explicit handling on top of that:

- `-0` serializes to `0`. (`String(-0)` already produces `"0"` in every
  compliant JS engine, but we assert it explicitly rather than rely on that
  being obviously true forever.)
- `NaN`, `Infinity`, and `-Infinity` are not valid JSON values. Rather than
  let them silently produce `"NaN"` or `"null"`, we throw
  `CanonicalizationError` with code `NON_FINITE_NUMBER`.

`bigint` is rejected outright (`UNSUPPORTED_TYPE`) rather than coerced to
`number`, which could silently lose precision.

### Strings

Shortest-form JSON escaping: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t` for
their respective characters; any other code unit below `U+0020` becomes
`\u00xx` with lowercase hex. Everything else — including `/` and `U+007F`
(`DEL`) — is emitted as-is. Escaping more than the minimum would still be
valid JSON, but it wouldn't be *canonical*: there would again be more than
one legal way to represent the same string.

### Why NFC on top of JCS

Two strings can look identical and mean the same thing to a human while
being byte-for-byte different — one built from precomposed characters, the
other from a base character plus combining marks. RFC 8785 intentionally
does not normalize these, because JCS's job is to canonicalize a *JSON
document*, not to make judgment calls about Unicode equivalence.

We need that judgment call anyway, because our fingerprints are meant to
answer "did this MCP server's response change" — and "no, the bytes are
different only because someone typed the same string with a different
Unicode decomposition" is not a change we want to report as one. So every
key and string value is normalized to NFC before it takes part in sorting
or escaping.

That decision forces two more rules:

- **Two distinct keys that normalize to the same NFC string is an error, not
  a silent overwrite.** If it silently overwrote, two visually-identical but
  differently-encoded keys would collapse into one JSON property — an
  attacker's easiest way to make a payload look stable while smuggling a
  change past the fingerprint. We throw `DUPLICATE_KEY_AFTER_NFC` instead.
- **An unpaired ("lone") UTF-16 surrogate is an error, not a silent
  replacement character.** A lone surrogate cannot be encoded as well-formed
  UTF-8; silently emitting `U+FFFD` in its place would mean two different
  malformed inputs both hash to the same fingerprint. We throw
  `LONE_SURROGATE` instead.

One consequence worth being explicit about: two of the six official RFC 8785
test vectors (`unicode.json` and `weird.json`) are specifically designed to
prove that *raw* JCS does not normalize. Our output for those two therefore
does not match the official expected output — on purpose. `unicode.json`'s
value normalizes from two code points to one; `weird.json` contains a key,
U+FB33, whose canonical decomposition is excluded from recomposition under
NFC, so it becomes two code points instead of one, moving its sort position.
`src/rfc8785-vectors.test.ts` asserts both the divergence itself and the
correct NFC-adjusted output, using an independently hand-derived expected
value — not the implementation's own output — so a regression that silently
removes the NFC step is caught rather than rubber-stamped.

### Other rules

- `undefined`, functions, and `Symbol` values throw `UNSUPPORTED_TYPE` —
  including when they appear as an object property value or array element,
  where `JSON.stringify` would silently drop them (or turn `undefined` into
  `null` inside an array). Silent data loss under a hash function defeats
  the purpose of hashing.
- `toJSON()` methods are never called. Canonicalization operates on the
  value's own enumerable properties, full stop — not on however the value
  would prefer to present itself. (A `Date`, which has no own enumerable
  properties, canonicalizes to `{}`; it does not call `Date.prototype.toJSON`
  and produce an ISO string.)
- Circular references throw `CIRCULAR_REFERENCE`. This is detected as "is
  this object its own ancestor in the current traversal", not "have we ever
  seen this object" — the same object reachable twice through different,
  non-cyclic paths (a DAG) is completely normal and is not an error.
- Output has no insignificant whitespace.

## API

```ts
import {
  canonicalize,
  canonicalBytes,
  digest,
  CanonicalizationError,
  CANONICALIZATION_PROFILE,
  TOOLSET_PROJECTION_VERSION,
  projectToolset,
  projectSchemas,
} from '@mcpcheckup/canonicalizer'

CANONICALIZATION_PROFILE                       // 'nfc-jcs/v1' — record this alongside every fingerprint
canonicalize(value: unknown): string           // nfc-jcs/v1 text
canonicalBytes(value: unknown): Uint8Array      // same, as UTF-8 bytes
await digest(value: unknown): string            // "sha256:<64 lowercase hex chars>"
```

`CanonicalizationError` carries a `code`, one of: `NON_FINITE_NUMBER`,
`UNSUPPORTED_TYPE`, `DUPLICATE_KEY_AFTER_NFC`, `LONE_SURROGATE`,
`CIRCULAR_REFERENCE`.

### Projections: what actually gets fingerprinted

We never fingerprint a raw `tools/list` response. MCP servers legitimately
add fields over time (`annotations`, `_meta`, and whatever comes next); if
the fingerprint covered the whole response, every such addition would look
like drift on every monitored server at once. A false-positive rate above
3% is this project's kill criteria — fingerprinting the raw response would
blow through that on the first protocol revision.

Instead, `packages/canonicalizer` exports explicit, versioned projections
that pick fields by **allowlist** — never by exclusion — via
`projectToolset(tools)` and `projectSchemas(tools)`.

**The exact rules — every field read, the sort order, the same-name
tie-break, and what happens when `inputSchema` is missing — are specified
in [`PROJECTION-v1.md`](./PROJECTION-v1.md), not here.** That document is
written so a third party can reproduce `toolset_fingerprint` /
`schema_fingerprint` from their own `tools/list` call without this
package's code, and its own appendix cites the exact function and line
behind every rule — so this README stays a pointer, not a second copy that
can drift out of sync with the one that actually runs. Test vectors that
exercise every rule end to end (one real `tools/list` response, three
synthetic) live in `test/vectors/projection-v1/` and are checked by
`src/projection-v1-vectors.test.ts`.

## Testing

- `src/*.test.ts` — hand-written positive and negative cases for every rule
  above, run directly by Node (no test framework; this repo's convention).
- `src/rfc8785-vectors.test.ts` — the six official RFC 8785 test vectors from
  [cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization),
  copied byte-for-byte into `test/fixtures/rfc8785/` with no modification.
  Four match our output exactly; the other two (`unicode.json`, `weird.json`)
  are asserted to *deliberately* diverge, for the reason explained above.
- `src/cross-consistency.test.ts` — the same logical data, built with keys
  inserted in a different order, must canonicalize to identical bytes.
- `src/differential.test.ts` — differential testing against an independent
  reference implementation (below).
- `src/property.test.ts` — property-based testing with
  [`fast-check`](https://github.com/dubzzz/fast-check) for the invariants
  listed below.

Run with `pnpm test` (or `pnpm -r test` from the repo root).

### Differential testing against an independent implementation

Every hand-written test above checks this implementation against
expectations a human derived. `src/differential.test.ts` checks it against a
*second, independent implementation* instead: on every run it generates
5,000 random JSON values with [`fast-check`](https://github.com/dubzzz/fast-check)
— nested objects and arrays (including empty ones), deeply nested structures,
Unicode strings (surrogate pairs and decomposed combining-character
sequences deliberately over-represented), and number edge cases (`-0`,
`1e21`, `1e-7`, `Number.MAX_SAFE_INTEGER`, `Number.MAX_VALUE`,
`Number.MIN_VALUE`) — and runs each one through both this package's
`canonicalize()` and through [`canonicalize`](https://www.npmjs.com/package/canonicalize),
the npm package published by Erdtman, the author of RFC 8785 itself. It is a
`devDependency` only; nothing in this package's runtime depends on it — the
zero runtime-dependency guarantee described above is the whole point of
this package, and stays true here too.

Each of the 5,000 samples is checked one of two ways, chosen by whether the
sample is already fully NFC-normalized (every object key and every string
value, checked with a helper that does not call into this package's own
code — a differential test that reused the code under test to decide how to
check it would not be testing anything):

- **Already NFC.** `nfc-jcs/v1`'s NFC step is then a no-op, so this
  package's output must be **byte-for-byte identical** to the reference
  implementation's — this is, in effect, an independent second proof that
  step 3 of `nfc-jcs/v1` (see "The scheme" above) really is unmodified
  RFC 8785.
- **Not NFC.** The two outputs are first asserted to be **different** — if
  they were ever equal here, the NFC step would have been silently deleted.
  Then this package's output is asserted to equal **the reference
  implementation run on a deep-NFC-normalized copy of the same input**
  (again computed independently, via a second, separate helper). That is
  the precise characterization of the only difference between `nfc-jcs/v1`
  and raw JCS: *our divergence from a conformant JCS implementation is
  exactly the NFC step, applied once, and nothing else.* Not "close to,"
  not "usually" — exactly equal, checked byte-for-byte on every one of the
  ~1,300 (of 5,000) samples that landed in this branch on the run this
  paragraph was written against; the actual split is logged by the test
  itself on every run and varies with the random seed.

Both `assert`s above are backstops against a regression that removes the
NFC step. A third assertion at the end of the test fails outright if either
branch is never reached by a given run (all-NFC or all-divergent input
would make half of this test vacuous), so the two-way split isn't an
incidental property of the generator — it's required.

### Property-based testing

`src/property.test.ts` uses `fast-check` to assert properties that must
hold for *any* input, not just the specific cases hand-written elsewhere in
this test suite:

- Shuffling an object's key insertion order never changes `canonicalize`'s
  output (property-based generalization of `cross-consistency.test.ts`).
- `digest(x) === digest(JSON.parse(canonicalize(x)))` — a fingerprint
  survives a canonicalize-then-reparse round trip.
- `canonicalize`'s output is always valid JSON (`JSON.parse` never throws
  on it).
- NFC idempotence: re-canonicalizing `JSON.parse(canonicalize(x))` produces
  byte-for-byte the same string as the first pass, for any `x` — the second
  pass's NFC step is necessarily a no-op, because the first pass already
  normalized everything reachable through JSON.
- A lone UTF-16 surrogate, inserted at an arbitrary position inside an
  arbitrary string, inside an arbitrary surrounding JSON structure, always
  throws `LONE_SURROGATE` — whether it appears in a string value or an
  object key.
- `undefined`, a function, or a `Symbol`, inserted at an arbitrary position
  inside an arbitrary array or object, always throws `UNSUPPORTED_TYPE`.
- `projectToolset`/`projectSchemas`: shuffling the input tool array never
  changes the projection, and adding a field outside the allowlist to every
  tool never changes the projection either — the property-based form of
  "a server adding a new field can never look like drift" (see
  "Projections" above).
- `projectToolset`/`projectSchemas` with same-named tools: a dedicated
  generator draws tool names from a 3-name pool (`fc.constantFrom`) instead
  of near-unique random strings, so every run forces name collisions instead
  of hoping to sample one — the property-based form of the tie-breaking fix
  described in "Tie-breaking for same-named tools" above.
