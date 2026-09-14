# Projection `v1` — exact rules

This is the precise, versioned specification of `toolset_projection_version:
'v1'`: what gets read out of a `tools/list` response before it is
canonicalized and hashed into `toolset_fingerprint` / `schema_fingerprint`.
It exists so a third party can reproduce either fingerprint from their own
`tools/list` call against the same server, without this package's code —
only these rules, `nfc-jcs/v1` canonicalization (see `README.md`), and
SHA-256.

If anything here and the code in `src/projections.ts` ever disagree, the
code is what actually ran and this document has drifted — but every rule
below cites the exact function and line it describes, specifically so that
drift is checkable, not a matter of trust. See the appendix at the end.

## Why a projection at all

Fingerprinting the raw `tools/list` response would fingerprint fields the
protocol legitimately adds over time (`annotations`, `_meta`, and whatever
comes next), and every such addition would look like drift on every
monitored server simultaneously. Projection picks fields by **allowlist**,
never by exclusion, so a new field never silently enters a fingerprint.

## Inputs

Both projections take `tools: unknown[]` — the `tools` array from a
`tools/list` JSON-RPC result, parsed from JSON, **before** any
canonicalization. Each entry is expected to be an object with at least a
string `name`; entries that aren't fail the whole call (see "Failure
modes" below) — there is no silent skip.

## `projectToolset(tools)` — feeds `toolset_fingerprint`

1. For every tool, take its `name` (a string). Any other field is discarded.
2. Sort the resulting array of names using JavaScript's default
   `Array.prototype.sort()` — i.e. ascending by UTF-16 code unit.
3. Return that sorted array of strings, unmodified duplicates included (two
   tools sharing a name produce two identical entries in the array).

`toolset_fingerprint` itself is `digest(projectToolset(tools))` — the
`sha256:<64 lowercase hex chars>` of `canonicalize()`'s `nfc-jcs/v1` bytes
of that sorted array. `digest()` NFC-normalizes each name as part of
canonicalization, so two names that differ only in Unicode normalization
form (e.g. a precomposed vs. decomposed accent) fingerprint identically.

## `projectSchemas(tools)` — feeds `schema_fingerprint`

1. For every tool, take `{ name, inputSchema }` — `name` as above,
   `inputSchema` exactly as the server sent it (not itself re-projected;
   whatever JSON value it is, including `undefined` when the field is
   absent). Every other field (`description`, `annotations`, `_meta`, …)
   is discarded.
2. Sort the resulting array primarily by `name` (same ordering as step 2
   above).
3. **Tie-break same-named tools by `canonicalize(inputSchema)` string
   comparison** — ascending, ordinary string `<`/`>` on the canonical JCS
   text. This is a real rule, not a fallback: two tools sharing a `name`
   but differing `inputSchema` must sort into one deterministic order
   regardless of the order the server happened to return them in, or the
   projection isn't reproducible from someone else's `tools/list` call.
   When `inputSchema` is `undefined`, its sort key is the empty string
   `''` (see appendix — this does **not** call `canonicalize(undefined)`,
   which would throw).
4. Return the sorted array of `{ name, inputSchema }` pairs, in that key
   order — `name` first, `inputSchema` second, matching the object literal
   `projectSchemas` itself returns (`nfc-jcs/v1`'s own key-sort step makes
   this irrelevant to the final bytes, but it's what a reader diffing this
   document against the code will see).

`schema_fingerprint` itself is `digest(projectSchemas(tools))`.

## Failure modes (both projections)

- `tools` is not an array → throws (`TypeError`), no fingerprint is
  produced. A caller must not substitute `[]` or skip the check.
- Any entry is not an object with a string `name` → throws (`TypeError`),
  for the same reason: a malformed entry is a **reportable defect**, not
  something to silently drop from the fingerprint.
- `schema_fingerprint` specifically: if **any** tool's `inputSchema` is
  `undefined`, `digest(projectSchemas(tools))` throws at the
  canonicalization step (`canonicalize()` rejects `undefined` — see
  `CanonicalizationError('UNSUPPORTED_TYPE', …)`). The projection itself
  still returns `undefined` in that slot (rule 1 above); it is
  `canonicalize()`, one layer up, that refuses to hash it. A tool that
  legitimately omits `inputSchema` therefore makes `schema_fingerprint`
  unable to be computed for the whole `tools/list` result, not just for
  that one tool.

## What is deliberately NOT part of this projection

- Tool `description`, `annotations`, `_meta`, and any other field: never
  read, by either projection (this is the allowlist property itself).
- The order tools were returned in: never preserved — both projections
  re-sort.
- Whether the server is the same server across two calls, or whether the
  transport was legacy or modern MCP: out of scope; the projection is a
  pure function of the `tools` array alone.

## Versioning

`TOOLSET_PROJECTION_VERSION` (currently `'v1'`) is recorded alongside every
published attestation. Any future change to either rule set above —
including tie-breaking, sort order, or which fields are read — is a new
version, never a silent redefinition of what `'v1'` means. See
`src/projections.ts`'s own module comment for the one exception already on
record (a same-name tie-break fix folded into `'v1'` because no attestation
had shipped under it yet — that window is closed for any future change).

## Appendix: rule → code

| Rule above | Function | File : line |
|---|---|---|
| Version string | `TOOLSET_PROJECTION_VERSION` | `src/projections.ts:12` |
| Tool array validation (`tools` must be an array) | `assertToolArray` | `src/projections.ts:14` |
| Tool `name` extraction + validation | `requireToolName` | `src/projections.ts:20` |
| `projectToolset`: name-only, sorted | `projectToolset` | `src/projections.ts:33` |
| `projectSchemas`: `{name, inputSchema}`, sorted, tie-broken | `projectSchemas` | `src/projections.ts:52` |
| Tie-break sort key when `inputSchema === undefined` (→ `''`) | `projectSchemas` | `src/projections.ts:57` |
| `nfc-jcs/v1` canonicalization applied before hashing | `canonicalize` | `src/canonicalize.ts:23` |
| NFC normalization of every string/key | `normalizeAndCheckSurrogates` | `src/canonicalize.ts:96` |
| `undefined` rejected by canonicalization (why `schema_fingerprint` throws when any `inputSchema` is missing) | `serialize`'s `case 'undefined'` | `src/canonicalize.ts:43-44` |
| `sha256:<hex>` digest of the canonical bytes | `digest` | `src/digest.ts:8` |

Test vectors that exercise every rule above end to end — one real
`tools/list` response and three synthetic ones — live in
`test/vectors/projection-v1/` and are recomputed and checked by
`src/projection-v1-vectors.test.ts`.
