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
`tools/list` JSON-RPC result (all pages of it: see "Which pages are
covered" below), parsed from JSON, **before** any canonicalization.
"Parsed from JSON" means what `JSON.parse` does: numbers become IEEE 754
doubles (so `1.0` and `1` are the same value, and an integer above 2^53 is
rounded), and when one object repeats a key, the last occurrence wins. Each
entry is expected to be an object with at least a string `name`; entries
that aren't fail the whole call (see "Failure modes" below) — there is no
silent skip.

## Which pages are covered

The projections receive one plain array and know nothing of pages; what that
array holds is decided by the check suite that read the server. The
attestation records which suite that was (`suite_version`).

**Suite 0.15.0 and later: every page.** The probe sends `tools/list`; while
the answer's `result` has a `nextCursor` that is present and not `null`, it
sends `tools/list` again to the same endpoint with `params: {"cursor":
<that nextCursor>}`. The `tools` arrays of all the pages are joined into one
array, and that one array is what both projections receive. Nothing is
removed from it: a tool that appears on two pages appears twice. Both
projections sort, so the order the pages or the tools came in never reaches
a fingerprint.

The probe reads at most 10 pages and at most 5,000 tools. A list it could
not read to its end is **incomplete**, and for an incomplete list **no
fingerprint is computed**, for either projection. A list is incomplete when
a further page exists but is not read, that is when

- 10 pages are in, or 5,000 tools are in, and a `nextCursor` is still
  present;
- a `nextCursor` is present but is not a string;
- a later page cannot be read: it runs out of the run's time, its request
  or its response goes over the body-size limit, or it is not a readable
  `tools/list` result (an authentication challenge, a body that is not
  JSON-RPC, an error, no `tools` array);
- more than 5,000 tools came in (the first 5,000 are kept, and the list is
  marked incomplete).

On an incomplete list `toolset_fingerprint` and `schema_fingerprint`, and
the two checks that compare them with an approved baseline, are recorded as
`SKIPPED` / `UNVERIFIED` with the reason key `tools_list_incomplete`, and no
tool snapshot is stored. A later page that fails in any other way (the
server asking the probe to back off, the probe's own request guard
refusing, a failed connection) ends the run, which likewise yields no
fingerprint. Behind a credential gate the list is not used at all, and no
fingerprint is computed.

**Suite 0.14.0 and earlier: the first page only.** Those suites sent one
`tools/list` request and fingerprinted its answer, even when it carried a
`nextCursor`. A fingerprint recorded by one of them covers that page alone;
it is not a fingerprint of the server's whole list, and a server that has
more than one page may give a different value when you recompute over all
of its pages.

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

## Recomputing a fingerprint yourself

`scripts/recompute-fingerprints.mjs` does the two computations above in plain
Node (standard library only; it imports nothing from this package). It reads
one `tools/list` answer per file, in page order — or one answer on standard
input — and prints

```
toolset_fingerprint sha256:…
schema_fingerprint sha256:…
```

An answer can be the JSON-RPC response, its bare `result`, a bare `tools`
array, or an event-stream body carrying the response. Exit status: 0 both
fingerprints computed; 1 one or both `FAILED` because the projection or the
canonicalization refused (a tool without a string `name`, a missing
`inputSchema` for the schema fingerprint, two keys of one object that become
the same after NFC, an unpaired surrogate, or a number that is not finite);
2 input unreadable, or a page given after one with no `nextCursor` (the probe
would not have asked for it); 3 the list is incomplete by the probe's rules
above (more than 10 pages or 5,000 tools, a `nextCursor` still present after
the 10th page or the 5,000th tool, a `nextCursor` that is not a string, or a
last page that still has a `nextCursor`), so no fingerprint is printed, as the
probe records none.

This site's own endpoint answers `tools/list` without a session, so one
`curl` is enough (POSIX shell syntax; the `accept` header must name both
types):

```
curl -sS -X POST https://mcpcheckup.com/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | node packages/canonicalizer/scripts/recompute-fingerprints.mjs
```

A server that wants an `initialize` handshake and a session header first
needs them before `tools/list`; the script only reads answers. When an
answer has a `nextCursor`, request the next page with `"params":
{"cursor":"<that value>"}`, keep each answer in its own file, and pass the
files in order.

Compare the result with `toolset_fingerprint` and `schema_fingerprint` in
`get_mcp_report` for the same server. `toolset_fingerprint` there is the
latest stored tool list's (`snapshot_run_id` and `snapshot_observed_at` say
which run and when). `schema_fingerprint` is the one in the signed
attestation of the latest settled run (`run_id`). It is `null` when that run
has no signature this site can read (it was not signed or was disqualified,
its signing key is not in the published key list, or its payload cannot be
read) and when it was signed `auth_gated`, a signature that carries no
fingerprints. A fingerprint changes only when a field its projection
covers changes: for `toolset_fingerprint` the tool names (a tool added,
removed or renamed), for `schema_fingerprint` a tool name or an
`inputSchema`. A changed `description`, `annotations`, `_meta` or any other
field changes neither. If your value differs from a fingerprint recorded
while those fields were the same, check these first:

- **Sort before you serialize.** Names are sorted as sent, by UTF-16 code
  unit (not by locale, not after NFC); same-named tools by the canonical
  text of their `inputSchema`.
- **Every object's keys are sorted, the outer ones too.** Each entry of the
  schema projection is `{"inputSchema":…,"name":…}`, `inputSchema` first.
- **Compact text.** No space after `:` or `,`; arrays keep their order.
- **Hash the UTF-8 bytes** of that text and write `sha256:` and 64 lowercase
  hex characters.
- **Read every page,** and use a list from the same time as the fingerprint
  you compare with.

`src/recompute-script.test.ts` holds the script to this package on the
recorded vectors and on random input, and shows that each of sixteen changes
to a single step of the script (no NFC, locale order, no tie-break, unsorted
keys, only the first page, and so on) makes the fingerprints stop matching.

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
| The script that follows the rules above | `canonicalize`, `projectToolset`, `projectSchemas`, `collectTools` | `scripts/recompute-fingerprints.mjs` |

The rules under "Which pages are covered" live in the check suite, not in
this package. `packages/checks/src/probe.ts` and `protocol.ts` change more
often than this package does, so the table names functions and files there,
not lines:

| Rule above | Function | File |
|---|---|---|
| Follow `nextCursor`, join the pages' `tools`, stop at 10 pages or 5,000 tools, mark the list incomplete | `performToolsList` (page limits: `MAX_TOOLS_LISTED`, and `budget.max_tools_list_pages` in `packages/checks/checks.json`) | `packages/checks/src/protocol.ts` |
| A later page that cannot be read makes the list incomplete; any other failure ends the run | `readFurtherPage` inside `performToolsList` | `packages/checks/src/protocol.ts` |
| Incomplete list: both fingerprints `SKIPPED` / `UNVERIFIED` with `tools_list_incomplete`, no tool snapshot | `runProbe`, the `listIncomplete` branch | `packages/checks/src/probe.ts` |
| Complete list: both projections applied to the joined array | `computeToolsetFingerprint`, `computeSchemaFingerprint`, `buildToolSnapshot` | `packages/checks/src/fingerprint.ts` |

Test vectors that exercise every rule above end to end — one real
`tools/list` response and three synthetic ones — live in
`test/vectors/projection-v1/` and are recomputed and checked by
`src/projection-v1-vectors.test.ts`. The paging rules are exercised by
`packages/checks/src/probe-tools-list-paging.test.ts`.
