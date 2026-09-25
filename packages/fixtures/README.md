# @mcpcheckup/fixtures

A deterministic corpus of simulated MCP servers, each declaring the exact detector
assertions a correct run against it must produce. This is the spec a detector is built
to satisfy — not a set of examples to eyeball and hope the output "looks right." TDD
here means: this corpus and its expected results were written first; the detector's job
is to satisfy them, not the other way around.

**Scope note:** this corpus is the acceptance standard for the **prober** — the thing
that probes a live MCP server and produces `checks.json`-shaped assertions about it. PRD
§5.4's "CANON normalization rules" also names four negative categories — stale version,
auth scope mismatch, cross-layer hash mismatch, key rotation — but those describe
defects in a *signed attestation* (e.g. an attestation citing a stale suite version, or
signed with a since-rotated key), which is what an attestation **verifier** checks, not
what a prober observes about a live server. That verifier corpus does not exist yet; it
belongs to `packages/verifier` (tracked internally for M2). Two
fixtures below were originally mis-filed under those PRD §5.4 names because they
happened to share a topic (auth, keys) — they've been kept and renamed, because the
prober-observable behavior they test is real, but the PRD §5.4 framing has been removed
from them; see the footnote under the negative-fixtures table.

## The layering problem this package exists to solve, and how it's solved

Fixtures need to provide an MCP server the detector can actually probe. But
[`@mcpcheckup/ssrf-guard`](../ssrf-guard) unconditionally rejects `localhost` and every
private IP range — which means a real local fixture HTTP server would fail the
product's own SSRF defense.

**The fix is not a bypass flag on the guard.** `ssrf-guard` has no `allowPrivate` /
`testMode` switch, on purpose — a test backdoor on a security boundary is exactly the
kind of thing that eventually gets left on in production. Its own 139 assertions cover
its policy unconditionally; nothing here weakens that.

Instead, the detector is expected to accept an **injectable fetch implementation**:
production wires in `guardedFetch` from `ssrf-guard`; tests wire in a fixture's
`createHandler()` directly. Whether the *guard's policy* is correct and whether the
*detector's probing logic* is correct are two separate questions, verified separately,
neither one diluted by the other. Every fixture in this package is exactly that
injectable handler — a plain `(input, init) => Promise<Response>` function, the same
shape `fetch` itself has, so it drops into that seam with no adapter.

## What a fixture is

Not a static JSON blob. A fetch-compatible **handler** — because what needs testing
includes interactions a blob can't express: handshake sequences, session state,
redirect chains, and how a server's error responses are *shaped*, not just what they
contain. Every fixture declares:

- `id` and a one-sentence `description`
- the protocol revision it simulates (`protocolRevision`, or `null` when the fixture is
  deliberately about a server whose revision can't be identified)
- `guardsAgainst` — the specific misjudgment this fixture exists to catch, for every
  fixture, not just the negative ones (a positive fixture guards against a false
  failure just as much as a negative one guards against a false pass)
- `expectedAssertions` — every `check_id` + `execution_status` + `assertion_status` (+
  `reason` when `UNVERIFIED`) a correct detector run must produce, aligned against
  [`packages/checks/checks.json`](../checks/checks.json), the single source of truth
  for check definitions
- `createHandler()` — returns a **fresh** handler instance with its own isolated state
  (session tracking, etc.) — never share one handler across two separate runs, or the
  second run inherits state left over from the first and the determinism guarantee
  breaks
- `sampleRun(handler)` — drives a handler through the fixture's natural request
  sequence and returns each response's deterministic summary; both the thing the
  determinism tests replay and a runnable example of the exact traffic the fixture
  expects

`tls_certificate` (`packages/checks/checks.json`'s one check with `executor:
"container"`) is out of scope for this corpus: these fixtures model the JS/fetch-level
prober, not a TLS-terminating container executor, so no fixture declares an assertion
for it.

## Determinism

No fixture may emit a real wall-clock timestamp, a random id, or a random port —
session ids are fixed constants (see `FIXED_SESSION_ID` in `src/fixtures/shared.ts`),
not `crypto.randomUUID()`. `src/determinism.test.ts` proves this isn't just a stated
intent: it runs every fixture's `sampleRun` twice against two independently-created
handlers and asserts the two runs' `canonicalBytes` (via `@mcpcheckup/canonicalizer`)
are byte-identical.

## Nothing here is hand-verified when it can be mechanically verified

Three of this package's checks re-derive their expected result from the real
production logic instead of trusting a hand-typed `assertion_status`:

- **`fingerprint-consistency.test.ts`** — for every fixture with a `toolset_fingerprint`
  / `schema_fingerprint` expectation, it actually runs `@mcpcheckup/canonicalizer`'s
  real `projectToolset` / `projectSchemas` + `digest` against the fixture's tool list
  and asserts the resulting success/throw matches what the fixture declares. This is
  how `cross-layer-hash-mismatch`'s `schema_fingerprint: FAILED` is verified: a tool
  missing its `inputSchema` key makes `projectSchemas` include `inputSchema: undefined`,
  which `canonicalize()` genuinely throws `UNSUPPORTED_TYPE` on — not an assertion we
  typed by hand and hoped was right.
- **`hygiene-consistency.test.ts`** — for every fixture with a `tool_description_hygiene`
  expectation, it runs `@mcpcheckup/checks`'s real `runHygieneCheck` and asserts the
  result matches. This package never re-implements the hygiene regex table itself —
  `CLAUDE.md`'s rule against duplicating predicate logic applies here too.
- **`drift-pair.test.ts`** — for the `toolset-drift-run-1` / `toolset-drift-run-2` pair,
  it computes both fixtures' real `toolset_fingerprint` and asserts they actually
  differ, proving the "drift" the pair claims to demonstrate is real, not asserted.

## Versioning

`FIXTURE_CORPUS_VERSION` and `corpusDigest(corpus)` (order-independent, hashes only the
normative content — `id` / `protocolRevision` / `kind` / `expectedAssertions` — not prose
handler implementations) exist so a future attestation can record "this conclusion was
produced by a detector verified against fixture corpus vX @ `<digest>`" — evidence about
the evidence-producer itself, not just about the target.

## The corpus

The two "required" minimums are the ones `src/corpus.test.ts` actually asserts (at least
3 positive, at least 9 negative). The "provided" counts are the real `FIXTURE_CORPUS`
counts, and `src/corpus.test.ts` now asserts that both headings below match it — so a
fixture added without touching this file turns that test red instead of silently rotting
these numbers — which is how both of them came to be wrong for several rounds.

**The tables below are not exhaustive.** Several fixtures added in later rounds have no
row here yet; `src/index.ts`'s `FIXTURE_CORPUS` is the authoritative list, and the counts
in the two headings come from it rather than from these rows.

### Positive (3 required, 15 provided)

| id | revision | guards against |
|---|---|---|
| `modern-baseline-clean` | `2026-07-28` | **P0 (PRD §5.2).** A fully correct modern implementation. This is also the corpus's negative control: it exists to prove the detector doesn't misreport the newest implementation as `FAILED` just because it only recognizes the old `initialize` handshake. |
| `legacy-baseline-clean` | `2025-06-18` | That a correct legacy implementation is judged fairly — the detector must probe modern first, recognize the resulting 400 as *not* a modern error, and fall back to `initialize`, per the 2026-07-28 spec's own backward-compatibility algorithm. |
| `large-toolset-nested-schemas` | `2026-07-28` | That deeply nested `inputSchema` (object-in-object, arrays of objects, `enum`) doesn't destabilize `nfc-jcs/v1` canonicalization or the `projectSchemas` field-allowlist projection. |

### Negative (9 required, 59 provided)

| id | assertion_status | guards against |
|---|---|---|
| `stale-protocol-version` | `protocol_revision: FAILED` | A revision string outside `checks.json`'s `revision_matrix` must not pass just because *some* version string was present. `discovery_handshake` stays `VERIFIED` — the handshake mechanics were fine; the version itself is unrecognized. Two independent facts. |
| `tools-list-illegal-structure` | `tools_list: FAILED` | Structural legality is a determinate fact, not a judgment call — `OBSERVED_RISK`/`UNVERIFIED` would be too lenient here. Fingerprint/hygiene checks correctly fall back to `UNVERIFIED` (no usable data), not a fingerprint computed over garbage. |
| `error-response-nonconformant-shape` | `error_taxonomy: OBSERVED_RISK` | A malformed error shape breaks client retry logic but isn't evidence the server itself is broken — hygiene problem, not failure. |
| `no-credentials-unverifiable-auth` | `auth_metadata: UNVERIFIED` | "We saw nothing" must never collapse into "we saw something wrong" (`OBSERVED_RISK`) or "it's fine" (`VERIFIED`) — a bare 401 with no challenge proves nothing either way. |
| `response-exceeds-budget` | `reachability: ERROR`/`UNVERIFIED`, everything downstream `SKIPPED`/`UNVERIFIED` | **The hardest one to get wrong.** A timeout/oversized response is not evidence the target is broken — it may be our own network. Never `FAILED`. And once a run aborts on budget, nothing downstream gets to claim confident `VERIFIED` while `reachability` says `ERROR` — that combination would be a self-contradictory attestation. |
| `redirect-cross-host` | `redirect_policy: OBSERVED_RISK` | A cross-host redirect is flagged regardless of whether the destination turns out to be perfectly normal (this fixture's destination *is* perfectly normal) — "a redirect happened" and "the destination is trustworthy" are different claims; only the first one is what this check makes. |
| `auth-challenge-scope-contradicts-metadata`\* | `auth_metadata: OBSERVED_RISK` | The `WWW-Authenticate` challenge's declared `scope` and its own linked protected-resource-metadata document's `scopes_supported` must actually be cross-checked against each other — reading only one of the two misses a self-contradiction. |
| `auth-metadata-illegal-structure` | `auth_metadata: OBSERVED_RISK` | Distinguishes "we saw a challenge but couldn't parse what it points to" from `no-credentials-unverifiable-auth`'s "we saw nothing at all" — two different kinds of uncertainty, and the detector has to tell them apart rather than lumping every auth-related unknown into one bucket. |
| `jwks-multiple-keys-not-flagged`\* | `auth_metadata: VERIFIED` | A JWKS with two keys (old `kid` + new `kid`) is the *correct*, standard way to implement key rotation with a transition window — not evidence of anything wrong. A detector that assumes "exactly one key" would misflag every server going through a normal rotation. |
| `credential-challenge-qdtext-control-char-not-exempted` | `discovery_handshake` / `protocol_revision` / `tools_list`: `FAILED` | A 401 whose `WWW-Authenticate` is a fully well-formed `Bearer realm="…"` except for one C0 control character inside the quoted-string. RFC 9110 §5.6.4's `qdtext` and `quoted-pair` admit no C0 control but HTAB and no DEL, so this challenge is malformed and the round keeps its ordinary `FAILED` verdict — the credential-gate exemption must never turn a genuine `FAILED` into `UNVERIFIED`/`credential_required`. Same ruling and same expectations as `credential-challenge-htab-separator-not-exempted`. |
| `tool-description-injection-pattern` | `tool_description_hygiene: OBSERVED_RISK` | Same non-negotiable rule as the check itself: signal only, never inferred intent, never `FAILED`. |
| `cross-layer-hash-mismatch` | `toolset_fingerprint: VERIFIED`, `schema_fingerprint: FAILED` | Proves `toolset_fingerprint` (name-only) and `schema_fingerprint` (name + `inputSchema`) are genuinely independent checks — one succeeding must never be read as implying the other does. `tools_list` itself stays `VERIFIED`: it only requires a legal array of tool objects, not that every tool has a fingerprintable schema — a boundary the two checks draw on purpose. |
| `toolset-drift-run-1` / `toolset-drift-run-2` | both entirely `VERIFIED` internally | `CLAUDE.md`'s hard rule: on the monitoring path (no approved baseline), a toolset change produces a `drift_event` and `assertion_status` stays `VERIFIED` — only an approved baseline can make a deviation `FAILED`. `drift_event` is a cross-run product concept, not a `checks.json` check_id, so it can't live in either fixture's own `expectedAssertions`; `drift-pair.test.ts` verifies the pair's `toolset_fingerprint` values genuinely differ and that both individually stay `UNVERIFIED` (not `FAILED`) on `toolset_unchanged_vs_approved`. |

\* **`auth-challenge-scope-contradicts-metadata` and `jwks-multiple-keys-not-flagged`
were originally named `auth-scope-mismatch` and `key-rotation-multi-key-jwks`, framed as
covering PRD §5.4's "auth scope mismatch" / "key rotation" categories.** That framing was
wrong: those PRD §5.4 categories describe defects in a *signed attestation* (an
attestation's claimed authorization scope not matching what was actually granted; an
attestation signed with an already-rotated key) — properties an attestation **verifier**
checks by inspecting the attestation itself, not properties a **prober** can observe by
talking to a live server. The two fixtures were renamed to describe the actual
prober-observable behavior they test (a `WWW-Authenticate` challenge's declared scope
contradicting its own linked metadata document; a multi-key JWKS correctly *not* being
flagged as risky) and the PRD §5.4 citation was removed from both. They're kept because
that behavior is real and worth a fixture — they just don't stand in for the PRD §5.4
verifier corpus, which remains unbuilt (see the scope note at the top of this file).

### Why HTTP 400 with a plain JSON-RPC error for the legacy `server/discover` probe

The 2026-07-28 spec's backward-compatibility section is explicit that a legacy server's
exact response to a modern probe is implementation-defined — it "may reject the request
with an implementation-defined error, stay silent, or even process an era-ambiguous
method under legacy semantics." `createLegacyHandler` (in `src/fixtures/shared.ts`)
models this as HTTP 400 with a bog-standard JSON-RPC `-32601 Method not found` error —
deliberately *not* one of the three recognized modern error names
(`UnsupportedProtocolVersionError` / `MissingRequiredClientCapabilityError` /
`HeaderMismatchError`). A correct detector inspecting the error body must recognize this
as "not a modern error" and fall back to `initialize`, exactly per the spec's own
detection algorithm — this is the concrete mechanism behind the P0 requirement, not just
a description of it.

## Boundary

This package ships to the public repo. No real maintainer endpoint, domain, package
name, or tool description appears anywhere in it — every host is `example.com` or a
subdomain of it (`notes-mcp.example.com`, `mirror.example.com`), matching
`scripts/scan-secrets.mjs`'s allowlist without needing an exemption.

This package is `devDependency`-natured from the perspective of whoever builds a
detector against it (a real detector consumes it only to run its own test suite,
never at runtime) — but it lives under `packages/` like every other piece of the
product's public surface, with its own `dependencies` on `@mcpcheckup/canonicalizer`
and `@mcpcheckup/checks` (both workspace packages, zero third-party runtime
dependencies transitively) so it can verify its own fixtures against real production
logic instead of duplicating it.
