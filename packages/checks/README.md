# @mcpcheckup/checks

Two things live in this package:

1. **`checks.json`** — the single source of truth for what the `remote-baseline-v0.1`
   check suite is: 15 checks, their failure semantics, their protocol-revision matrix,
   and the global probe budget. Nothing else in this repo redefines any of that.
2. **The remote prober** (`runProbe`) — the thing that actually talks to a live MCP
   server over Streamable HTTP and turns what it observes into exactly one `Assertion`
   per registered check. This is the product's core: everything upstream of this
   package (canonicalizer, attestation-schema, ssrf-guard, fixtures) exists to make
   this part correct and honest.

Also here: `runHygieneCheck` (the `tool_description_hygiene` predicate — pre-existing,
unrelated to the prober's own control flow, reused by it rather than reimplemented).

## TDD against a pre-written spec

`packages/fixtures` was built *before* this prober, specifically so it could define
"what counts as correct" independently of whatever this package's implementation
happened to do. `src/probe.test.ts` runs `runProbe` against every one of
`@mcpcheckup/fixtures`' 16 fixtures (3 positive, 13 negative) and compares
`execution_status`/`assertion_status` per `check_id` against what each fixture
declares. That test is this package's actual acceptance criteria — everything else
here is either infrastructure it depends on or additional properties (closed count,
determinism, the UNVERIFIED-needs-a-reason invariant) that the corpus alone doesn't
fully pin down.

## Execution order and dependencies between checks

`runProbe` doesn't run 15 independent probes — most of what it observes comes from a
handful of wire calls, and several checks read from the same call:

1. **Handshake** (`server/discover`, falling back to `initialize` per the 2026-07-28
   spec's own backward-compatibility algorithm — see `protocol.ts`'s
   `performHandshake`) → produces `discovery_handshake` and `protocol_revision`.
   These are two independent judgments over the *same* response: `discovery_handshake`
   asks "did the mechanics go right," `protocol_revision` asks "is the declared
   version string one we recognize" (checked against `checks.json`'s own
   `revision_matrix`, never a hardcoded copy of it). A stale-but-well-formed version
   string can make `protocol_revision` FAILED while `discovery_handshake` stays
   VERIFIED — see `stale-protocol-version` in the fixture corpus.
2. Once the handshake succeeds: `transport_type` and `latency_profile` are recorded
   (both trivially VERIFIED at this point in the current remote-only implementation —
   see "What's out of scope" below).
3. **`tools/list`** → `tools_list` (a determinate structural fact: is `result.tools` an
   array). If it is, the raw tool list feeds three more checks in parallel:
   `toolset_fingerprint` / `schema_fingerprint` (via `@mcpcheckup/canonicalizer`'s
   `projectToolset`/`projectSchemas`/`digest`, wrapped so a thrown
   `CanonicalizationError` becomes a FAILED verdict rather than an unhandled
   exception — this is exactly how `cross-layer-hash-mismatch` proves the two
   fingerprints are independently judged) and `tool_description_hygiene` (via this
   same package's own `runHygieneCheck` — no duplicate regex table). If `tools/list`
   is structurally illegal, all three of those — plus the two baseline-comparison
   checks below — become `SKIPPED`/`UNVERIFIED`, because there's no usable tool data
   to compute anything from.
4. **`toolset_unchanged_vs_approved`** / **`schema_unchanged_vs_approved`** compare the
   fingerprints above against `input.approvedBaseline`. No baseline → both are always
   `SKIPPED`/`UNVERIFIED` with `checks.json`'s own `no_baseline_reason_zh` (read from
   the registry, not retyped). A baseline that doesn't match → `FAILED`, and a
   `DriftEvent` is recorded. This is the *only* path that can produce `FAILED` here —
   see "Baselines and drift" below.
5. **`tools/call`** with the name we reserve for a tool that should not exist
   (`__mcpcheckup_probe_nonexistent_tool__`) — the protocol-level, non-destructive way
   to trigger an error scenario, matching exactly what the fixture corpus models. When
   the call is sent, its response feeds both `error_taxonomy` (is the error shape
   protocol-conformant) and `auth_metadata` (was there a `WWW-Authenticate` challenge,
   and if so, does its declared `scope` actually match its own linked resource-metadata
   document's `scopes_supported`). A bare 401/403 counts as a legitimate auth rejection
   for `error_taxonomy`'s purposes (not a taxonomy violation) but is exactly what
   `auth_metadata` reads. The name is reserved for a tool that should not exist, but a
   server can define it, so outside a credential gate the call is withheld when the
   first `tools/list` page names it, when the list carries a `nextCursor`, or when
   `tools/list` failed; both checks are then `SKIPPED`/`UNVERIFIED`. Under a credential
   gate (a 401 challenge on the handshake or on `tools/list`, see "Why a
   credential-gated handshake or tools/list is UNVERIFIED" below) the call is not sent,
   whatever the list says: `error_taxonomy` is then `SKIPPED`/`UNVERIFIED` with
   `credential_required`, and `auth_metadata` reads the 401 challenge on the response
   that required credentials. If the run's budget runs out before either check is
   recorded, that check is `SKIPPED`/`UNVERIFIED` with the budget's own key instead
   (see "Why a budget-exhausted (or otherwise aborted) run makes `reachability`
   UNVERIFIED" below).
6. **`redirect_policy`** is judged last, from whether *any* wire call in the whole run
   crossed hosts on a redirect (tracked once, centrally, in `wire.ts`'s
   `ProbeContext` — not recomputed per call site). Every wire call this package makes
   is `POST` (see `protocol.ts`), and `sendRequest` **never follows a redirect for a
   non-GET request**: a 3xx becomes that call's terminal response instead of a second
   hop, though `redirectCrossHostObserved` still gets set when the `Location` crosses
   hosts, so the observation isn't silently lost. This is the same rule
   `@mcpcheckup/ssrf-guard`'s `guardedFetch` independently enforces one layer below
   (see that package's README, "Non-GET does not follow redirects") — re-derived here
   rather than centralized into one shared signal between the two packages, so
   neither layer's protection depends on the other layer remembering it (see
   `wire.ts`'s own module doc for the full reasoning). A redirect mid-handshake (e.g.
   on `server/discover`) therefore does not silently resolve on some other host — it
   shows up as `discovery_handshake`/`protocol_revision` `FAILED` plus
   `redirect_policy: OBSERVED_RISK`, not a quietly-successful run against a different
   endpoint. See `redirect-cross-host` in the fixture corpus.
7. **`reachability`** is judged the moment `performHandshake` returns — i.e. as soon as
   the endpoint has answered with a complete HTTP response, whatever its status
   (`200`, `401`, `403`, any `4xx`, any `5xx`). That is the whole question this check
   asks (`checks.json`'s predicate: "endpoint responds within budget", with no status
   condition), and it is settled before anything later in the run can go wrong. It used
   to be judged *last of all*, meaning "the whole probe completed within budget" — see
   the cascading-failure section below for why that was changed in T6.9-F.
8. **`tls_certificate`** is set first and unconditionally, before anything else runs —
   see "What's out of scope."

## The global probe budget, and why it's enforced in one place

`checks.json`'s `budget` field (`max_requests: 8`, `max_duration_ms: 10000`,
`max_body_bytes: 2097152`, `max_redirects: 3`, and `unclaimed_max_requests: 8` — the
same request budget for both tiers since T6.9-F; the halving that used to apply to
unclaimed targets could not finish a legacy-protocol round and was withdrawn)
documents the *contract* this suite claims to run under. The actual runtime
enforcement value is `ProbeInput.budget`, typed as `@mcpcheckup/ssrf-guard`'s
`ProbeBudget` — the same shape `guardedFetch` itself takes. That's deliberate: in
production, whoever constructs a `ProbeInput` needs to hand the *same* budget numbers
to both `guardedFetch` (which enforces them at the network layer, per hop) and to this
package (which enforces them again at the request-count/body-size/duration level,
since a plain injected `fetchImpl` returning a bare `Response` gives this package no
other way to know a limit was hit). This package does not itself read `checks.json`'s
`budget` field or cross-check it against `input.budget` — keeping the two numbers in
sync is the caller's responsibility. Both currently use the same numbers by
construction (`checks.json`'s budget and `@mcpcheckup/ssrf-guard`'s
`DEFAULT_PROBE_BUDGET` are identical), but nothing in this package enforces that they
stay that way.

All budget accounting — request count, wall-clock duration, redirect hop count,
response body size — happens in exactly one place: `wire.ts`'s `sendRequest`, called by
every wire operation in this package. No individual check re-implements any of it.
This is what "the budget is global, not per-check" (8 requests total for the *whole
run*, not 8 per check) actually means in the code, not just in the doc comment.

Each request is given only the time left in the run's duration budget. If the probe's
own deadline timer fires while a request, or the reading of its response, is still in
progress, that request is abandoned: nothing it returns or reports after that moment is
used. Once no time is left, the probe starts no further request of its own, and does not
read the body of a response it has already received but not yet read. When a run stops
this way, the checks that had not completed are recorded as `SKIPPED`/`UNVERIFIED` with
`probe_budget_exhausted_duration` — or, for `reachability` when time ran out before the
handshake had completed, `ERROR`/`UNVERIFIED` with the same reason.

## Why a budget-exhausted (or otherwise aborted) run makes `reachability` UNVERIFIED, never FAILED — and why checks that already completed keep their result

A single `try`/`catch` wraps the entire wire sequence — handshake through the final
`tools/call` probe. Any exception — `wire.ts`'s own `ProbeAborted` (budget exhausted),
an error `@mcpcheckup/ssrf-guard` raised on the way to or from the target, or any other
error `fetchImpl` throws — produces:
every check that never got a chance to run (except `tls_certificate`, always out of
scope regardless) becomes `SKIPPED`/`UNVERIFIED`, and `reachability` becomes
`ERROR`/`UNVERIFIED` **if and only if it had not already been settled** — i.e. only
when the abort landed at or before the handshake. **Checks that already `COMPLETED`
before the abort keep whatever result they earned**, and since T6.9-F that expressly
includes `reachability` itself. `response-exceeds-budget` in the fixture corpus is
explicit about this: the handshake in that fixture succeeds fine and only the
subsequent `tools/list` call blows the body-size budget, so `reachability`,
`discovery_handshake`, `protocol_revision`, `transport_type`, and `latency_profile`
stay `VERIFIED` in the result — `tools_list` itself (which never finished) and
everything that depends on its data cascade to `SKIPPED`/`UNVERIFIED` as before.

**T6.9-F, why `reachability` moved.** It used to be the last statement of the `try`
block, which made the most basic fact in the whole run hostage to every step that
followed: a target whose handshake and `tools/list` were both `VERIFIED` could still be
published as `reachability: UNVERIFIED` — and therefore as 0% uptime — purely because
the run later ran out of request budget. Eight of twelve unclaimed targets were in that
state in production (2026-09-09). The assertion is now made at the moment it becomes
true, and the `catch` guards on `assertionsByCheckId` so it can never be revised
afterwards.

**What the cascaded checks are told.** For `wire.ts`'s own `ProbeAborted` the cascade
reason is the abort's real key and its numeric details
(`probe_budget_exhausted_requests: { maxRequests: 8 }`, `probe_rate_limited`, …), not a
generic one, so a reader can see *why* a check did not run; the approved copy for those
keys already ends in "— later checks did not run". The key and its params must travel
together: `reason-messages.ts`'s renderers call `requireParam` and **throw** on a
missing one.

Since suite 0.9.0 the same holds for an error `@mcpcheckup/ssrf-guard` raised. The
`catch` reads its class, its `code` and its `hop` — never its message — and gives
`reachability` (when it was not yet settled) and every never-ran check one of these
reasons. `hop` is how many redirects the guard followed before the request that failed:
0 is the URL it was asked for.

| ssrf-guard error | reachability not yet settled | reachability already settled |
|---|---|---|
| `UpstreamFetchFailed` — the request, or reading its response body, failed | `reachability_unanswered` `{ kind: "other" }` | `probe_cascade_incomplete` |
| `BudgetExceeded` `MAX_DURATION` — no complete response within the time budget | hop 0: `reachability_unanswered` `{ kind: "timeout" }`; hop > 0: `{ kind: "other" }` | `probe_budget_exhausted_duration`, with the run's own budget number |
| `BudgetExceeded` `MAX_REQUESTS` / `MAX_REDIRECTS` / `MAX_BODY_BYTES` | `probe_budget_exhausted_requests` / `_redirects` / `_body`, with the run's own budget number | the same |
| `RateLimited` | `probe_rate_limited` | the same |
| `SsrfBlocked` `RESOLUTION_FAILED` — the host name did not resolve | hop 0: `reachability_dns_failed`; hop > 0: `reachability_unanswered` `{ kind: "other" }` | `probe_cascade_incomplete` |
| `SsrfBlocked` `RESOLVER_UNAVAILABLE` — our own DNS resolver did not answer | `probe_resolver_unavailable` | the same |
| any other `SsrfBlocked` — our own policy declined the address or the request | `probe_blocked_by_policy` `{ code }` | the same |

Two rules decide the two columns, so that no reason says something false about the
endpoint. First, the reasons whose text names "the endpoint" — `reachability_dns_failed`
and `reachability_unanswered` `{ kind: "timeout" }` — are used only at hop 0, the
request to the endpoint's own URL; after a redirect the failing host may be another one,
so the reason is `reachability_unanswered` `{ kind: "other" }`. Reasons that do not name
the endpoint do not depend on hop. Second, once `reachability` is settled the endpoint
has answered, so a never-ran check is not told that it did not: a DNS failure or a
failed request later in the run (for example the authorization metadata lookup, which
can go to another host) gives the generic `probe_cascade_incomplete`, and running out of
time gives `probe_budget_exhausted_duration`, the same reason `wire.ts`'s own time budget
gives.

The params are only `kind`, `code` or a budget number: the error's message and cause
reach no assertion, no stored row and no signed payload. Any other thrown error — for
example one of the prober's own wrapper errors — keeps the generic
`probe_cascade_incomplete` on the cascade, and only `reachability` carries
`probe_aborted` with the error's message: that message is an unbounded string, and
copying it onto all thirteen never-ran checks would inflate a canonicalized, signed
payload without adding information.

The reasoning: "we verified the protocol handshake, then ran out of budget" is a
coherent, honest statement — the four-state model exists specifically to let a report
say exactly that. Retroactively discarding an observation that was, in fact, correctly
obtained would itself be a form of the dishonesty `UNVERIFIED`'s "no reason left
unstated" rule exists to prevent — the mirror image of claiming confidence that wasn't
earned. What still must never happen is guessing at checks that *never ran*: those
stay `SKIPPED`/`UNVERIFIED`, not `VERIFIED` and not `FAILED`, because nothing was
actually observed about them in this run.

**A related, deliberate design choice:** `checks.json` declares `reachability`'s
`failure_status` as `null` — it has exactly two reachable states, `VERIFIED` and
`UNVERIFIED`, never `FAILED`. Since suite 0.9.0 this package does tell some causes
apart: it imports `@mcpcheckup/ssrf-guard`'s error classes (`UpstreamFetchFailed`,
`BudgetExceeded`, `RateLimited`, `SsrfBlocked`) and reads their class, `code` and `hop` — the
only runtime values it takes from that package; `no-direct-fetch.test.ts` still enforces
that it never calls the network itself. It does so only to say *why* a check could not
conclude, never to conclude `FAILED`: a request that failed, or got no complete answer
within its budget, still does not show that the target is down — it could be our
network. Declaring a `FAILED` state that requires a signal this
package cannot reliably produce would be worse than not declaring it — guessing `FAILED`
without a trustworthy basis risks exactly the false-failure outcome CLAUDE.md calls out
as equally damaging as a false pass. If a future executor gains a reliable way to tell
"reached, but broken" apart from "never reached," `failure_status` can be reintroduced
alongside a fixture that actually forces the distinction — no fixture in the current
corpus does.

## Why a credential-gated handshake or tools/list is UNVERIFIED, never FAILED (Lead finding N10, round 3)

A server can legitimately put its handshake, or just `tools/list`, behind
authentication — an internal server whose tool names/descriptions/schemas
shouldn't be visible to an anonymous caller is a deliberate access-control
choice, not a protocol defect. When the response that actually settles a
handshake attempt (or a standalone `tools/list` call) answers `401` with a
structurally valid `WWW-Authenticate` challenge — see `auth.ts`'s
`classifyCredentialChallenge` for the exact grammar this checks against, the
one place that predicate is computed — `probe.ts`'s cascade records
`discovery_handshake`/`protocol_revision`/`tools_list` as `UNVERIFIED` with
reason `credential_required`, not `FAILED`. Under either gate,
`error_taxonomy` is `UNVERIFIED` with `credential_required` too: since suite
0.8.0 the probe does not send its `tools/call` behind a gate, and
`auth_metadata` reads the gate's own `401` challenge instead (step 5 above).
The reasoning is the same one this section's title borrows from
`reachability`'s own UNVERIFIED-not-FAILED discipline above: "we couldn't
verify what's behind the gate" is a true, narrower claim than "it's broken,"
and asserting the broader, false claim just because the narrower one is
inconvenient to report is exactly the failure mode CLAUDE.md's
`不确定时的出口是 UNVERIFIED` rule exists to rule out.

This exemption is narrow on purpose and does **not** apply to every 4xx a
handshake attempt can produce:

- A `403`, an empty `WWW-Authenticate` value, or a header whose **first
  challenge is not complete and well-formed** never qualifies — those stay on
  the pre-existing `FAILED`/legacy-fallback paths (see the
  `credential-challenge-*-not-exempted` and `forbidden-403-not-credential-gated`
  fixtures). "Complete" is the operative word: it is not enough for the value
  to *begin* with a legal auth-scheme token. `classifyCredentialChallenge`
  accepts exactly three shapes for that first challenge — the scheme alone,
  the scheme plus a complete `token68` (`Bearer abc def` does not qualify:
  `def` is neither part of the `token68` nor the start of a new challenge),
  or the scheme plus one or more individually well-formed `auth-param`s — and
  rejects everything else, `Bearer ???` included (see
  the `credential-challenge-malformed-remainder-not-exempted` fixture, added
  for Codex PR#19's P2 in round 6). Validation deliberately stops at the
  point where a *second* challenge begins, because the `#challenge` list's
  comma is ambiguous. Be precise about what that leaves the predicate
  asserting: **the first challenge parses cleanly, and so does any auth-param
  continuation after it** — which is narrower than "the header carries at
  least one valid challenge", because a malformed element after a comma
  rejects the whole header rather than falling back to the last complete
  challenge. `classifyCredentialChallenge`'s own comment works that through;
  it is the authority, this is a pointer to it. The narrowness is toward
  `FAILED`, never toward a false exemption. Within that
  first challenge the grammar is the RFC's, with nothing added and nothing
  taken away: `token68`'s trailing `=` run is accepted at any length (the RFC
  names base32 and base16 alongside base64, and their padding lengths differ),
  so `Bearer realm=` — which is simultaneously a valid `token68` and a
  truncated `auth-param`, the same string under both readings — is accepted as
  the structurally valid challenge the RFC says it is. Rejecting it would make
  this predicate stricter than the RFC while the copy promises RFC structural
  validity, i.e. copy wider than code. The grammar and that tie-break are
  written out on `classifyCredentialChallenge` and `consumeToken68` in
  `auth.ts` — the one place this predicate lives.
- **On the `server/discover` response only** — the probe's first request — a
  body carrying one of the recognized MCP JSON-RPC error codes
  (`RECOGNIZED_MODERN_ERROR_CODES` in `protocol.ts`) is not exempted, even at
  `401` with an otherwise-valid challenge header: that shape means a modern
  server is actively rejecting this specific request rather than asking for
  credentials, and it stays `FAILED` (see the
  `recognized-modern-error-code-401-not-exempted` fixture). This body test
  lives in `performHandshake`'s 4xx branch and nowhere else, because the
  question it answers — "is this a modern server rejecting my probe, or a
  legacy server I should retry against?" — only arises at `server/discover`.
  `performLegacyHandshake` and `performToolsList` never inspect the body for
  error codes at all; on those responses the classification is
  status-code-plus-headers only, so a `401` with a valid challenge there is
  credential-gated whatever error code the body carries. Widening the body
  test to those layers would be a change to the approved spec
  (the handshake-layer credential-gate rule asks only that the existing modern
  branch be left unchanged), not a bug fix, and is not made here.
- The tools-list-layer exemption additionally requires the handshake itself
  to have completed successfully (`handshake.handshakeOk`) — a `tools/list`
  challenged with `401` when the handshake itself already failed for an
  unrelated reason stays on the ordinary `FAILED` path, not this one.
- At the tools-list layer the challenge is classified from **status and headers
  before the body is read at all**, and a challenge present makes
  `performToolsList`'s `ok` false regardless of what the body contains. So a
  `tools/list` that answers `401` with a valid challenge but whose body
  happens to carry a well-formed `result.tools` array — a misconfigured auth
  proxy stamping `401` onto a successful upstream response produces exactly
  that — yields `tools: null`, and **no toolset or schema fingerprint is
  computed from it, on either the `handshakeOk` or the `!handshakeOk` path**
  (see the `credential-gated-tools-list-with-tools-body` fixture and its
  fingerprint-absence test). Governing principle, established round 9: a `401`
  is the server declaring the response unauthorized, and signed evidence must
  never be derived from a response the server itself disowned. This is also
  why the criterion is status-plus-headers in the first place — it is what
  this rule states and what the published `tools_list.cannot_*` copy says,
  neither of which mentions the body.

## What "checks.json is the single source of truth" means here, concretely

- The **set** of checks `runProbe` produces assertions for comes from
  `registry.checks`, iterated at the end of the run — never a hardcoded array. Any
  check this implementation forgot to compute (a future registry addition this code
  hasn't caught up to) becomes an explicit `ERROR`/`UNVERIFIED` assertion instead of
  silently vanishing from the output.
- `docs_version` on every assertion is read from the matching registry entry, never
  retyped. It moves when *that one check* changes: a change to what the check can
  conclude, or to its `explain`/`predicate` text, bumps that check's `docs_version` and
  no other's, while a change to any registry field bumps `registry_version` —
  `registry_version` versions the registry as a whole and never stands in for a
  per-check document version.
- `protocol_revision`'s acceptable version strings come from `revision_matrix` on the
  registry entry.
- `toolset_unchanged_vs_approved`/`schema_unchanged_vs_approved`'s no-baseline reason
  text comes from `no_baseline_reason_zh` on the registry entry.
- What this package *doesn't* avoid: the check-computation **logic** itself
  necessarily names specific `check_id` strings as literals (e.g. `A('tools_list', ...)`
  inside `probe.ts`) — there's no way to write "the logic that identifies stale
  protocol versions" without the code knowing it's computing `protocol_revision`. The
  rule this project actually cares about — don't maintain a second, driftable copy of
  a check's *definition* (its failure semantics, its docs text, its revision matrix)
  — is what's avoided; naming which check a block of logic is for is not the same
  thing as duplicating that check's definition.

## Baselines and drift

Per the "有无基线决定语义" rule: no `approvedBaseline` (the monitoring/unclaimed path)
→ the two `*_unchanged_vs_approved` checks are always `SKIPPED`/`UNVERIFIED`, never
`FAILED`, regardless of whether the fingerprint changed relative to some *other* run.
An `approvedBaseline` that doesn't match the current fingerprint is the only path that
can produce `FAILED`, and it also appends a `DriftEvent` to `ProbeResult.driftEvents`.

**What this package does not do:** detect drift on the monitoring path (no baseline) by
comparing this run's fingerprint against a *previous* run's. `ProbeInput` carries no
prior-run reference — only `approvedBaseline` — so a single `runProbe` call has no
memory of history to diff against. `toolsetDriftRun1`/`toolsetDriftRun2` in the fixture
corpus prove genuine drift is *detectable* (by comparing two `ProbeResult.toolSnapshot`s
— or, as that fixture pair's own test does, two independently-computed fingerprints —
from outside this package), not that this package detects it internally across calls.
Building that comparison — storing a target's last observed snapshot and diffing the
next run against it — is a caller/storage concern, consistent with this repo's existing
pattern of keeping deployment-specific state (thresholds, rate-limit numbers, storage)
out of these packages. `toolSnapshot` is returned on every successful run specifically
so that comparison is possible externally.

## `FetchLike`, `GuardSignals`, and how a production caller is expected to wire in `guardedFetch`

`ProbeInput.fetchImpl` is almost identical to the fetch API itself —
`(input, init, onGuardSignal) => Promise<Response>` — close enough to the shape
`@mcpcheckup/fixtures`' handlers have (`(input, init?) => Promise<Response>`) that a
fixture's `createHandler()` drops in for tests with zero adapter code: TypeScript
allows a function with fewer declared parameters to satisfy a type expecting more (the
extra argument is simply never read), and no fixture needs to call `onGuardSignal` —
see that package's own README for the layering rationale: this package's probing logic
and `ssrf-guard`'s SSRF policy are verified completely independently of each other.

In production, `guardedFetch`'s actual signature is richer than plain `fetch` — it
takes a `ProbeBudget`, a `RateLimitDecision`, and a required `parseResponse` callback
(by design: a caller can't casually get a raw response body/headers out of it — see
`ssrf-guard`'s README on "blind SSRF"). Reconciling that with this package's `FetchLike`
seam is the *production caller's* job, not this package's: build a small adapter that
calls `guardedFetch`, uses `parseResponse` to read the `SafeResponseHandle` back into a
plain `Response`, and returns that. This package never imports or calls `guardedFetch`
itself (`src/no-direct-fetch.test.ts` enforces the "no direct `fetch(` call in this
package's own source" half of that boundary).

`guardedFetch`'s `dnsAnswerChangedDuringProbe` (real signal, not preventable — see
`ssrf-guard`'s README on why the TOCTOU window can only be detected after the fact, not
closed) has no natural home in a plain `Response` — and, critically, must **never** be
squeezed into one anyway: a `Response` is entirely under the target's control (status,
headers, body), so anything a security signal derives from it is something a hostile
target can forge or suppress at will. An earlier version of this package relayed the
signal via a `x-mcpcheckup-dns-answer-changed` response header, which meant *any*
target could set that header on every response it sent and permanently exempt itself
from `disqualifiedFromPublication` — a real vulnerability, since disqualification is
what keeps a target's own DNS-rebinding attempt out of the published, unclaimed-target
corpus. The fix: `FetchLike`'s third parameter, `onGuardSignal`, is a callback the
production adapter calls directly with a `GuardSignals` object
(`{ dnsAnswerChanged: true }`) taken from the audit record `guardedFetch` hands to its
`onAudit` callback on both the success and the throw path — a
channel the target has no way to reach, since it never touches the `Response` object at
all. `wire.ts`'s `sendRequest` passes this callback to every `fetchImpl` call and folds
any `dnsAnswerChanged: true` into `ProbeContext.dnsAnswerChangedObserved`; `probe.ts`
reads that field once, at the very end of the run (from `finalize()`, not inline in the
success path, so a report is disqualified even if a *later* request in the same run
throws before the run would otherwise have reached that check), to set both
`ProbeResult.disqualifiedFromPublication` and `ProbeResult.dnsAnswerChangedObserved`.
`wire.test.ts` and `probe-dns-rebind.test.ts` each include a regression test proving a
target-forged copy of the old header name has no effect.

A DNS-answer change is deliberately **not** folded into any per-`check_id` assertion (it
no longer feeds `redirect_policy` — a changed DNS answer is not a redirect, and showing
readers the wrong `check_id` for what was actually observed would be worse than showing
none) — and never will be: many healthy production endpoints legitimately return
different DNS answers across requests (round-robin load balancing, CDN edge selection,
active failover), so judging this as a per-check verdict would misjudge routine DNS
behavior as a target defect, risking this project's own >3% false-positive kill
criteria. It's a condition of *this run*, not a claim about the target — the same
category `probe_region` is already in. `ProbeResult.dnsAnswerChangedObserved` (`boolean`
for a `remote` target that reached the try block, regardless of whether the run later
aborted; `null` for `stdio`, which does no DNS resolution to observe) is this package's
half of that: a caller assembling an `AttestationPayload` reads it to populate
`@mcpcheckup/attestation-schema`'s `probe_dns_answer_changed` field directly — see that
package's README for the full reasoning, including why it's kept separate from
`disqualifiedFromPublication` rather than making a caller infer it from that field's
presence.

Per `ssrf-guard`'s own design, none of this ever blocks the connection that was already
made — the guard can only observe the DNS mismatch after the fact, not prevent it.

## What's out of scope in this implementation

- **`tls_certificate`** (`checks.json`'s one check with `executor: "container"`) is
  always `SKIPPED`/`UNVERIFIED` with a fixed reason, unconditionally, regardless of how
  the rest of the run goes — it needs a TLS-terminating container executor this
  fetch-based prober isn't. No fixture declares an expectation for it (see
  `@mcpcheckup/fixtures`' README for the same note from the other side).
- **`stdio` targets.** `ProbeTarget` includes a `stdio` variant (matching
  `AttestationPayload`'s own `StdioTarget`/`RemoteTarget` discriminated union), but this
  implementation only actually probes `remote` targets. A `stdio` target produces every
  check as `SKIPPED`/`UNVERIFIED` (never a crash, never a silently-missing assertion)
  with a reason naming this as a scope boundary, and never calls `fetchImpl` at all. All
  16 corpus fixtures are remote servers, so this path is exercised by its own dedicated
  test (`probe-scope.test.ts`), not by the shared corpus test.
- **`transport_type`'s `OBSERVED_RISK` path** (declared transport doesn't match observed
  transport) is currently a pass-through: given remote-only scope, if the probe reaches
  this point at all, transport is trivially "remote, as declared." No fixture in the
  current corpus models a transport mismatch.
- **`auth_metadata` does not follow `jwks_uri`** even when a resource-metadata document
  declares one. No predicate this package currently implements depends on JWKS
  contents — a multi-key JWKS is a normal key-rotation transition window, not evidence
  of anything (`jwks-multiple-keys-not-flagged` in the fixture corpus exists
  specifically to prove this package doesn't misjudge that) — so fetching it would only
  spend probe request budget without changing any verdict.
- **The `RECOGNIZED_MODERN_ERROR_CODES` branch of the handshake algorithm** — a modern
  server's `server/discover` returning 400 with one of the three spec-defined modern
  error codes (`HeaderMismatch`/`MissingRequiredClientCapability`/
  `UnsupportedProtocolVersion`) — is implemented per the 2026-07-28 spec's own text, but
  no fixture in the current corpus exercises it. It's untested against a real handler,
  only against the spec's written description of the behavior.
- **`error_taxonomy`'s "protocol-level safe error scenario"** is implemented
  specifically as "call `tools/call` with the name we reserve for a tool that should not exist," matching what
  the fixture corpus itself models (and what `@mcpcheckup/fixtures`' shared handler
  engine implements on the server side) — not, e.g., an unrecognized top-level JSON-RPC
  method name. Both are defensible readings of "触发一个安全的错误场景"; this package
  follows the corpus's own choice since the corpus is this package's spec.

## Security boundaries this package holds to

- Never calls a business tool — the only `tools/call` this package ever makes uses the
  name we reserve for a tool that should not exist
  (`__mcpcheckup_probe_nonexistent_tool__`), withheld whenever the server's tool list
  names it or could not be read in full, and whenever a credential gate stands in front
  of the handshake or the tool list (step 5 above); that call is exactly what
  `checks.json`'s `forbidden` list requires (a protocol-level error trigger, not a real
  operation).
- Never writes, never sends credentials, never does anything destructive.
- Never puts a target's raw response body or headers into an `Assertion`'s `reason` —
  every `reason` string in this package is authored by this package's own code (status
  codes and structural facts are sometimes interpolated, e.g. "returned HTTP 500," but
  never third-party free text).

## Zero non-workspace runtime dependencies

`dependencies`: `@mcpcheckup/canonicalizer`, `@mcpcheckup/attestation-schema`,
`@mcpcheckup/ssrf-guard` — all workspace packages, none with third-party runtime
dependencies themselves. `devDependencies` additionally includes
`@mcpcheckup/fixtures` (test-only — production code in `src/` never imports it; see
`package.json`'s `dependencies`/`devDependencies` split).

## Suite identity: what `suite_version` and `suite_digest` identify

An attestation payload's `suite_version` is this package's `version` field, read
straight from `package.json` by the prober application that produces the
payload, rather than retyped.
`suite_digest` is defined in `suite_digest`'s own description in
`packages/attestation-schema/schema/attestation.schema.json`, which is the single
authoritative statement of the recipe. It is deliberately not paraphrased here:
the obvious paraphrase — "the git tree hash of this package" — names a
*different* value than the ruled recipe does, and a reader who computes the
paraphrase will not reproduce any attestation.

### Recomputing `suite_digest` yourself

Take `suite_commit` out of the payload you are checking, check this repository
out, and run:

<!-- suite-digest-verify-command:begin -->
```sh
git ls-tree -r -z --full-tree <commit> -- packages/checks | openssl dgst -sha512 -binary | openssl base64 -A
```
<!-- suite-digest-verify-command:end -->

Prefix the result with `sha512-` and compare it against the payload's
`suite_digest`. `scripts/suite-identity.mjs` computes the same value using Node's
own crypto and no OpenSSL, and `scripts/suite-identity.test.mjs` runs both for a
real commit and fails if they disagree — so the command printed above cannot
drift away from what the deploy path actually injects.

Two properties, stated so that nobody reads more into a changed digest than is
there:

- **This file is inside the digest's scope, and the scope is exactly
  `packages/checks` — nothing more.** A documentation-only edit anywhere under
  `packages/checks` therefore moves `suite_digest` while leaving `suite_version`
  and `registry_version` untouched. That is coherent rather than a defect: the
  digest answers "which bytes of *this package* produced these assertions", and the
  two version fields answer "which judgment semantics were in effect". **A changed
  `suite_digest` is not evidence that any check can now conclude something
  different.**
- **An unchanged `suite_digest` is likewise not evidence that the executing code is
  unchanged.** A run also executes `@mcpcheckup/canonicalizer`,
  `@mcpcheckup/ssrf-guard` and the prober application that calls them, and none
  of those is inside the scope — a change to any of them leaves this value byte-identical.
  `scripts/suite-identity.test.mjs` asserts precisely that, on purpose, so the
  limit is pinned rather than assumed.
  When `suite_commit` is a commit in github.com/mcpcheckup/checks, it names the state of every package in that repository, the canonicalizer and the SSRF guard included; the prober application is not in that repository, and `suite_commit` does not identify it;
  `canonicalization` and `toolset_projection_version` separately name the
  canonicalizer's own contract.
- **The digest is taken over committed objects, not over your checkout.**
  `git ls-tree` never reads the working tree, so the value does not depend on your
  `core.autocrlf`, your platform, your Node version, or any packaging step.

### What the historical values are, and are not

- **`suite_version` `0.1.0` does not identify a single code state.** Attestations
  carrying it were produced by more than one code state, and cannot be distinguished
  by suite identity alone. There is no historical backfill: signed attestations are
  immutable.
- **No `suite_digest` signed before payload version 0.3 is reproducible.** Those
  values were taken over a `pnpm pack` tarball, and depended on the packing
  machine's line endings, its `pnpm` major and its Node/zlib major; the script that
  produced them has been deleted. Such a payload has no `suite_commit` field at
  all, which is how you can tell one apart: it records provenance, not an identity
  anyone can re-verify. Those values are not being recomputed or backfilled, for
  the same reason as above — signed attestations are immutable.
