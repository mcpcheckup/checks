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
2. Once the handshake requests have returned a complete HTTP response: `transport_type`
   is recorded (trivially VERIFIED at this point in the current remote-only
   implementation — see "What's out of scope" below). `latency_profile` is written
   once, when the run ends, from the requests it already sent (suite 0.16.0, see
   "`FetchLike`, `GuardSignals`…" below); it sends no request of its own. Suites up
   to 0.11.0 recorded it `VERIFIED` at this point without measuring anything, and
   suites 0.12.0 to 0.15.0 recorded it `SKIPPED`/`UNVERIFIED` with
   `latency_not_recorded` on every branch.
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
   Since suite 0.15.0 the list is read to its end: while a page carries a `nextCursor`,
   the next page is requested with that cursor, up to `checks.json`'s
   `budget.max_tools_list_pages` (10) pages or `MAX_TOOLS_LISTED` (5,000) tools in
   all, whichever comes first. The first page is sent and judged exactly as before.
   Pages 2 and later are not counted against `max_requests`; the run's time budget
   and the body limit hold for each of them, on the request and on the response. The
   list is *incomplete* when a further page exists but is not read (the page or tool
   limit is reached, the cursor is not a string, or the page runs out of time, its
   request or its response goes over the body limit, or it is not a readable tools
   result) or when more than 5,000 tools came in (only the first 5,000 are kept: a
   page is cut at the allowance left). None of these ends the run: the time and body
   limits end only the paging, whichever layer enforces them (wire.ts's
   `ProbeAborted`, or, first in production, `@mcpcheckup/ssrf-guard`'s
   `BudgetExceeded`, matched by its code). On an incomplete list `tools_list` is still judged on the
   first page; `toolset_fingerprint`, `schema_fingerprint` and both baseline checks
   are `SKIPPED`/`UNVERIFIED` with `tools_list_incomplete`, and no `toolSnapshot` is
   returned; `tool_description_hygiene` still judges the tools that came in, but a
   clean result is `COMPLETED`/`UNVERIFIED` with `tools_list_incomplete` instead of
   `VERIFIED`, because the tools not read were not looked at; and the `tools/call` of
   step 5 is not sent, since the reserved name could be on a page we did not read
   (`error_taxonomy` and `auth_metadata` are `SKIPPED`/`UNVERIFIED` with
   `probe_tool_name_unverifiable`, or `probe_tool_name_collision` when a page we did
   read names it). A response
   on a later page that ends the run for any other reason (the server asking us to
   back off, a guard refusal, a failed connection) ends it as on any other request.
   Behind a handshake-layer credential gate the list is not used, so only its first
   page is read.
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
   document's `scopes_supported`). A bare 401/403 is not a taxonomy violation, but no
   protocol error came back either, so there is nothing for `error_taxonomy` to
   classify: it is `SKIPPED`/`UNVERIFIED` with `error_shape_not_observed` (suites up to
   0.11.0 recorded `COMPLETED`/`VERIFIED`); it is exactly what `auth_metadata` reads. An
   answer that is not a 401 carries no challenge to check, so `auth_metadata` is
   `SKIPPED`/`UNVERIFIED` with `auth_no_challenge_observed` (suites up to 0.11.0
   recorded `COMPLETED`/`VERIFIED`); `VERIFIED` now means a 401 challenge was observed
   and its metadata checked out. Both are `SKIPPED`, not `COMPLETED`, like
   `latency_profile` and `tls_certificate`: there was nothing for the check to look at.
   The name is reserved for a tool that should not exist, but a
   server can define it, so outside a credential gate the call is withheld when a
   `tools/list` page we read names it, when the list was not read to its end (step 3),
   or when `tools/list` failed; both checks are then `SKIPPED`/`UNVERIFIED`. (Up to
   suite 0.14.0, which read only the first page, a `nextCursor` on it withheld the
   call the same way.) Under a credential
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
   `ProbeContext` — not recomputed per call site). The protocol calls (`protocol.ts`)
   are `POST`; the one `GET` is `auth.ts`'s fetch of the target's `resource_metadata`
   URL. `sendRequest` follows a `GET`'s redirects itself, one `fetchImpl` call per hop
   (the production `fetchImpl` asks `guardedFetch` not to follow them, with
   `followRedirects: false`), so every hop counts against the request budget, passes
   through the caller's own `fetchImpl` wrappers, and sets `redirectCrossHostObserved`
   when it leaves the host that call started on; a hop to another host drops the
   credential headers (`authorization`, `proxy-authorization`, `cookie`) from that hop
   on. `sendRequest` **never follows a redirect for a
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
   condition), and it is settled before anything later in the run can go wrong. It is
   judged only at that moment: if the handshake exchange itself stops first (the endpoint
   asks us to back off with a `429`, or a `503` carrying `Retry-After`; a response is over
   the body limit; the connection fails; or a budget runs out), `reachability` is
   `UNVERIFIED` with that reason even when the endpoint had already answered an earlier
   request of the same exchange. It used
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
sync is the caller's responsibility. The one exception is
`max_tools_list_pages` (suite 0.15.0), which `ProbeBudget` has no field for:
`runProbe` reads it from `input.registry`. Both currently use the same numbers by
construction (`checks.json`'s budget and `@mcpcheckup/ssrf-guard`'s
`DEFAULT_PROBE_BUDGET` are identical), but nothing in this package enforces that they
stay that way.

All budget accounting — request count, wall-clock duration, redirect hop count,
response body size — happens in exactly one place: `wire.ts`'s `sendRequest`, called by
every wire operation in this package. No individual check re-implements any of it.
This is what "the budget is global, not per-check" (8 requests total for the *whole
run*, not 8 per check) actually means in the code, not just in the doc comment. Since
suite 0.15.0 the further `tools/list` pages (at most 9) are sent on top of those 8:
`performToolsList` puts the request count back after each of them, and sends each with
the run's own deadline and body limit.

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
`discovery_handshake`, `protocol_revision`, and `transport_type` stay `VERIFIED` in
the result (`latency_profile` never takes the abort's reason: it is judged from the
requests that were answered before the abort) — `tools_list` itself (which never finished) and
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
0 is the URL it was asked for. Since suite 0.11.0 the production `fetchImpl` asks the
guard to follow no redirects (`followRedirects: false`; `sendRequest` follows a `GET`'s
hops itself, one guard call each), so there `hop` is always 0 and a redirect hop is a
call of its own. The rules below stay true: the only request that is ever redirected
is the `GET` of the `resource_metadata` URL, which runs after `reachability` is settled,
where the endpoint-naming reasons are not used.

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

Since suite 0.11.0 one error of our own has a reason of its own as well:
`OtherHostDeclined` (exported from this package), which a caller's `fetchImpl` wrapper
throws, before any request, when it declines to contact a host other than the
endpoint's — a redirect hop or a `resource_metadata` URL on another host. It gives
`probe_declined_other_host` (no params) to `reachability`, when not yet settled, and to
every never-ran check, in both columns. The reason names neither the host nor why it
was declined. Like any abort, it ends the run.

One check is not left to the cascade once its observation is in. Since suite 0.15.0,
when a cross-host redirect was seen before the abort, `redirect_policy` is
`COMPLETED`/`OBSERVED_RISK` with `redirect_cross_host_observed`, as on a run that
finishes, whatever ended the run afterwards: another host declined
(`OtherHostDeclined`), a guard refusal, the redirect, request or time budget, or the
server asking us to back off (`429`, or `503` with `Retry-After`). The hop that goes
over the redirect budget counts: `wire.ts` reads its `Location` and records a
cross-host one before it stops. The other never-ran checks stay `SKIPPED`/`UNVERIFIED`
with the abort's reason, never `FAILED`. Up to suite 0.14.0, `redirect_policy` took
the abort's reason too, even after a cross-host hop.

The params are only `kind`, `code` or a budget number: the error's message and cause
reach no assertion, no stored row and no signed payload. Any other thrown error — for
example one of the prober's own wrapper errors — keeps the generic
`probe_cascade_incomplete` on the cascade, and only `reachability` carries
`probe_aborted`. Since suite 0.15.0 its params are `{ error_class }` only: the name of
the thrown value's constructor (e.g. `TypeError`); `unknown` when that name cannot be
read or is not a JavaScript identifier of at most 64 characters; `null` or `undefined`
when that was thrown. The error's message is never read.
Up to suite 0.14.0 they were `{ message }`, the error's message, which is unbounded
text; `reason-messages.ts` still renders those rows as they were.

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

Since suite 0.14.0 a run stopped at either gate whose `auth_metadata` was
judged from that gate's challenge also returns `ProbeResult.authObservation`:
the challenge reduced to what an `auth_gated` attestation payload records
(`auth-observation.ts`; each rule is stated in the attestation schema's
`auth_observation` descriptions), except when `credentialShapes()` flags the
challenge's auth-scheme, as sent or lowercased: then `authObservation` is
absent. It adds no request and changes no assertion.
Whether such a run can be signed as `auth_gated` is decided from its
assertions by whoever builds the payload, not here.

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
  lives in `performHandshake`'s 2xx/4xx branch and nowhere else, because the
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

### Response time (`latency_profile`, suite 0.16.0)

The same out-of-band channel carries the one other transport fact the probe records:
`GuardSignals.responseHeadersMs`, how long a call took from just before its request was
sent until its response headers arrived, by the FetchLike's own clock. It is never read
off the `Response`. The production adapter (the probe Worker's) measures it by handing
`guardedFetch` a `fetchImpl` that wraps the platform `fetch` with a clock: `guardedFetch`
calls that `fetchImpl` only for the request to the target, after its address checks, so
its DoH lookups (before and after the request) and the body read are not in the time.
No request is added, and `ssrf-guard` itself is unchanged.

`sendRequest` keeps a time only for a POST (every protocol request is a POST to the
endpoint; the one GET, auth metadata, is another resource), at most once per call, only
while the call has not been abandoned at the run's deadline, and only when it is a whole
non-negative number of ms (`isLatencySampleMs` in `latency.ts`). Any HTTP status counts.
At the end of the run `probe.ts` writes the one `latency_profile` row (`judgeLatency`):

- at least one time, the handshake not credential-gated: `COMPLETED`/`VERIFIED` `latency_measured`
  with `{ p50_ms, p95_ms, n, timed_to: 'response_headers' }`, nearest rank over the n
  times (with n ≤ 19, p95 is the slowest). `VERIFIED` means measured, never fast: the
  check is `observation_only`, with no threshold;
- at least one time on a run whose handshake stopped at a credential gate:
  `SKIPPED`/`UNVERIFIED` `latency_not_signed_auth_gated` (an `auth_gated` payload covers
  only four checks and requires every other row to be `UNVERIFIED`). A gate on
  `tools/list` alone is measured like any other run: its handshake keeps its real
  verdicts, so no `auth_gated` payload covers it;
- answers but no time (a FetchLike that does not time, such as the fixtures' handlers):
  `SKIPPED`/`UNVERIFIED` `latency_not_recorded`, the row suites 0.12.0 to 0.15.0 wrote;
- no answer at all: `SKIPPED`/`UNVERIFIED` `latency_no_samples`.

The numbers travel in the signed `reason.params` of attestation payload v0.4; the
schema, signer and verifier are unchanged.

## Tool description hygiene: what suite 0.17.0 no longer counts

`tool_description_hygiene` (`hygiene.ts`) reports signals and never infers intent. Suite
0.17.0 narrows two of its rules. Both can only remove a flag, never add one, and the
signed result keeps its shape: the same reason keys (`hygiene_risk_detected` with
`{ hitCount, totalCount }`, or `hygiene_no_risk`), with fewer tools counted.

**`zero_width_chars`.** Every zero-width character in the text is examined, not only the
first. A ZWNJ (U+200C) or ZWJ (U+200D) is not a hit when both neighbours, with combining
marks (`\p{M}`) skipped, share one `Script_Extensions` value from this list: Arabic,
Devanagari, Bengali, Gurmukhi, Gujarati, Oriya, Tamil, Telugu, Kannada, Malayalam,
Sinhala, Syriac, Thaana. These are scripts whose ordinary spelling uses the two
characters (cursive joining, conjuncts and half forms). A ZWJ directly between two
`\p{Extended_Pictographic}` characters (combining marks such as U+FE0F skipped) is not a
hit either.
Everything else still is: every other zero-width character (U+200B, U+200E, U+200F,
U+2060–U+2064, U+FEFF, U+180E), and a ZWNJ or ZWJ at either end of the text, next to
another zero-width character, between ASCII letters, between two different scripts, or
next to an unassigned (`\p{Cn}`) code point. The last rule means an engine with older
Unicode data treats a character it does not know as a hit, not as compliant. U+FE0E and
U+FE0F were never scanned and still are not. A ZWJ after a skin-tone modifier is a hit:
the modifier is neither `\p{M}` nor `\p{Extended_Pictographic}`.

**`injection_imperative`, two of its seven patterns.**

- "do not tell / inform / mention / reveal / show the user (or human)" is a hit only when
  followed by `about`, `that you`, `what you`, `how you`, `anything`, `any of`, one
  of `.` `,` `;` `:` `!` `)` (optionally after whitespace) or the end of the text. "Do not tell the user X until Y" is an
  ordinary instruction about what not to claim and is no longer a hit.
- "system prompt" / "developer prompt" is a hit only after `your`, or after reveal,
  print, output, repeat, disclose, leak, ignore, override, disregard or forget
  (optionally with `the`, `any` or `all` between). A `system prompt` field or parameter,
  an agent's configured prompt, and "never treat it as a system prompt" are no longer
  hits.

The other five `injection_imperative` patterns are unchanged, and so are
`pseudo_system_delimiter`, `embedded_markup` and `excessive_length`.

`hygiene-0170-fixtures.ts` holds the evidence: minimal reconstructions (not copies of any
real server's text) of the five injections the rules must keep catching, the false
positives they drop (each tagged with its class), and inputs that must keep their flags.
`suite-0170-differential.test.ts` holds the live suite against frozen suite 0.16.0: on
every tool description the differentials serve and every fixture, the 0.17.0 flags are a
subset of the 0.16.0 ones, a tool loses a flag only if the fixtures list it, and the
five must-hit inputs keep exactly their flags. `hygiene-0170.test.ts` pins the
zero-width rule code point by code point.

## Tool description hygiene: what suite 0.18.0 adds

Suite 0.18.0 adds one flag and widens the two patterns suite 0.17.0 narrowed. Both
changes can only add a flag, never remove one, and the signed result keeps its shape: the
same reason keys and params, with more tools counted where a description hits.
`excessive_length` is unchanged and still counts toward `OBSERVED_RISK`.

**`unconfirmed_spending`: spending or sending identity data without per-action
confirmation.** A hit is one of these phrases (case ignored):

- `pay`, then `by default` in the same sentence within 40 characters;
- `no approval` or `no confirmation`, then `needed` or `required` (optionally after `is`);
- `need not ask`; `zero questions`;
- `without asking`, unless `never`, `not` or a word ending in `n't` (ASCII apostrophe only)
  comes within 30 characters before it in the same sentence, or `for` or `us` follows it;
- `does not` or `doesn't` `require` `per-change`, `per-action`, `per-call`,
  `per-purchase` or `per-payment` (a space instead of the hyphen also counts) `approval`;
- `the` grant, allowance or delegation `is` the or your permission, approval or consent;
- accept or approve, then all, every or any, then up to two words, then prompt,
  confirmation, dialog or request, singular or plural;
- continues, repeats or recurs `automatically`;
- the, your or this `agent loop`;
- `git config`, then `user.email` (options such as `--get` may come between);
- `never ask` (optionally followed by `the user`) `before` charging, paying, buying,
  purchasing, spending, billing, renewing or subscribing;
- 无需确认 or 无需另行确认; 视为同意 or 视为用户同意.

A phrase counts only when both guards pass. **Proximity:** a money or identity word (see
**Negation** below) is
within 200 characters before or after it: pay, pays, paid, paying, payer, payment(s),
charge (charges, charged, charging), credit(s), wallet(s), USDC, invoice(s), purchase
(purchases, purchased, purchasing), buy (buys, buying), subscribe (subscribes, subscribed,
subscribing), subscription(s), renew (renews, renewed), renewal(s), bill (bills, billed,
billing), cost(s), fee(s), refund (refunds, refunded, refundable), spend (spends,
spending), money, identity, email(s) or e-mail(s), a `$` amount, or 扣费, 续费, 费用, 支付,
付款, 购买, 订阅, 钱包, 邮箱, 身份. **Limit:** no cap(s), capped, limit(s), ceiling(s), max,
maximum, policy or policies, mandate(s), allowlist(ed), whitelist(ed) (either also as
allow-list, white-list), threshold(s) or quota(s) (or 上限, 额度, 限额, 策略, 白名单)
is in the 120 characters before it, because spending inside a cap, allowlist or policy the
user set is not a missing confirmation. A limit word after the phrase does not suppress it.

**Negation:** a money or identity word does not count when its own clause says it costs
nothing or is not sent: `cost` or `costs` followed by `nothing` (up to two words between),
`free`, `no charge`, `no cost` or `no fee` (or their plurals), does not, doesn't, do not,
don't, never, will not or won't (ASCII apostrophe only) followed by send, collect, store or share (or sends,
collects, stores, shares), or 免费 or 不收费; `free` right after `feel` does not count. A
clause ends at `.` `!` or `?` followed by whitespace or the end of the text, at `,` `;` or a
line break, or at ，。！？；, and reaches at most 200 characters either side of the word's
first character. The same words in another
clause change nothing: "a free trial. Then 99 a year is charged …" still counts the charge.

**No-spend:** a phrase does not count when its own clause has `no purchase` (or
`no purchases`), `read-only` (or `read only`), `does not` or `doesn't` followed by buy,
purchase, register or charge, `what it costs` or `how much`. The same words in a money or
identity word's own clause stop that word from counting; in any other clause they change
nothing. A spending phrase that is itself a negation ("No confirmation needed: …", "Never
ask the user before charging") is not cancelled by its own negation.

**`injection_imperative`, the two patterns suite 0.17.0 narrowed.** Each new form is
suite 0.16.0's own pattern followed (or, for the prompt rule, surrounded) by a further
condition, so it can only flag text suite 0.16.0 flagged.

- "do not tell / inform / mention / reveal / show (the) user or human" is also a hit when
  followed by `'s` or `’s`, a hyphen with a space or tab before it, an en or em dash, a
  line break, or one of `that`, `what`, `why`, `where`, `how`, `this`, `any`, unless the
  text after it has until, unless, yet, before, after, otherwise, once, while, if or when
  before the next `.` `;` `!` `?` or line break (after a line break, "the text after it"
  is the next line). "Do not
  tell the user that the seat is held until the id comes back" stays a non-hit.
- "system prompt" / "developer prompt" is also a hit after `your new`; after show,
  return, display, replace, dump, echo or act as as well as the 0.17.0 verbs, optionally
  followed in turn by `out`, by the, any, all or your, by previous, prior, above, earlier,
  original or `contents of`, and by the or your; and at the start of a line (after only
  spaces, tabs, `#`, `*`, `>`, `[` or `-`) when followed, after optional whitespace, by a
  colon or `override`. A `returns
  the system prompt` field and a mid-line `system prompt:` label stay non-hits.

`hygiene-0180-fixtures.ts` holds the evidence, all invented sentences: one SPENDING
fixture per phrase form, NOT_SPENDING inputs for each guard, the RESTORED injection forms
and the STILL_REMOVED ones. `suite-0180-differential.test.ts` holds the live suite
against frozen suite 0.17.0: on every tool description the differentials serve and every
fixture, the 0.17.0 flags are a subset of the 0.18.0 ones, a tool gains a flag only if the
fixtures declare it, every added `injection_imperative` is one frozen suite 0.16.0 also
flags, and the SPENDING must-hit set is exact. `hygiene-0180.test.ts` pins the guards at
their character boundaries.

## Tool description hygiene: what suite 0.19.0 adds

Suite 0.19.0 stops counting length alone as a risk, adds one flag, three
`unconfirmed_spending` forms and one `injection_imperative` form, and moves three sentence
or clause boundaries. The signed
result keeps its shape: the same reason keys and params.

**`excessive_length` no longer counts on its own.** A description over 2,048 characters
is still flagged `excessive_length` on its tool, but a tool counts toward `OBSERVED_RISK`
and `hitCount` only when it has some other flag. A tool list whose only flags are
`excessive_length` is `hygiene_no_risk`; the `Info:` line still counts such a tool among
those that hit a signal.

**`unprompted_continuation`: continuing without another user prompt.** A hit is
`without`, optionally `waiting for`, then another, a further, any further, further, a
new, a second, an additional or additional, then user or human, then prompt, message,
request, turn or reply, singular or plural (case ignored). It has no guard.

**`unconfirmed_spending`, three more forms.** The 0.18.0 guards apply to each, with the
one exception noted.

- sell, sells, selling, sellable, resell, resells, reselling or resellable, then
  `entrusted` or `lent`, optionally `to`, then `you`, in the same sentence within 80
  characters.
- raise, increase, disable or `turn off`, optionally the or your, then `spendControls`
  (optionally followed by a dot and a name), `maxAmountPerPayment`, `spend` or
  `spending` and limit, limits, cap or caps, or `payment` and cap or caps; or `set`,
  optionally the or your, then one of those, optionally `:`, `=` or `to`, then `false`
  or `0` (not followed by a dot, letter, digit or underscore, so `0.5` is not one). The
  **Limit** guard does not apply to this form: the limit is what it is about.
- pays, charges or spends, then within 40 characters in the same sentence `from` your
  owner's, the user's, your human's or the human's (either apostrophe), then credit,
  credits, balance, wallet or funds. It does not count when that sentence or the next has
  confirm, confirms, confirmed, confirming, confirmation, confirmations, approve,
  approves, approved, approving, approval or approvals, or ask, asks, asked or asking
  followed within 40 characters in the same sentence by `permission`. "Explain the cost
  to your human" is not a confirmation. A sentence ends at `.` `!` or `?` followed by
  whitespace or the end of the text, at a line break, or at 。！？; the two sentences reach at
  most 400 characters before the start of the phrase and 800 after it.

**`injection_imperative`, one more form, outside suite 0.16.0.** "Never", "do not" or
"don't" (either apostrophe) followed by say, mention, tell, disclose, reveal or state,
when missing, not verified, unverified, failed or absent comes after it in the same
clause, unless because, when, if, unless, since, as or so (whole words) comes between
them. "Never say that a step is missing" is a hit; "never say the batch is done when a row
failed" asks for honesty and is not. This is the one `injection_imperative` form suite
0.16.0 did not flag.

**Boundaries (TODO 1316).**

- The same-sentence windows of `pay … by default` and of the `without asking` negation
  also end at 。！？, as well as at `.` `!` `?` or a line break. "Pay the invoice。By
  default, list prices only." is no longer a hit; "Never share the email。Without asking,
  charge the card." now is.
- The flow-word lookahead of "do not tell the user" also ends at `,` and at ，。！？；.
  "Do not tell the user why, until the payment clears." is a hit again, as in suite
  0.16.0. This form is still suite 0.16.0's pattern followed by a lookahead, so it can
  only flag what suite 0.16.0 flagged.

`hygiene-0190-fixtures.ts` holds the evidence, invented sentences and the two review
counterexamples above. `suite-0190-differential.test.ts` holds the live suite against
frozen suite 0.18.0: on every tool description the differentials serve and every fixture,
a tool gains a flag only if the fixtures declare it, loses one only if they declare it,
every added `injection_imperative` is one frozen suite 0.16.0 also flags except exactly
the DECLARED_INJECTION_0190 fixtures (the form above), and only the
LENGTH_ONLY fixture is flagged `excessive_length` alone. `hygiene-0190.test.ts` pins the
boundaries character by character.

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
- **`transport_type` compares nothing, and does not say the handshake succeeded.** It
  has no `OBSERVED_RISK` path: nothing in this package reads a transport the server
  declares (`checks.json` declares its `failure_status` as `null`, and its `explain` text
  says so). `probe.ts` records it `VERIFIED` at the point where
  `latency_profile` was recorded `VERIFIED` by suites up to 0.11.0 (since suite 0.16.0
  it is judged at the end of the run from the times of the requests sent):
  once `performHandshake` has returned, i.e. once the handshake
  exchange over the transport the probe used has finished with an HTTP response from the
  endpoint. The predicate is exactly that ("the endpoint answered our handshake request
  over the transport used"), not "the handshake completed": it does not depend on how
  the handshake itself concluded. A credential-gated or `FAILED` handshake still leaves
  `transport_type` `VERIFIED`, and `discovery_handshake` carries the handshake's own
  verdict. If the probe stops before the exchange finishes (a `429`, or a `503` carrying
  `Retry-After`; a response over the body limit; a budget running out), `performHandshake`
  throws, `transport_type` is `SKIPPED`/`UNVERIFIED` and carries the abort's reason. A
  comparison against a declared transport would need that declaration to be recorded per
  target first; no fixture in the current corpus models a transport mismatch.
- **`auth_metadata` does not follow `jwks_uri`** even when a resource-metadata document
  declares one. No predicate this package currently implements depends on JWKS
  contents — a multi-key JWKS is a normal key-rotation transition window, not evidence
  of anything (`jwks-multiple-keys-not-flagged` in the fixture corpus exists
  specifically to prove this package doesn't misjudge that) — so fetching it would only
  spend probe request budget without changing any verdict.
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
