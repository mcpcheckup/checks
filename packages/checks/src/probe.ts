import { assertUnverifiedHasReason } from '@mcpcheckup/attestation-schema'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { BudgetExceeded, RateLimited, SsrfBlocked, UpstreamFetchFailed } from '@mcpcheckup/ssrf-guard'

type ExecutionStatus = Assertion['execution_status']
import { runHygieneCheck } from './hygiene.ts'
import { createProbeContext, ProbeAborted } from './wire.ts'
import { OtherHostDeclined } from './other-host-declined.ts'
import type { ProbeContext } from './wire.ts'
import { offeredRevision, performHandshake, performToolsList, performUnknownToolCall } from './protocol.ts'
import type { CredentialChallenge } from './protocol.ts'
import { judgeAuthMetadata, judgeAuthMetadataFromGate } from './auth.ts'
import { authObservationOf, keepLastOkBody } from './auth-observation.ts'
import { judgeErrorTaxonomy } from './error-taxonomy.ts'
import { computeToolsetFingerprint, computeSchemaFingerprint, buildToolSnapshot } from './fingerprint.ts'
import type { FingerprintVerdict } from './fingerprint.ts'
import type { CheckDefinition, ChecksRegistry } from './registry.ts'
import type { DriftEvent, EvidenceProvenance, ProbeInput, ProbeResult } from './types.ts'

/** A name no real business tool would ever use — the protocol-level, non-destructive
 *  way error_taxonomy and auth_metadata trigger a safe error scenario. Never a
 *  business tool call (CLAUDE.md / checks.json's own `forbidden` list).
 *  T86: the name is published, so a server can define it; runProbe withholds
 *  the call unless it can rule that out (see probeCallWithheld). */
const PROBE_TOOL_NAME = '__mcpcheckup_probe_nonexistent_tool__'

type Reason = { key: string; params?: Record<string, string | number> } | null

type AssertionBuilder = (
  check_id: string,
  execution_status: ExecutionStatus,
  assertion_status: Assertion['assertion_status'],
  reason?: Reason,
) => void

/** Suite 0.12.0: the two reasons whose whole content is "the answer had nothing
 *  of the kind this check reads" — no 401 challenge for auth_metadata
 *  (auth_no_challenge_observed), no protocol error for error_taxonomy
 *  (error_shape_not_observed). A check with no object to look at did not run on
 *  anything: it is SKIPPED/UNVERIFIED like tls_certificate and latency_profile,
 *  not COMPLETED. That also keeps it out of the badge fold, which drops SKIPPED
 *  rows: an open server (answers the reserved-name call with an ordinary error)
 *  keeps the badge it had under suites up to 0.11.0. Every other verdict of
 *  these two checks — including every other UNVERIFIED — is a check that ran. */
const NOTHING_TO_OBSERVE_KEYS: ReadonlySet<string> = new Set(['auth_no_challenge_observed', 'error_shape_not_observed'])

function executionOf(verdict: { status: string; reason?: Reason }): ExecutionStatus {
  return verdict.status === 'UNVERIFIED' && verdict.reason != null && NOTHING_TO_OBSERVE_KEYS.has(verdict.reason.key) ? 'SKIPPED' : 'COMPLETED'
}

/** T73b: a FAILED discovery_handshake / tools_list forwards the reason
 *  protocol.ts classified at the failing return — never re-derived here.
 *  Reaching FAILED without one would be a classification gap in protocol.ts,
 *  never data, so it throws: the catch in runProbe then records the check
 *  UNVERIFIED, never FAILED-without-a-reason. failed-reasons-differential.test.ts
 *  shows the gap unreachable. */
function classified(failure: Reason | undefined, checkId: string): NonNullable<Reason> {
  if (!failure) throw new Error(`${checkId} is FAILED but protocol.ts classified no reason`)
  return failure
}

/** Shape a guard code must have before it may enter params (and so a signed
 *  payload and a public page): every code ssrf-guard raises is one of these. */
const GUARD_CODE_SHAPE = /^[A-Z][A-Z0-9_]{0,63}$/

/** T85 (suite 0.9.0): the reason for an error @mcpcheckup/ssrf-guard
 *  raised on the way to or from the target, read off its class and `.code`
 *  alone. The error's message and cause are never read and never copied: the
 *  only params are `kind` (a fixed word) or `code` (a guard constant), and the
 *  budget numbers come from this run's own budget. Returns undefined for
 *  anything else — our own errors: OtherHostDeclined (its own key, in
 *  runProbe's catch) and the adapter's argument checks, which keep
 *  probe_aborted.
 *
 *  Two rules keep a reason from saying something false about the endpoint:
 *  - The keys whose copy names "the endpoint" — reachability_dns_failed and
 *    reachability_unanswered {kind:"timeout"} — hold only at hop 0: the
 *    request guardedFetch was given, before any redirect (the guard's `hop`
 *    field). At hop > 0, or with no hop recorded, they are always
 *    reachability_unanswered {kind:"other"}. Keys that do not name the
 *    endpoint ignore hop.
 *  - Once reachability is settled the endpoint has answered, so a never-ran
 *    row may not say otherwise: a DNS failure or an unanswered request becomes
 *    probe_cascade_incomplete (the 0.8.0 reason), and a guard timeout becomes
 *    probe_budget_exhausted_duration, as wire.ts's own duration abort does. */
function guardErrorReason(e: unknown, budget: ProbeInput['budget'], reachabilitySettled: boolean): NonNullable<Reason> | undefined {
  const other = (): NonNullable<Reason> => reachabilitySettled ? { key: 'probe_cascade_incomplete' } : { key: 'reachability_unanswered', params: { kind: 'other' } }
  if (e instanceof UpstreamFetchFailed) return other()
  if (e instanceof BudgetExceeded) {
    if (e.code === 'MAX_DURATION') {
      if (reachabilitySettled) return { key: 'probe_budget_exhausted_duration', params: { maxDurationMs: budget.maxDurationMs } }
      return e.hop === 0 ? { key: 'reachability_unanswered', params: { kind: 'timeout' } } : other()
    }
    if (e.code === 'MAX_REQUESTS') return { key: 'probe_budget_exhausted_requests', params: { maxRequests: budget.maxRequests } }
    if (e.code === 'MAX_REDIRECTS') return { key: 'probe_budget_exhausted_redirects', params: { maxRedirects: budget.maxRedirects } }
    if (e.code === 'MAX_BODY_BYTES') return { key: 'probe_budget_exhausted_body', params: { maxBodyBytes: budget.maxBodyBytes } }
    return undefined
  }
  // Our own rate-limit decision said no — not the target. So only the key, and
  // never ProbeResult.rateLimited, which means "the target told us to wait".
  if (e instanceof RateLimited) return { key: 'probe_rate_limited' }
  if (e instanceof SsrfBlocked) {
    if (e.code === 'RESOLUTION_FAILED') return e.hop === 0 && !reachabilitySettled ? { key: 'reachability_dns_failed' } : other()
    if (e.code === 'RESOLVER_UNAVAILABLE') return { key: 'probe_resolver_unavailable' }
    if (GUARD_CODE_SHAPE.test(e.code)) return { key: 'probe_blocked_by_policy', params: { code: e.code } }
  }
  return undefined
}

/** Shape an error class name must have to enter params: a JavaScript
 *  identifier, at most 64 characters. */
const ERROR_CLASS_SHAPE = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/

/** Suite 0.15.0 (probe_aborted): the class of a thrown value, by its
 *  constructor's name (e.g. TypeError), never by its message or its `name`
 *  property. A name of another shape, or one that cannot be read, is
 *  'unknown'; a thrown null or undefined is that word. */
function errorClassOf(e: unknown): string {
  if (e === null || e === undefined) return String(e)
  try {
    const name: unknown = (Object(e) as { constructor?: { name?: unknown } }).constructor?.name
    return typeof name === 'string' && ERROR_CLASS_SHAPE.test(name) ? name : 'unknown'
  } catch {
    return 'unknown'
  }
}

function docsVersionFor(registry: ChecksRegistry, checkId: string): string {
  return registry.checks.find((c) => c.check_id === checkId)?.docs_version ?? 'unknown'
}

function checkDef(registry: ChecksRegistry, checkId: string): CheckDefinition | undefined {
  return registry.checks.find((c) => c.check_id === checkId)
}

/** Compares a freshly computed fingerprint against an approved baseline (when one
 *  was supplied) or records why comparison is impossible — the "有无基线决定语义"
 *  rule: no baseline is always UNVERIFIED (never FAILED), a baseline mismatch is
 *  the one case that can be FAILED, and a mismatch also becomes a DriftEvent. */
function judgeBaselineCheck(
  checkId: 'toolset_unchanged_vs_approved' | 'schema_unchanged_vs_approved',
  fp: FingerprintVerdict,
  baselineValue: string | undefined,
  now: () => string,
  registry: ChecksRegistry,
  A: AssertionBuilder,
  driftEvents: DriftEvent[],
): void {
  if (fp.status !== 'VERIFIED') {
    A(checkId, 'SKIPPED', 'UNVERIFIED', { key: 'fingerprint_comparison_unavailable' })
    return
  }
  if (baselineValue === undefined) {
    const def = checkDef(registry, checkId)
    const reason: Reason = def?.no_baseline_reason_zh
      ? { key: 'no_baseline_reason', params: { check_id: checkId } }
      : { key: 'no_baseline_reason_generic' }
    A(checkId, 'SKIPPED', 'UNVERIFIED', reason)
    return
  }
  if (fp.fingerprint === baselineValue) {
    A(checkId, 'COMPLETED', 'VERIFIED')
    return
  }
  A(checkId, 'COMPLETED', 'FAILED', { key: 'fingerprint_baseline_mismatch' })
  driftEvents.push({ check_id: checkId, previous_fingerprint: baselineValue, current_fingerprint: fp.fingerprint, detected_at: now() })
}

/** Runs the full remote-baseline-v0.1 check suite (packages/checks/checks.json)
 *  against one target and returns exactly one assertion per registered check —
 *  never fewer (silent omission), never more. Every wire call goes through
 *  input.fetchImpl; this module never calls the fetch API or guardedFetch itself (see
 *  no-direct-fetch.test.ts).
 *
 *  Cascading failure semantics: reachability answers "did the endpoint answer
 *  us at all," and it is asserted at the moment that becomes true — as soon as
 *  performHandshake returns, which it only does after a real HTTP response
 *  came back (any status: 200, 401, 403, 4xx, 5xx alike — checks.json's own
 *  predicate is "endpoint responds within budget", with no status condition).
 *  Everything after that point is a different question, so a later abort can
 *  no longer take reachability down with it. T6.9-F: it used to be the LAST
 *  statement of the try block, which made the most basic fact in the run
 *  hostage to every step that followed — eight of twelve unclaimed targets
 *  reported 0% uptime while their handshake and tools/list were VERIFIED.
 *
 *  A SINGLE try/catch still wraps the entire wire sequence (handshake through
 *  the final tools/call probe). Any exception, whether a budget/duration/
 *  redirect abort from wire.ts or an arbitrary error thrown by fetchImpl
 *  itself, produces: reachability = ERROR/UNVERIFIED **only if it was not
 *  already settled** (i.e. the abort happened at or before the handshake), and
 *  every check that never got to run (except the always-out-of-scope
 *  tls_certificate and the never-run latency_profile) = SKIPPED/UNVERIFIED
 *  carrying the abort's own reason.
 *  Checks that already COMPLETED before the abort keep whatever result they
 *  earned — "we verified the protocol handshake, then ran out of budget" is a
 *  coherent, honest statement; discarding an already-verified observation would
 *  itself be a form of the same dishonesty this four-state model exists to
 *  avoid (see response-exceeds-budget in the fixture corpus, and the README's
 *  "cascading failure" section). T85 (suite 0.9.0): which reason an exception
 *  gets is decided by its class and code only (guardErrorReason), never by
 *  its message — so the ssrf-guard errors fetchImpl passes through now tell
 *  "the endpoint did not answer" apart from our own policy, resolver and
 *  budget. Suite 0.11.0: a host other than the endpoint's that a FetchLike
 *  wrapper declined to contact (OtherHostDeclined) gets
 *  probe_declined_other_host; anything else still gets probe_aborted.
 *  Suite 0.12.0: three checks stop recording VERIFIED for something that was
 *  not observed — latency_profile (never run: latency_not_recorded),
 *  auth_metadata (the tools/call answer was not a 401: auth_no_challenge_observed,
 *  in auth.ts) and error_taxonomy (it was a 401/403: error_shape_not_observed,
 *  in error-taxonomy.ts). All three are SKIPPED/UNVERIFIED (see
 *  NOTHING_TO_OBSERVE_KEYS): there was nothing for the check to look at.
 *  Suite 0.14.0: a run stopped at a credential gate also returns
 *  authObservation, the gate's challenge as an auth_gated attestation payload
 *  records it (auth-observation.ts); no assertion changes.
 *  Suite 0.15.0: tools/list follows nextCursor; a list not read to its end
 *  records tools_list_incomplete instead of anything VERIFIED it could
 *  change, and no toolSnapshot. A cross-host redirect seen before an abort
 *  is still recorded by redirect_policy, and probe_aborted carries the
 *  error's class, never its message. */
export async function runProbe(input: ProbeInput): Promise<ProbeResult> {
  const { target, fetchImpl, budget, now, newId, approvedBaseline, provenance, registry } = input

  const assertionsByCheckId = new Map<string, Assertion>()
  const driftEvents: DriftEvent[] = []
  let disqualifiedFromPublication: { key: string; params?: Record<string, string | number> } | undefined
  let toolSnapshot: ProbeResult['toolSnapshot']
  // Hoisted so finalize() can read it on every exit path (success, abort, or
  // stdio-scope) — a DNS-answer-change observed on an early request must still
  // disqualify the run even if a later request in the same run throws and never
  // reaches the in-try-block check below.
  let ctx: ProbeContext | undefined
  // Hoisted so finalize() can read it on every exit path — stays null on the
  // stdio path and on any path where the try block throws before reaching the
  // handshake line (never set from inside the catch block).
  let protocolRevisionDeclared: string | null = null
  // TODO 217: set on the same line and the same paths as protocolRevisionDeclared.
  let probeOfferedRevision: string | null = null
  // Set ONLY from the catch block's RATE_LIMITED branch — its presence is the
  // whole signal ("this run stopped because the target asked us to come back
  // later"), so it must never be set speculatively anywhere else.
  let rateLimited: ProbeResult['rateLimited']
  // Suite 0.14.0: set only on the credential-gated path, once auth_metadata has
  // been judged from the gate's challenge.
  let authObservation: ProbeResult['authObservation']

  const A: AssertionBuilder = (check_id, execution_status, assertion_status, reason = null) => {
    const assertion: Assertion = {
      check_id,
      docs_version: docsVersionFor(registry, check_id),
      execution_status,
      assertion_status,
      evidence_provenance: provenance as EvidenceProvenance,
      reason,
      unverified_reason: assertion_status === 'UNVERIFIED' ? reason : null,
    }
    assertUnverifiedHasReason(assertion)
    assertionsByCheckId.set(check_id, assertion)
  }

  const cascadeRemaining = (execution_status: ExecutionStatus, reason: Reason) => {
    for (const def of registry.checks) {
      if (assertionsByCheckId.has(def.check_id)) continue
      A(def.check_id, execution_status, 'UNVERIFIED', reason)
    }
  }

  // tls_certificate is out of this executor's scope unconditionally — set first
  // so every other branch below can rely on it already being present.
  A('tls_certificate', 'SKIPPED', 'UNVERIFIED', { key: 'tls_certificate_out_of_scope' })
  // Suite 0.12.0: latency_profile is not run on any branch — nothing in this
  // executor times a request, so it is never VERIFIED (suites up to 0.11.0
  // wrote it VERIFIED unconditionally). Set here, beside tls_certificate, so
  // the stdio branch, the cascade and the credential gates each end with this
  // one row and no branch below writes it a second time.
  A('latency_profile', 'SKIPPED', 'UNVERIFIED', { key: 'latency_not_recorded' })

  if (target.transport === 'stdio') {
    cascadeRemaining('SKIPPED', { key: 'stdio_out_of_scope' })
    return finalize()
  }

  // Marks every one of the five tools-derived checks SKIPPED/UNVERIFIED with
  // the same reason — shared by both the "tools/list itself never ran because
  // the handshake was structurally gated" cascade and the pre-existing
  // "tools/list ran but returned an illegal structure" cascade below, so the
  // check_id list is declared exactly once.
  const skipToolsDerivedChecks = (reason: Reason) => {
    for (const check_id of ['toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene', 'toolset_unchanged_vs_approved', 'schema_unchanged_vs_approved']) {
      A(check_id, 'SKIPPED', 'UNVERIFIED', reason)
    }
  }

  try {
    ctx = createProbeContext(Date.now())
    const handshake = await performHandshake({ fetchImpl, endpoint: target.endpointUrl, budget, ctx, newId })

    // Asserted HERE, at the first moment it is true, and never again (the catch
    // below guards on assertionsByCheckId). performHandshake can only return by
    // having received at least one complete HTTP response from the endpoint;
    // every way of NOT getting one — DNS/TLS/connection failure, the first
    // request timing out, the first request being budget-aborted or
    // rate-limited — throws out of it instead and lands in the catch, which
    // then produces the UNVERIFIED-with-a-reason this check is supposed to
    // have. Status code is deliberately not a condition: a 401/403 IS the
    // endpoint responding, which is all this check claims (checks.json's
    // predicate_en, and the same reading credentialChallengeFrom already
    // relies on one layer down in protocol.ts).
    A('reachability', 'COMPLETED', 'VERIFIED')

    protocolRevisionDeclared = handshake.protocolVersionDeclared
    probeOfferedRevision = offeredRevision(handshake.mode)

    // Handshake-layer credential-gate rule: a server that
    // deliberately puts the handshake behind auth gets UNVERIFIED/
    // credential_required here, not FAILED — "we couldn't verify" is not the
    // same claim as "this is broken." This is the ONE place in probe.ts that
    // decides the cascade; nothing downstream re-derives it.
    const handshakeCredentialGated = !handshake.handshakeOk && handshake.credentialChallenge !== undefined

    if (handshakeCredentialGated) {
      const reason: Reason = { key: 'credential_required', params: { scheme: handshake.credentialChallenge!.scheme } }
      A('discovery_handshake', 'COMPLETED', 'UNVERIFIED', reason)
      // Lead finding N1 (round 2): NOT "no handshake means no version was
      // ever identified" — that's false in the branch where a legacy
      // initialize succeeds (200 + matrix-member protocolVersion) and only
      // the FOLLOWING notifications/initialized call gets 401+challenge;
      // handshake.protocolVersionDeclared is non-null there too (see
      // protocol.ts's performLegacyHandshake, the ackRes-failure return).
      // The real reason is: the handshake sequence itself never completed,
      // so we don't compare whatever version we did see against
      // revision_matrix — a version glimpsed mid-handshake isn't the same
      // claim as "this server completed the handshake speaking version X."
      A('protocol_revision', 'COMPLETED', 'UNVERIFIED', reason)
    } else {
      if (handshake.handshakeOk) {
        A('discovery_handshake', 'COMPLETED', 'VERIFIED')
      } else {
        A('discovery_handshake', 'COMPLETED', 'FAILED', classified(handshake.failure, 'discovery_handshake'))
      }

      const revisionMatrix = checkDef(registry, 'protocol_revision')?.revision_matrix ?? []
      if (handshake.protocolVersionDeclared && revisionMatrix.includes(handshake.protocolVersionDeclared)) {
        A('protocol_revision', 'COMPLETED', 'VERIFIED')
      } else {
        // T73b: which half of the condition above failed. Never the declared
        // value itself (third-party text) nor its length.
        A('protocol_revision', 'COMPLETED', 'FAILED', { key: handshake.protocolVersionDeclared ? 'protocol_revision_unknown' : 'protocol_revision_missing' })
      }
    }

    A('transport_type', 'COMPLETED', 'VERIFIED')

    // Always run tools/list, in both cascade branches: the credential-gate rule
    // does not change whether it is sent, and on the branches that still send
    // the tools/call, performUnknownToolCall below needs
    // toolsList.currentEndpoint regardless of how the tools_list assertion
    // itself gets judged.
    // Suite 0.15.0: tools/list follows nextCursor (performToolsList), up to the
    // registry's budget.max_tools_list_pages. Behind a handshake-layer gate the
    // list is never used (see below), so only its first page is read.
    const toolsList = await performToolsList({ fetchImpl, budget, ctx, newId, handshake, maxPages: handshakeCredentialGated ? 1 : registry.budget.max_tools_list_pages })
    // Suite 0.15.0: the list was not read to its end. Nothing the unread part
    // could change is recorded as VERIFIED: no fingerprint (so no tool
    // snapshot), no baseline comparison, and no clean result from a check
    // that looked only at the tools that did come in. Nor is the reserved-name
    // tools/call sent (probeCallWithheld below).
    const listIncomplete: Reason = toolsList.ok && toolsList.incomplete ? { key: 'tools_list_incomplete' } : null

    // T86: set when the tools/call probe must not be sent, because the server
    // may really define PROBE_TOOL_NAME. A readable list is judged first: a
    // page we read names that exact tool (collision; exact string equality, no
    // case folding, trimming or prefix match), or the list was not read to its
    // end (unverifiable: the name could be on a page we did not read, so the
    // call could reach a real tool). Suite 0.15.0: only a list read to its end
    // lets the call go out; up to suite 0.14.0, which read the first page
    // only, a nextCursor on it withheld the call the same way. The final else
    // adds the failed tools/list. T86b: both credential-gated branches then replace it with
    // their credential_required reason, whatever the list said (a gate wins
    // over a collision), so no gated run sends the call; auth_metadata reads
    // the gate's own 401 challenge (gateChallenge) instead of that call's
    // response.
    let probeCallWithheld: Reason =
      !toolsList.ok ? null
      : toolsList.tools!.some((tool) => typeof tool === 'object' && tool !== null && (tool as { name?: unknown }).name === PROBE_TOOL_NAME) ? { key: 'probe_tool_name_collision' }
      : listIncomplete ? { key: 'probe_tool_name_unverifiable' }
      : null
    let gateChallenge: CredentialChallenge | undefined

    if (handshakeCredentialGated) {
      // Handshake-layer credential-gate rule, continued:
      // tools_list and everything derived from it cascade to UNVERIFIED/
      // credential_required too — there was never a handshake to have run
      // tools/list meaningfully against, whatever toolsList.ok happens to say.
      // Fingerprints are deliberately never computed on this branch: declaring
      // tools_list unverified while still publishing a fingerprint derived
      // from that same response would be incoherent.
      const reason: Reason = { key: 'credential_required', params: { scheme: handshake.credentialChallenge!.scheme } }
      A('tools_list', 'COMPLETED', 'UNVERIFIED', reason)
      skipToolsDerivedChecks(reason)
      probeCallWithheld = reason
      gateChallenge = handshake.credentialChallenge
    } else if (handshake.handshakeOk && !toolsList.ok && toolsList.credentialChallenge !== undefined) {
      // Tools-list-layer credential-gate rule: the handshake
      // itself was fine (discovery_handshake / protocol_revision above already
      // carry their real results) but tools/list specifically is gated.
      //
      // Lead finding B6 (round 3): requires handshake.handshakeOk explicitly
      // — without it this branch also fires when the handshake itself
      // FAILED (e.g. a recognized modern JSON-RPC error in the discover
      // answer, or a legacy initialize that failed after the fallback) and tools/list
      // separately happens to be 401-challenged, which is one condition
      // wider than this rule's approved scope ("握手成功但 tools/list 响应
      // 满足判据"). A 401-challenged tools/list is arguably just as honestly
      // "unverifiable" regardless of what the handshake did, but widening the
      // branch would be a change to the approved spec, which is not this
      // fix's call to make. The code conforms to the approved spec; the
      // scoping observation is tracked internally for a future ruling.
      const reason: Reason = { key: 'credential_required', params: { scheme: toolsList.credentialChallenge.scheme } }
      A('tools_list', 'COMPLETED', 'UNVERIFIED', reason)
      skipToolsDerivedChecks(reason)
      probeCallWithheld = reason
      gateChallenge = toolsList.credentialChallenge
    } else if (toolsList.ok) {
      A('tools_list', 'COMPLETED', 'VERIFIED')

      const tools = toolsList.tools!
      if (listIncomplete) {
        // Suite 0.15.0: no fingerprint of part of a list, so no toolSnapshot
        // either (the probe stores one only with a toolset_fingerprint), and
        // nothing to compare with a baseline. Hygiene still reads every tool
        // that came in: what it found there is real, but finding nothing is
        // not a clean list.
        A('toolset_fingerprint', 'SKIPPED', 'UNVERIFIED', listIncomplete)
        A('schema_fingerprint', 'SKIPPED', 'UNVERIFIED', listIncomplete)
        const hygiene = runHygieneCheck(tools as { name: string; description?: string }[])
        if (hygiene.assertion_status === 'OBSERVED_RISK') A('tool_description_hygiene', 'COMPLETED', 'OBSERVED_RISK', hygiene.reason)
        else A('tool_description_hygiene', 'COMPLETED', 'UNVERIFIED', listIncomplete)
        A('toolset_unchanged_vs_approved', 'SKIPPED', 'UNVERIFIED', listIncomplete)
        A('schema_unchanged_vs_approved', 'SKIPPED', 'UNVERIFIED', listIncomplete)
      } else {
        toolSnapshot = await buildToolSnapshot(tools, now())

        const toolsetFp = await computeToolsetFingerprint(tools)
        // T73b: a FAILED verdict carries fingerprint.ts's bounded catalog key
        // (classified by error class; the raw canonicalizer message is never
        // kept), forwarded as the probe-level reason.
        A('toolset_fingerprint', 'COMPLETED', toolsetFp.status, toolsetFp.status === 'FAILED' ? toolsetFp.reason : null)

        const schemaFp = await computeSchemaFingerprint(tools)
        A('schema_fingerprint', 'COMPLETED', schemaFp.status, schemaFp.status === 'FAILED' ? schemaFp.reason : null)

        const hygiene = runHygieneCheck(tools as { name: string; description?: string }[])
        A('tool_description_hygiene', 'COMPLETED', hygiene.assertion_status, hygiene.assertion_status === 'OBSERVED_RISK' ? hygiene.reason : null)

        judgeBaselineCheck('toolset_unchanged_vs_approved', toolsetFp, approvedBaseline?.toolset_fingerprint, now, registry, A, driftEvents)
        judgeBaselineCheck('schema_unchanged_vs_approved', schemaFp, approvedBaseline?.schema_fingerprint, now, registry, A, driftEvents)
      }
    } else {
      A('tools_list', 'COMPLETED', 'FAILED', classified(toolsList.failure, 'tools_list'))
      skipToolsDerivedChecks({ key: 'tools_list_invalid_structure' })
      probeCallWithheld = { key: 'probe_tool_name_unverifiable' }
    }

    if (probeCallWithheld) {
      // T86: error_taxonomy reads only that call's response, so it did not
      // run. Written first, so the catch below never becomes its second
      // writer, even when the metadata fetch below aborts the run.
      A('error_taxonomy', 'SKIPPED', 'UNVERIFIED', probeCallWithheld)
      if (gateChallenge) {
        // T86b: the gate's own 401 challenge is the input; only its reason
        // key/params reach the assertion, never the header itself.
        // Suite 0.14.0: the same request on the same fetchImpl, which also keeps
        // the metadata document's bytes, as sendRequest reads them, for
        // auth_observation's digest.
        const metadata = keepLastOkBody(fetchImpl)
        const authVerdict = await judgeAuthMetadataFromGate({ fetchImpl: metadata.fetchImpl, budget, ctx, challenge: gateChallenge })
        A('auth_metadata', 'COMPLETED', authVerdict.status, authVerdict.status !== 'VERIFIED' ? authVerdict.reason : null)
        authObservation = (await authObservationOf(gateChallenge, metadata.lastOkBody())) ?? undefined
      } else {
        A('auth_metadata', 'SKIPPED', 'UNVERIFIED', probeCallWithheld)
      }
    } else {
      const callResult = await performUnknownToolCall({
        fetchImpl,
        budget,
        ctx,
        newId,
        handshake: { ...handshake, currentEndpoint: toolsList.currentEndpoint },
        toolName: PROBE_TOOL_NAME,
      })

      const taxonomy = judgeErrorTaxonomy(callResult)
      A('error_taxonomy', executionOf(taxonomy), taxonomy.status, taxonomy.status !== 'VERIFIED' ? taxonomy.reason : null)

      const authVerdict = await judgeAuthMetadata({ fetchImpl, budget, ctx, callResult })
      A('auth_metadata', executionOf(authVerdict), authVerdict.status, authVerdict.status !== 'VERIFIED' ? authVerdict.reason : null)
    }

    // DNS-answer-change is judged independently of redirect_policy: a changed DNS
    // answer is not a redirect, and folding it into redirect_policy would show
    // readers the wrong check_id for what was actually observed (see NEXT.md #1 —
    // no check_id in checks.json currently names "DNS answer changed mid-probe",
    // so it is deliberately not attached to any per-check assertion here; it only
    // affects disqualifiedFromPublication below, pending a registry decision).
    if (ctx.redirectCrossHostObserved) {
      A('redirect_policy', 'COMPLETED', 'OBSERVED_RISK', { key: 'redirect_cross_host_observed' })
    } else {
      A('redirect_policy', 'COMPLETED', 'VERIFIED')
    }
  } catch (e) {
    // Checks that already COMPLETED before the abort keep their result — "we
    // verified the handshake, then ran out of budget" is coherent and honest;
    // see this function's module doc. That now includes reachability itself
    // whenever the handshake got far enough to settle it, so every write below
    // is guarded by assertionsByCheckId: this block may only ever be the FIRST
    // writer of a check_id, never a second one.
    //
    // Two reasons, not one. reachabilityReason answers "why could we not tell
    // whether the endpoint answers"; cascadeReason answers "why did this later
    // check not run". They coincide for our own aborts and deliberately differ
    // for an arbitrary thrown error — see that branch.
    let reachabilityReason: Reason
    let cascadeReason: Reason
    const guardReason = guardErrorReason(e, budget, assertionsByCheckId.has('reachability'))
    if (e instanceof ProbeAborted) {
      // Our own budget-exhaustion abort — e.message is first-party generated
      // Chinese prose (useful for logs/stack traces, see wire.ts), never a
      // reader-facing reason. e.details carries the numeric facts instead, so
      // the per-code catalog key can render locale-correct copy from them
      // rather than leaking that prose verbatim into the params channel
      // (which is third-party-diagnostic-text only — see README's "Security
      // boundaries" section).
      const key = {
        MAX_REQUESTS: 'probe_budget_exhausted_requests',
        MAX_DURATION: 'probe_budget_exhausted_duration',
        MAX_REDIRECTS: 'probe_budget_exhausted_redirects',
        MAX_BODY_BYTES: 'probe_budget_exhausted_body',
        RATE_LIMITED: 'probe_rate_limited',
      }[e.code]
      // The same reason for both: for our own aborts the abort's real key +
      // numeric details ("this run stopped at its 8-request budget") is
      // strictly more informative on a never-ran check than the generic
      // probe_cascade_incomplete it used to be, and the approved copy for
      // these keys already ends in "— later checks did not run"
      // (reason-messages.ts), i.e. it was written for exactly this position.
      // The params MUST travel with the key: those renderers call requireParam
      // and THROW on a missing one, so a key-only cascade reason would fail at
      // render time on the report page rather than here.
      reachabilityReason = { key, params: e.details }
      cascadeReason = reachabilityReason
      // The scheduler's control signal, carried on its own typed field rather
      // than read back out of the reason above: reason.params is the localized
      // copy-rendering channel (see the comment on this catch block), and a
      // copy edit must never be able to quietly change how often we probe.
      if (e.code === 'RATE_LIMITED') {
        rateLimited = { retryAfterSeconds: e.retryAfterSeconds ?? null }
      }
    } else if (e instanceof OtherHostDeclined) {
      // A FetchLike wrapper refused, before any request, to contact a host
      // other than the endpoint's own (see other-host-declined.ts): our
      // decision, so never FAILED or OBSERVED_RISK. No params — the key names
      // neither the host nor why — so, like the branches around it, the
      // cascade carries the same reason.
      reachabilityReason = { key: 'probe_declined_other_host' }
      cascadeReason = reachabilityReason
    } else if (guardReason !== undefined) {
      // T85: an ssrf-guard error — classified by class / code, never message
      // (guardErrorReason). Its params are kind / code / budget numbers only,
      // bounded, so the cascade carries the same reason, as ProbeAborted's
      // does above; guardErrorReason already chose one that is true on a
      // never-ran row, given whether reachability is settled.
      reachabilityReason = guardReason
      cascadeReason = reachabilityReason
    } else {
      // Anything else — in production, one of our own wrapper errors (the
      // adapter's argument checks). Suite 0.15.0: only the error's class
      // reaches params (errorClassOf), never its message. Up to suite 0.14.0
      // the message was kept here, and a message is unbounded text that can
      // carry whatever the failing code put in it.
      //
      // The cascade keeps the generic probe_cascade_incomplete: the class names
      // what stopped the run, which is reachability's question, not why each
      // later check did not run.
      reachabilityReason = { key: 'probe_aborted', params: { error_class: errorClassOf(e) } }
      cascadeReason = { key: 'probe_cascade_incomplete' }
    }
    // Suite 0.15.0 (TODO 779 / 797): a cross-host redirect seen before the
    // abort was observed, whatever ended the run afterwards (another host
    // declined, a guard refusal, the redirect, request or time budget, the
    // server asking us to back off). redirect_policy records it as it does on
    // a run that finishes; only the checks that never ran take the abort's
    // reason below.
    if (ctx?.redirectCrossHostObserved && !assertionsByCheckId.has('redirect_policy')) {
      A('redirect_policy', 'COMPLETED', 'OBSERVED_RISK', { key: 'redirect_cross_host_observed' })
    }
    // Only ever the first writer: reachability is still unset here exactly
    // when the abort happened at or before the handshake. When it is already
    // set, it was set by the try block from a real HTTP response and a later
    // abort has no standing to revise it.
    if (!assertionsByCheckId.has('reachability')) {
      A('reachability', 'ERROR', 'UNVERIFIED', reachabilityReason)
    }
    cascadeRemaining('SKIPPED', cascadeReason)
  }

  return finalize()

  function finalize(): ProbeResult {
    // Closed-count guarantee: any registry check_id this implementation somehow
    // forgot to compute becomes an explicit ERROR, never a silent omission.
    for (const def of registry.checks) {
      if (!assertionsByCheckId.has(def.check_id)) {
        A(def.check_id, 'ERROR', 'UNVERIFIED', { key: 'check_not_implemented', params: { check_id: def.check_id } })
      }
    }
    // Checked here, not inline in the try block, so a DNS-answer-change observed
    // on an early request still disqualifies the run even if a later request
    // throws before the try block would otherwise have reached this check.
    if (ctx?.dnsAnswerChangedObserved) {
      disqualifiedFromPublication = { key: 'disqualified_dns_rebind' }
    }
    const assertions = registry.checks.map((def) => assertionsByCheckId.get(def.check_id)!)
    return {
      assertions,
      driftEvents,
      // null for stdio (ctx is never created — no DNS resolution happens for a
      // local process launch); a real boolean for remote, regardless of
      // whether this run later aborted.
      dnsAnswerChangedObserved: ctx?.dnsAnswerChangedObserved ?? null,
      protocolRevisionDeclared,
      probeOfferedRevision,
      ...(toolSnapshot ? { toolSnapshot } : {}),
      ...(disqualifiedFromPublication ? { disqualifiedFromPublication } : {}),
      ...(rateLimited ? { rateLimited } : {}),
      ...(authObservation ? { authObservation } : {}),
    }
  }
}
