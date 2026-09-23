// FROZEN: packages/checks/src/probe.ts at suite 0.6.0 (a05097e), verbatim except that
// FROZEN: imports of files outside this directory go through ../../ instead of ./ .
// FROZEN: Test-only baseline for probe-tool-name-differential.test.ts, which checks
// FROZEN: its git blob id. DO NOT edit or "update" it; it is the 0.6.0 behaviour.
import { assertUnverifiedHasReason } from '@mcpcheckup/attestation-schema'
import type { Assertion } from '@mcpcheckup/attestation-schema'

type ExecutionStatus = Assertion['execution_status']
import { runHygieneCheck } from '../../hygiene.ts'
import { createProbeContext, ProbeAborted } from '../../wire.ts'
import type { ProbeContext } from '../../wire.ts'
import { performHandshake, performToolsList, performUnknownToolCall } from './protocol.ts'
import { judgeAuthMetadata } from '../../auth.ts'
import { judgeErrorTaxonomy } from './error-taxonomy.ts'
import { computeToolsetFingerprint, computeSchemaFingerprint, buildToolSnapshot } from '../../fingerprint.ts'
import type { FingerprintVerdict } from '../../fingerprint.ts'
import type { CheckDefinition, ChecksRegistry } from '../../registry.ts'
import type { DriftEvent, EvidenceProvenance, ProbeInput, ProbeResult } from '../../types.ts'

/** A name no real business tool would ever use — the protocol-level, non-destructive
 *  way error_taxonomy and auth_metadata trigger a safe error scenario. Never a
 *  business tool call (CLAUDE.md / checks.json's own `forbidden` list). */
const PROBE_TOOL_NAME = '__mcpcheckup_probe_nonexistent_tool__'

type Reason = { key: string; params?: Record<string, string | number> } | null

type AssertionBuilder = (
  check_id: string,
  execution_status: ExecutionStatus,
  assertion_status: Assertion['assertion_status'],
  reason?: Reason,
) => void

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
 *  tls_certificate) = SKIPPED/UNVERIFIED carrying the abort's own reason.
 *  Checks that already COMPLETED before the abort keep whatever result they
 *  earned — "we verified the protocol handshake, then ran out of budget" is a
 *  coherent, honest statement; discarding an already-verified observation would
 *  itself be a form of the same dishonesty this four-state model exists to
 *  avoid (see response-exceeds-budget in the fixture corpus, and the README's
 *  "cascading failure" section). This package makes no attempt to distinguish
 *  "the target is genuinely down" from "our own probe broke" — see README for
 *  why that distinction isn't safely derivable from a generic FetchLike without
 *  coupling to ssrf-guard's specific error types. */
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
  // Set ONLY from the catch block's RATE_LIMITED branch — its presence is the
  // whole signal ("this run stopped because the target asked us to come back
  // later"), so it must never be set speculatively anywhere else.
  let rateLimited: ProbeResult['rateLimited']

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
    A('latency_profile', 'COMPLETED', 'VERIFIED')

    // Always run tools/list, in both cascade branches: the probe budget and
    // request count are unchanged by this feature, and performUnknownToolCall
    // below still needs toolsList.currentEndpoint regardless of how the
    // tools_list assertion itself gets judged.
    const toolsList = await performToolsList({ fetchImpl, budget, ctx, newId, handshake })

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
    } else if (handshake.handshakeOk && !toolsList.ok && toolsList.credentialChallenge !== undefined) {
      // Tools-list-layer credential-gate rule: the handshake
      // itself was fine (discovery_handshake / protocol_revision above already
      // carry their real results) but tools/list specifically is gated.
      //
      // Lead finding B6 (round 3): requires handshake.handshakeOk explicitly
      // — without it this branch also fires when the handshake itself
      // FAILED (e.g. the discover.status===200-but-malformed-supportedVersions
      // shape, or a recognized modern JSON-RPC error) and tools/list
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
    } else if (toolsList.ok) {
      A('tools_list', 'COMPLETED', 'VERIFIED')

      const tools = toolsList.tools!
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
    } else {
      A('tools_list', 'COMPLETED', 'FAILED', classified(toolsList.failure, 'tools_list'))
      skipToolsDerivedChecks({ key: 'tools_list_invalid_structure' })
    }

    const callResult = await performUnknownToolCall({
      fetchImpl,
      budget,
      ctx,
      newId,
      handshake: { ...handshake, currentEndpoint: toolsList.currentEndpoint },
      toolName: PROBE_TOOL_NAME,
    })

    const taxonomy = judgeErrorTaxonomy(callResult)
    A('error_taxonomy', 'COMPLETED', taxonomy.status, taxonomy.status === 'OBSERVED_RISK' ? taxonomy.reason : null)

    const authVerdict = await judgeAuthMetadata({ fetchImpl, budget, ctx, callResult })
    A('auth_metadata', 'COMPLETED', authVerdict.status, authVerdict.status !== 'VERIFIED' ? authVerdict.reason : null)

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
    } else {
      // Not one of our own budget aborts — a genuine other exception (e.g. a
      // fetch-level failure). Its message really is third-party/system text,
      // so it legitimately belongs in params here, unlike ProbeAborted above.
      //
      // Deliberately NOT promoted into cascadeReason, unlike the ProbeAborted
      // branch: `message` is an unbounded third-party/system string, and the
      // cascade writes its reason onto every check that never ran (up to 13 of
      // them) in a payload that gets canonicalized and signed. One copy of an
      // unbounded string is a diagnostic; thirteen is a size amplifier with no
      // extra information in it. ProbeAborted's details are a small numeric
      // record and carry no such risk, which is why that branch does promote.
      const message = e instanceof Error ? e.message : String(e)
      reachabilityReason = { key: 'probe_aborted', params: { message } }
      cascadeReason = { key: 'probe_cascade_incomplete' }
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
      ...(toolSnapshot ? { toolSnapshot } : {}),
      ...(disqualifiedFromPublication ? { disqualifiedFromPublication } : {}),
      ...(rateLimited ? { rateLimited } : {}),
    }
  }
}
