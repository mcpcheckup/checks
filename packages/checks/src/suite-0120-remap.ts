/**
 * Test support for the differentials that hold the live probe against a frozen
 * older suite (suites 0.6.0 … 0.11.0): what suite 0.12.0 changes for EVERY run,
 * written once, so each differential states "identical to the frozen suite's
 * run, after this remap" instead of carrying its own copy of the rule.
 *
 * Suite 0.12.0 stops recording VERIFIED for three checks that observed nothing:
 *   - latency_profile: never run on any branch, so it is SKIPPED/UNVERIFIED
 *     latency_not_recorded on every run (older suites: COMPLETED/VERIFIED once
 *     the handshake returned, or the cascade's own reason before that).
 *   - auth_metadata: a tools/call answer that is not a 401 carries no challenge,
 *     so it is SKIPPED/UNVERIFIED auth_no_challenge_observed (older suites:
 *     COMPLETED/VERIFIED).
 *   - error_taxonomy: a tools/call answered 401 or 403 returned no protocol
 *     error, so it is SKIPPED/UNVERIFIED error_shape_not_observed (older
 *     suites: COMPLETED/VERIFIED).
 * All three are SKIPPED, not COMPLETED: there was nothing for the check to look
 * at, which keeps them out of the badge fold (it drops SKIPPED rows).
 *
 * The remap reads two things and nothing from the implementation under test:
 * the frozen suite's own ProbeResult, and the HTTP status the harness saw on the
 * reserved-name tools/call (recordToolsCallStatus). A row is rewritten only when
 * the frozen suite wrote the VERIFIED this change takes away, so an input on
 * which the frozen suite already had something else to say is left alone.
 */
import type { Assertion } from '@mcpcheckup/attestation-schema'
import type { FetchLike, ProbeResult } from './types.ts'

export interface ToolsCallRecorder {
  fetchImpl: FetchLike
  /** The status of the answer to the tools/call, or null if none was sent or answered. */
  toolsCallStatus: () => number | null
}

/** Wraps `inner` and remembers the HTTP status of the answer to the one request
 *  whose JSON-RPC method is tools/call (the probe's reserved-name call). */
export function recordToolsCallStatus(inner: FetchLike): ToolsCallRecorder {
  let status: number | null = null
  const fetchImpl: FetchLike = async (input, init, onGuardSignal, options) => {
    const res = await inner(input, init, onGuardSignal, options)
    if (typeof init?.body === 'string' && init.body.includes('"method":"tools/call"')) status = res.status
    return res
  }
  return { fetchImpl, toolsCallStatus: () => status }
}

function notObserved(a: Assertion, key: string): void {
  a.execution_status = 'SKIPPED'
  a.assertion_status = 'UNVERIFIED'
  a.reason = { key }
  a.unverified_reason = { key }
}

const completedVerified = (a: Assertion) => a.execution_status === 'COMPLETED' && a.assertion_status === 'VERIFIED'

/** A copy of a frozen suite's result as suite 0.12.0 would have it (see the
 *  module doc). `toolsCallStatus` is what recordToolsCallStatus saw on the run
 *  that produced `old`. Own keys and their order are left exactly as they were. */
export function suite0120Remap(old: ProbeResult, toolsCallStatus: number | null): ProbeResult {
  const out = structuredClone(old)
  for (const a of out.assertions) {
    if (a.check_id === 'latency_profile') notObserved(a, 'latency_not_recorded')
    else if (a.check_id === 'auth_metadata' && completedVerified(a) && toolsCallStatus !== null && toolsCallStatus !== 401) notObserved(a, 'auth_no_challenge_observed')
    else if (a.check_id === 'error_taxonomy' && completedVerified(a) && (toolsCallStatus === 401 || toolsCallStatus === 403)) notObserved(a, 'error_shape_not_observed')
  }
  return out
}
