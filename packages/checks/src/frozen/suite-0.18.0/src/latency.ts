import type { Assertion } from '@mcpcheckup/attestation-schema'

/** Suite 0.16.0 (latency_profile docs v0.3.0): what one run's requests to the
 *  endpoint showed about the time to their response headers. wire.ts's
 *  sendRequest fills it in (ProbeContext.latency); probe.ts reads it once, at
 *  the end of the run, through judgeLatency.
 *
 *  Only the protocol requests are counted: every one of them is a POST to the
 *  endpoint (protocol.ts), and a POST never follows a redirect (wire.ts). The
 *  one GET this package sends, auth.ts's fetch of the challenge's metadata
 *  document, is another resource, possibly on another host, and is never
 *  counted. */
export interface LatencyObservations {
  /** One entry per POST whose response headers arrived while the call still
   *  counted (it had not been abandoned at the run's deadline), in whole ms, as
   *  the FetchLike measured it and reported through
   *  GuardSignals.responseHeadersMs. */
  samplesMs: number[]
  /** POSTs whose FetchLike returned a Response without reporting a usable time
   *  for it: a FetchLike that does not time requests. The production FetchLike
   *  (the probe Worker's adapter over guardedFetch) times every call. */
  untimedResponses: number
}

/** What the timer covers, written into the signed params: from just before the
 *  request is sent until its response headers arrive (no DNS check, no body). */
export const LATENCY_TIMED_TO = 'response_headers'

/** A time a FetchLike may report: a whole, non-negative number of ms.
 *  Anything else is not recorded (the call then counts as untimed). */
export function isLatencySampleMs(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

/** Nearest-rank percentile: the value at rank ceil(percent / 100 × n) of the
 *  samples sorted in ascending order, so always one of the samples. With
 *  n ≤ 19, p95 is the largest. `percent` is an integer so that the rank is
 *  computed without a fractional factor (95 × n / 100 is exact whenever it is
 *  a whole number). */
export function nearestRank(sortedMs: readonly number[], percent: number): number {
  if (sortedMs.length === 0) throw new RangeError('nearestRank: no samples')
  if (!Number.isInteger(percent) || percent < 1 || percent > 100) throw new RangeError(`nearestRank: percent must be an integer in 1..100, got ${percent}`)
  const rank = Math.ceil((percent * sortedMs.length) / 100)
  return sortedMs[rank - 1]!
}

export interface LatencyVerdict {
  execution_status: Assertion['execution_status']
  assertion_status: Assertion['assertion_status']
  reason: { key: string; params?: Record<string, string | number> }
}

/** latency_profile for one run. VERIFIED means only that the time was
 *  measured; nothing here compares it with anything (observation_only).
 *  - `observations` undefined: no request was made at all (stdio) —
 *    latency_not_recorded, as in suites 0.12.0 to 0.15.0.
 *  - At least one sample on a run whose handshake stopped at a credential gate
 *    (`credentialGated`; probe.ts passes it for that gate only, the one an
 *    auth_gated payload signs): not recorded (latency_not_signed_auth_gated).
 *    An auth_gated payload requires every check outside the four it covers to
 *    be UNVERIFIED, so a VERIFIED row here would leave the run unsigned.
 *  - At least one sample otherwise: COMPLETED/VERIFIED latency_measured with
 *    p50_ms, p95_ms and n, always together, and timed_to.
 *  - No sample, but responses that were not timed: latency_not_recorded.
 *  - No sample and no response: latency_no_samples. */
export function judgeLatency(observations: LatencyObservations | undefined, credentialGated: boolean): LatencyVerdict {
  if (observations === undefined) return { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'latency_not_recorded' } }
  const sorted = [...observations.samplesMs].sort((a, b) => a - b)
  if (sorted.length > 0 && credentialGated) return { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'latency_not_signed_auth_gated' } }
  if (sorted.length > 0) {
    return {
      execution_status: 'COMPLETED',
      assertion_status: 'VERIFIED',
      reason: { key: 'latency_measured', params: { p50_ms: nearestRank(sorted, 50), p95_ms: nearestRank(sorted, 95), n: sorted.length, timed_to: LATENCY_TIMED_TO } },
    }
  }
  if (observations.untimedResponses > 0) return { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'latency_not_recorded' } }
  return { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'latency_no_samples' } }
}
