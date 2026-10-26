/**
 * Test support for suite 0.16.0, used by the differentials that hold the live
 * probe against a frozen older suite.
 *
 * Suite 0.16.0 changes one row: latency_profile (latency.ts). It is measured
 * from the times a FetchLike reports through GuardSignals.responseHeadersMs.
 * No differential's transport reports one, so on their inputs the row is what
 * suites 0.12.0 to 0.15.0 wrote, SKIPPED/UNVERIFIED latency_not_recorded,
 * except on a run in which no POST got a Response at all: there it is
 * SKIPPED/UNVERIFIED latency_no_samples. Whether one did is read off the
 * transcript (recordSuite0160): a POST whose call resolved with a Response.
 * Nothing else changes, on the wire or in the result; probe-latency.test.ts
 * and suite-0160-differential.test.ts prove that, also with a timing transport.
 *
 * recordSuite0160 / suite0160Remap stand in for recordSuite0150 /
 * suite0150Remap: they record and apply the suite 0.15.0 rules first, then
 * this one. The remap reads the frozen suite's own result and what the
 * transport did on that run, nothing from the implementation under test.
 */
import { recordSuite0150, suite0150Remap } from './suite-0150-remap.ts'
import type { Suite0150Observed } from './suite-0150-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

export interface Suite0160Observed extends Suite0150Observed {
  /** A POST whose call resolved with a Response. */
  postAnswered: boolean
}

export interface Suite0160Recorder {
  fetchImpl: FetchLike
  observed: () => Suite0160Observed
}

/** recordSuite0150 around `inner`, and, outside it, whether a POST was answered. */
export function recordSuite0160(inner: FetchLike): Suite0160Recorder {
  const suite0150 = recordSuite0150(inner)
  let postAnswered = false
  const fetchImpl: FetchLike = async (input, init, onGuardSignal, options) => {
    const response = await suite0150.fetchImpl(input, init, onGuardSignal, options)
    if ((init?.method ?? 'GET').toUpperCase() === 'POST') postAnswered = true
    return response
  }
  return { fetchImpl, observed: () => ({ ...suite0150.observed(), postAnswered }) }
}

/** A copy of a suite 0.15.0 result (or an older one already remapped to it, the
 *  suite 0.15.0 rules included: they are applied here first) as suite 0.16.0
 *  computes it for a transport that reports no time. Throws when the
 *  latency_profile row is not the one suites 0.12.0 to 0.15.0 wrote. */
export function suite0160Remap(old: ProbeResult, seen: Suite0160Observed): ProbeResult {
  return latency0160Remap(suite0150Remap(old, seen), seen.postAnswered)
}

/** The suite 0.16.0 rule alone, on a copy: for a result that already has every
 *  other suite 0.16.0 rule (wire-budget-differential.test.ts runs the live
 *  probe.ts over a frozen wire.ts that keeps no times). */
export function latency0160Remap(old: ProbeResult, postAnswered: boolean): ProbeResult {
  const out = structuredClone(old)
  const rows = out.assertions.filter((a) => a.check_id === 'latency_profile')
  if (rows.length !== 1) throw new Error(`suite0160Remap: ${rows.length} latency_profile rows`)
  const row = rows[0]!
  if (!(row.execution_status === 'SKIPPED' && row.assertion_status === 'UNVERIFIED' && row.reason?.key === 'latency_not_recorded' && row.reason.params === undefined && row.unverified_reason?.key === 'latency_not_recorded')) {
    throw new Error(`suite0160Remap: latency_profile is ${row.execution_status}/${row.assertion_status} ${row.reason?.key}, not the 0.15.0 row`)
  }
  if (!postAnswered) {
    row.reason = { key: 'latency_no_samples' }
    row.unverified_reason = { key: 'latency_no_samples' }
  }
  return out
}
