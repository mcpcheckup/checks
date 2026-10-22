/**
 * Test support for suite 0.15.0, used by the differentials that hold the live
 * probe against a frozen older suite.
 *
 * Suite 0.15.0 changes three things a run can show:
 *   1. tools/list follows nextCursor. On an input whose tools/list answers carry
 *      no nextCursor, and no single page of more than MAX_TOOLS_LISTED (5,000)
 *      tools (now cut there and incomplete; no fixture has one), nothing changes,
 *      on the wire or in the result. On an input
 *      whose first page does carry one the live run sends further pages and
 *      judges a longer (or incomplete) list, so no remap of the older run can
 *      stand for it: pagedToolsList(requests) names those runs, the older
 *      differentials set them aside (counted), and suite-0150-differential.test.ts
 *      proves them against an oracle of its own.
 *   2. redirect_policy: when a cross-host redirect was seen before the run
 *      aborted, it is COMPLETED/OBSERVED_RISK redirect_cross_host_observed (as on a
 *      run that finishes) instead of the abort's cascade reason. Up to suite 0.14.0
 *      the cascade took it. Whether one was seen is read off the transcript
 *      (recordSuite0150): a 3xx answer whose Location resolves to a host other than
 *      the one its request chain started on, by wire.ts's rule, including the hop
 *      that goes over the redirect budget (0.15.0 reads its Location first).
 *   3. probe_aborted: params { error_class } (the thrown value's constructor name)
 *      in place of { message }. The class is that of the error the transport threw,
 *      as recordSuite0150 saw it.
 *
 * The remap reads the frozen suite's own result and what the transport did on
 * that run, nothing from the implementation under test.
 */
import type { Assertion } from '@mcpcheckup/attestation-schema'
import type { FetchLike, ProbeResult } from './types.ts'

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

export interface Suite0150Observed {
  /** A 3xx whose Location left the host its request chain started on. */
  crossHostRedirect: boolean
  /** The constructor name of the last value the transport threw, or null. */
  thrownClass: string | null
}

export interface Suite0150Recorder {
  fetchImpl: FetchLike
  observed: () => Suite0150Observed
}

const hrefOf = (input: RequestInfo | URL): string => (typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)

/** Wraps `inner` and records, over the whole run, what suite0150Remap reads.
 *  A request continues a redirect chain when the answer before it was a 3xx
 *  with a Location, to a GET, and it is a GET to exactly that Location (wire.ts
 *  follows only a GET's redirects, one call per hop); any other request starts
 *  a chain on its own host. */
export function recordSuite0150(inner: FetchLike): Suite0150Recorder {
  let crossHostRedirect = false
  let thrownClass: string | null = null
  let follow: string | null = null
  let chainHost = ''
  const fetchImpl: FetchLike = async (input, init, onGuardSignal, options) => {
    const href = hrefOf(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    if (!(method === 'GET' && follow === href)) chainHost = new URL(href).hostname
    follow = null
    let res: Response
    try {
      res = await inner(input, init, onGuardSignal, options)
    } catch (e) {
      thrownClass = (e as { constructor?: { name?: string } } | null)?.constructor?.name ?? String(e)
      throw e
    }
    const location = res.headers.get('location')
    if (REDIRECT_STATUSES.has(res.status) && location) {
      let next: URL | null = null
      try { next = new URL(location, href) } catch { next = null }
      if (next !== null) {
        if (next.hostname !== chainHost) crossHostRedirect = true
        if (method === 'GET') follow = next.href
      }
    }
    return res
  }
  return { fetchImpl, observed: () => ({ crossHostRedirect, thrownClass }) }
}

/** True when the run asked for a further tools/list page: a recorded request
 *  (recordRequest's [method, URL, headers, body] JSON) whose body is a
 *  tools/list call with a `cursor` param. */
export function pagedToolsList(requests: readonly string[]): boolean {
  return requests.some((r) => {
    const body = (JSON.parse(r) as [string, string, string[], string | null])[3]
    if (body === null) return false
    try {
      const call = JSON.parse(body) as { method?: unknown; params?: unknown }
      return call.method === 'tools/list' && typeof call.params === 'object' && call.params !== null && Object.hasOwn(call.params, 'cursor')
    } catch {
      return false
    }
  })
}

function observedRisk(a: Assertion): void {
  if (a.execution_status !== 'SKIPPED' || a.assertion_status !== 'UNVERIFIED') {
    throw new Error(`suite0150Remap: a cross-host redirect was seen, but redirect_policy is ${a.execution_status}/${a.assertion_status}, not an abort's cascade`)
  }
  a.execution_status = 'COMPLETED'
  a.assertion_status = 'OBSERVED_RISK'
  a.reason = { key: 'redirect_cross_host_observed' }
  a.unverified_reason = null
}

/** A copy of a suite 0.14.0 result (or an older one already remapped to it) as
 *  suite 0.15.0 computes it, for an input whose tools/list carried no
 *  nextCursor (see the module doc). Own keys and their order are left as they
 *  were. Throws where the result and the transcript disagree. */
export function suite0150Remap(old: ProbeResult, seen: Suite0150Observed): ProbeResult {
  const out = structuredClone(old)
  for (const a of out.assertions) {
    if (a.check_id === 'redirect_policy' && seen.crossHostRedirect && a.assertion_status !== 'OBSERVED_RISK') observedRisk(a)
    const params = a.reason?.params
    if (a.reason?.key === 'probe_aborted' && params && Object.hasOwn(params, 'message')) {
      if (seen.thrownClass === null) throw new Error('suite0150Remap: probe_aborted { message } on a run whose transport threw nothing')
      a.reason = { key: 'probe_aborted', params: { error_class: seen.thrownClass } }
      if (a.unverified_reason !== null) a.unverified_reason = { key: 'probe_aborted', params: { error_class: seen.thrownClass } }
    }
  }
  return out
}
