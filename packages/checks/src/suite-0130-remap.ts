/**
 * Test support for the differentials that hold the live probe against a frozen
 * older suite (suites 0.6.0 … 0.12.0): what suite 0.13.0 (TODO 217) changes
 * for EVERY run, written once, so each differential states "identical to the
 * frozen suite's run, after this translation and this remap" instead of
 * carrying its own copy of the rule.
 *
 * Suite 0.13.0 changes one value on the wire and adds one key to the result:
 *   - the legacy initialize fallback offers revision 2025-11-25 (older suites:
 *     2025-06-18): the initialize body's params.protocolVersion, and the
 *     mcp-protocol-version header of the legacy requests that follow when the
 *     server declared no version (protocol.ts sends `declared ?? offer`);
 *   - ProbeResult.probeOfferedRevision, right after protocolRevisionDeclared:
 *     the revision offered by the handshake request whose answer the run
 *     recorded, null when the handshake never returned.
 *
 * offerAsLive wraps the fetch an OLDER suite's run goes through. Given the
 * request sequence of the live run of the same input, it hands the target the
 * live run's request in place of the older suite's whenever the two differ in
 * exactly those two places (the old offer where the live run has the new
 * one), so the target answers both runs alike and the rest of the two runs
 * can be compared value for value. It changes nothing else: a request that
 * differs in any other way goes out as the older suite sent it, and the
 * differential then reports the difference. offerSubstitutionProblem checks
 * afterwards that a header was only ever replaced on a run whose server
 * declared no version (the only case in which the header is the offer).
 *
 * suite0130Remap reads the frozen suite's own result and the requests its run
 * sent, nothing from the implementation under test.
 */
import type { FetchLike, ProbeResult } from './types.ts'

/** The legacy initialize offer of suites up to 0.12.0, and of suite 0.13.0. */
export const LEGACY_OFFER_BEFORE_0130 = '2025-06-18'
export const LEGACY_OFFER_0130 = '2025-11-25'
/** The server/discover offer, unchanged. */
export const MODERN_OFFER = '2026-07-28'

/** One request as every differential's harness records it: [method, URL, the
 *  `name: value` header lines Headers iterates, body or null], JSON-encoded. */
export function recordRequest(input: RequestInfo | URL, init?: RequestInit): string {
  const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  const headers: string[] = []
  new Headers(init?.headers).forEach((value, key) => { headers.push(`${key}: ${value}`) })
  return JSON.stringify([init?.method ?? 'GET', href, headers, typeof init?.body === 'string' ? init.body : null])
}

const methodOfBody = (body: unknown): unknown => {
  if (typeof body !== 'string') return undefined
  try { return (JSON.parse(body) as { method?: unknown }).method } catch { return undefined }
}

/** The older suite's request with the new offer in it, if that is exactly the live request; else null. */
function asLive(init: RequestInit | undefined, old: string, live: string): { init: RequestInit; body: boolean; header: boolean } | null {
  const [om, oh, oHeaders, oBody] = JSON.parse(old) as [string, string, string[], string | null]
  const [lm, lh, lHeaders, lBody] = JSON.parse(live) as [string, string, string[], string | null]
  if (om !== lm || oh !== lh) return null
  let body = false
  let newBody = oBody
  if (oBody !== lBody) {
    if (oBody === null || methodOfBody(oBody) !== 'initialize') return null
    const parsed = JSON.parse(oBody) as { params?: { protocolVersion?: unknown } }
    if (parsed.params?.protocolVersion !== LEGACY_OFFER_BEFORE_0130) return null
    // Spread keeps protocolVersion where it was: the key exists, only its value changes.
    newBody = JSON.stringify({ ...parsed, params: { ...parsed.params, protocolVersion: LEGACY_OFFER_0130 } })
    if (newBody !== lBody) return null
    body = true
  }
  const oldHeader = `mcp-protocol-version: ${LEGACY_OFFER_BEFORE_0130}`
  const newHeader = `mcp-protocol-version: ${LEGACY_OFFER_0130}`
  let header = false
  const swapped = oHeaders.map((h, i) => (h === oldHeader && lHeaders[i] === newHeader ? ((header = true), newHeader) : h))
  if (swapped.length !== lHeaders.length || swapped.some((h, i) => h !== lHeaders[i])) return null
  if (!body && !header) return null
  const headers = new Headers(init?.headers)
  if (header) headers.set('mcp-protocol-version', LEGACY_OFFER_0130)
  const plain: Record<string, string> = {}
  headers.forEach((value, key) => { plain[key] = value })
  return { init: { ...init, headers: plain, ...(body ? { body: newBody! } : {}) }, body, header }
}

export interface OfferTranslator {
  fetchImpl: FetchLike
  /** How many requests went out with the new offer in the body / in the header instead of the older suite's. */
  substituted: () => { body: number; header: number }
}

/** Wraps `inner` (the older suite's transport). `live` is the live run's recorded request sequence for the same input; undefined = no translation. */
export function offerAsLive(inner: FetchLike, live: readonly string[] | undefined): OfferTranslator {
  let index = 0
  const counts = { body: 0, header: 0 }
  const fetchImpl: FetchLike = async (input, init, onGuardSignal, options) => {
    const liveRecord = live?.[index++]
    let sent = init
    if (liveRecord !== undefined) {
      const old = recordRequest(input, init)
      if (old !== liveRecord) {
        const swapped = asLive(init, old, liveRecord)
        if (swapped) {
          sent = swapped.init
          if (swapped.body) counts.body++
          if (swapped.header) counts.header++
        }
      }
    }
    return inner(input, sent, onGuardSignal, options)
  }
  return { fetchImpl, substituted: () => ({ ...counts }) }
}

/** A header carries the offer only where the server declared no version; anywhere else a replaced header is a real difference. */
export function offerSubstitutionProblem(old: ProbeResult, substituted: { header: number }): string | null {
  return substituted.header > 0 && old.protocolRevisionDeclared !== null
    ? `the mcp-protocol-version header was replaced ${substituted.header} time(s) on a run whose server declared ${old.protocolRevisionDeclared}`
    : null
}

/** The value suite 0.13.0 records, read off the older suite's run: null unless the handshake returned — every suite
 *  records reachability COMPLETED/VERIFIED on the line before it sets protocolRevisionDeclared, and the catch never
 *  overwrites it — and then the legacy offer if the run sent an initialize (performHandshake returns 'legacy' exactly
 *  when it fell back to one), else the modern offer. */
export function offeredRevisionOf(old: ProbeResult, oldRequests: readonly string[]): string | null {
  const reach = old.assertions.find((a) => a.check_id === 'reachability')
  if (!(reach?.execution_status === 'COMPLETED' && reach.assertion_status === 'VERIFIED')) return null
  const sentInitialize = oldRequests.some((r) => methodOfBody((JSON.parse(r) as unknown[])[3]) === 'initialize')
  return sentInitialize ? LEGACY_OFFER_0130 : MODERN_OFFER
}

/** A copy of an older suite's result as suite 0.13.0 has it: probeOfferedRevision inserted right after
 *  protocolRevisionDeclared, every other own key and its order left exactly as they were. */
export function suite0130Remap(old: ProbeResult, oldRequests: readonly string[]): ProbeResult {
  if (!Object.hasOwn(old, 'protocolRevisionDeclared')) throw new Error('suite0130Remap: the older result has no protocolRevisionDeclared to place the offer after')
  if (Object.hasOwn(old, 'probeOfferedRevision')) throw new Error('suite0130Remap: the older result already carries probeOfferedRevision')
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(structuredClone(old))) {
    out[k] = v
    if (k === 'protocolRevisionDeclared') out.probeOfferedRevision = offeredRevisionOf(old, oldRequests)
  }
  return out as unknown as ProbeResult
}
