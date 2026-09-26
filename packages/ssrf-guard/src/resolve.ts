import { encodeQuery, decodeResponse, QTYPE_A, QTYPE_AAAA, QTYPE_TXT } from './dns-wire.ts'
import { classifyIp } from './ip-policy.ts'
import { SsrfBlocked } from './errors.ts'

/**
 * Hardcoded to Cloudflare's own resolver, deliberately not configurable. We already
 * fully trust Cloudflare's network to run this code and terminate the actual outbound
 * TLS connection — trusting their resolver for name lookups adds no new trust boundary
 * beyond what already exists, and it's the same resolver their own nodejs_compat
 * `node:dns` shim uses. Making this configurable would let a caller point the guard at
 * an untrusted resolver, which defeats the point of the guard. See README.
 */
export const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query' // scan-secrets-allow: real Cloudflare DoH endpoint, this package's fixed resolver

export interface ResolvedAddress {
  ip: string
  family: 4 | 6
}

/** Each DoH request's own bound (T85 PR-1b, R16). The request and its answer-body read share
 *  one AbortSignal.timeout; an abort lands in the existing catch (request) or decode try (body)
 *  as RESOLVER_UNAVAILABLE — no new throw site, no new code. Both of resolveHost's queries are
 *  bounded, so its allSettled failure path is bounded. 3 s is below wire's per-request budget:
 *  maxDurationMs 10,000 (budget.ts), at most two resolveHost calls per hop (before the fetch,
 *  then checkDnsAnswerChanged) = 6 s, leaving >= 4 s for the target. With < 3 s of run budget
 *  left, wire's deadline may fire first (probe_budget_exhausted_duration), as today.
 *  The README states this value as "3 s": change both together. */
export const DOH_TIMEOUT_MS = 3_000

export interface DnsDeps {
  fetchImpl?: typeof fetch
  /** Test injection only; production always uses DOH_TIMEOUT_MS. */
  timeoutMs?: number
}

/** Two codes, split by whose side failed (T85). RESOLVER_UNAVAILABLE: our own DoH
 *  resolver could not be asked (transport error, non-200, an answer whose body could
 *  not be read or decoded, no answer within the timeout).
 *  RESOLUTION_FAILED: the resolver answered, and the name does not resolve (a
 *  non-zero RCODE, or no A/AAAA record). Both reject; neither allows anything. */
async function queryOne(hostname: string, qtype: number, fetchImpl: typeof fetch, timeoutMs: number): Promise<{ rcode: number; ips: string[] }> {
  const query = encodeQuery(hostname, qtype, 0)
  let response: Response
  try {
    response = await fetchImpl(DOH_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: query,
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (cause) {
    throw new SsrfBlocked('RESOLVER_UNAVAILABLE', `DoH request to our own resolver failed: ${(cause as Error).message}`)
  }
  if (!response.ok) {
    throw new SsrfBlocked('RESOLVER_UNAVAILABLE', `DoH resolver returned HTTP ${response.status}`)
  }
  let decoded: ReturnType<typeof decodeResponse>
  try {
    // The body read is our resolver's answer arriving, so it fails the same way (T85).
    decoded = decodeResponse(new Uint8Array(await response.arrayBuffer()))
  } catch (cause) {
    throw new SsrfBlocked('RESOLVER_UNAVAILABLE', `DoH resolver returned an unparseable response: ${(cause as Error).message}`)
  }
  if (decoded.rcode !== 0) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DNS resolution failed with RCODE ${decoded.rcode}`)
  }
  return { rcode: decoded.rcode, ips: decoded.answers.filter((a) => a.type === qtype).map((a) => a.ip!) }
}

/** Resolves both A and AAAA records for hostname via Cloudflare's DoH wireformat API.
 *  Fails closed: any transport error, non-200, decode error, or non-NOERROR RCODE on
 *  either query rejects the whole call — a hostname with no addresses at all rejects too,
 *  since there is then nothing valid to connect to. Which failure is thrown is a fixed rule
 *  (T85), not settle order: an RCODE answer (RESOLUTION_FAILED) beats a non-answer, else A's
 *  error, else AAAA's. Cost: a failure waits for both queries, each bounded by DOH_TIMEOUT_MS. */
export async function resolveHost(hostname: string, deps: DnsDeps = {}): Promise<ResolvedAddress[]> {
  const fetchImpl = deps.fetchImpl ?? fetch
  const timeoutMs = deps.timeoutMs ?? DOH_TIMEOUT_MS
  const [a, aaaa] = await Promise.allSettled([queryOne(hostname, QTYPE_A, fetchImpl, timeoutMs), queryOne(hostname, QTYPE_AAAA, fetchImpl, timeoutMs)])
  const failed = [a, aaaa].flatMap((r) => (r.status === 'rejected' ? [r.reason as unknown] : []))
  if (a.status === 'rejected' || aaaa.status === 'rejected') throw failed.find((e) => e instanceof SsrfBlocked && e.code === 'RESOLUTION_FAILED') ?? failed[0]
  const addresses: ResolvedAddress[] = [
    ...a.value.ips.map((ip): ResolvedAddress => ({ ip, family: 4 })),
    ...aaaa.value.ips.map((ip): ResolvedAddress => ({ ip, family: 6 })),
  ]
  if (addresses.length === 0) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `${hostname} has no A or AAAA records`)
  }
  return addresses
}

/** Throws SsrfBlocked on the first disallowed address — any one bad address rejects the
 *  whole set, per policy: a multi-homed name is only as trustworthy as its worst answer. */
export function validateAddresses(addresses: ResolvedAddress[]): void {
  for (const { ip, family } of addresses) {
    const verdict = classifyIp(ip, family)
    if (verdict.blocked) {
      throw new SsrfBlocked(verdict.code, `${ip} is ${verdict.description}`)
    }
  }
}

export async function resolveAndValidateHost(hostname: string, deps: DnsDeps = {}): Promise<ResolvedAddress[]> {
  const addresses = await resolveHost(hostname, deps)
  validateAddresses(addresses)
  return addresses
}

/** Queries TXT records for hostname via the same fixed DoH resolver as resolveHost().
 *
 *  Deliberately NOT fail-closed the way resolveHost() is: for A/AAAA, "no address"
 *  means there is nothing to connect to, so rejecting is right. For TXT, "no record"
 *  is an ordinary, expected answer — the record simply has not been published yet —
 *  and the caller needs to tell that apart from "we could not ask". So NXDOMAIN and
 *  an empty answer set both return [], while a transport/decode failure or a timeout throws
 *  SsrfBlocked('RESOLVER_UNAVAILABLE') and any other non-zero RCODE
 *  SsrfBlocked('RESOLUTION_FAILED').
 *
 *  No IP validation applies here: a TXT lookup never produces an address to connect
 *  to, so there is nothing for classifyIp() to judge. */
export async function resolveTxt(hostname: string, deps: DnsDeps = {}): Promise<string[]> {
  const fetchImpl = deps.fetchImpl ?? fetch
  const timeoutMs = deps.timeoutMs ?? DOH_TIMEOUT_MS
  let response: Response
  try {
    response = await fetchImpl(DOH_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: encodeQuery(hostname, QTYPE_TXT, 0),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (cause) {
    throw new SsrfBlocked('RESOLVER_UNAVAILABLE', `DoH request to our own resolver failed: ${(cause as Error).message}`)
  }
  if (!response.ok) {
    throw new SsrfBlocked('RESOLVER_UNAVAILABLE', `DoH resolver returned HTTP ${response.status}`)
  }
  let decoded: ReturnType<typeof decodeResponse>
  try {
    decoded = decodeResponse(new Uint8Array(await response.arrayBuffer()))
  } catch (cause) {
    throw new SsrfBlocked('RESOLVER_UNAVAILABLE', `DoH resolver returned an unparseable response: ${(cause as Error).message}`)
  }
  // NXDOMAIN(3) and NOERROR-with-no-answers are both "not published yet", not failures.
  if (decoded.rcode === 3) return []
  if (decoded.rcode !== 0) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DNS resolution failed with RCODE ${decoded.rcode}`)
  }
  return decoded.answers.filter((a) => a.type === QTYPE_TXT && a.text !== undefined).map((a) => a.text!)
}
