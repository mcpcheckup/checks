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

export interface DnsDeps {
  fetchImpl?: typeof fetch
}

async function queryOne(hostname: string, qtype: number, fetchImpl: typeof fetch): Promise<{ rcode: number; ips: string[] }> {
  const query = encodeQuery(hostname, qtype, 0)
  let response: Response
  try {
    response = await fetchImpl(DOH_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: query,
    })
  } catch (cause) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DoH request to our own resolver failed: ${(cause as Error).message}`)
  }
  if (!response.ok) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DoH resolver returned HTTP ${response.status}`)
  }
  const bytes = new Uint8Array(await response.arrayBuffer())
  let decoded: ReturnType<typeof decodeResponse>
  try {
    decoded = decodeResponse(bytes)
  } catch (cause) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DoH resolver returned an unparseable response: ${(cause as Error).message}`)
  }
  if (decoded.rcode !== 0) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DNS resolution failed with RCODE ${decoded.rcode}`)
  }
  return { rcode: decoded.rcode, ips: decoded.answers.filter((a) => a.type === qtype).map((a) => a.ip!) }
}

/** Resolves both A and AAAA records for hostname via Cloudflare's DoH wireformat API.
 *  Fails closed: any transport error, non-200, decode error, or non-NOERROR RCODE on
 *  either query rejects the whole call — a hostname with no addresses at all rejects too,
 *  since there is then nothing valid to connect to. */
export async function resolveHost(hostname: string, deps: DnsDeps = {}): Promise<ResolvedAddress[]> {
  const fetchImpl = deps.fetchImpl ?? fetch
  const [a, aaaa] = await Promise.all([queryOne(hostname, QTYPE_A, fetchImpl), queryOne(hostname, QTYPE_AAAA, fetchImpl)])
  const addresses: ResolvedAddress[] = [
    ...a.ips.map((ip): ResolvedAddress => ({ ip, family: 4 })),
    ...aaaa.ips.map((ip): ResolvedAddress => ({ ip, family: 6 })),
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
 *  an empty answer set both return [], while a transport/decode failure still throws
 *  SsrfBlocked('RESOLUTION_FAILED').
 *
 *  No IP validation applies here: a TXT lookup never produces an address to connect
 *  to, so there is nothing for classifyIp() to judge. */
export async function resolveTxt(hostname: string, deps: DnsDeps = {}): Promise<string[]> {
  const fetchImpl = deps.fetchImpl ?? fetch
  let response: Response
  try {
    response = await fetchImpl(DOH_ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message' },
      body: encodeQuery(hostname, QTYPE_TXT, 0),
    })
  } catch (cause) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DoH request to our own resolver failed: ${(cause as Error).message}`)
  }
  if (!response.ok) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DoH resolver returned HTTP ${response.status}`)
  }
  let decoded: ReturnType<typeof decodeResponse>
  try {
    decoded = decodeResponse(new Uint8Array(await response.arrayBuffer()))
  } catch (cause) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DoH resolver returned an unparseable response: ${(cause as Error).message}`)
  }
  // NXDOMAIN(3) and NOERROR-with-no-answers are both "not published yet", not failures.
  if (decoded.rcode === 3) return []
  if (decoded.rcode !== 0) {
    throw new SsrfBlocked('RESOLUTION_FAILED', `DNS resolution failed with RCODE ${decoded.rcode}`)
  }
  return decoded.answers.filter((a) => a.type === QTYPE_TXT && a.text !== undefined).map((a) => a.text!)
}
