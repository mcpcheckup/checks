export type IpBlockCode =
  | 'PRIVATE_USE'
  | 'LOOPBACK'
  | 'LINK_LOCAL'
  | 'CLOUD_METADATA'
  | 'THIS_NETWORK'
  | 'CGNAT'
  | 'DOCUMENTATION'
  | 'BENCHMARKING'
  | 'MULTICAST'
  | 'RESERVED'
  | 'UNIQUE_LOCAL'
  | 'UNSPECIFIED'
  | 'MALFORMED'
  | 'PROTOCOL_ASSIGNMENT'
  | 'DEPRECATED'
  | 'NAT64'
  | 'IPV4_COMPATIBLE'
  | 'SIX_TO_FOUR'
  | 'TEREDO'
  | 'DISCARD_ONLY'
  | 'DUMMY_PREFIX'
  | 'SEGMENT_ROUTING'
  | 'SITE_LOCAL'

export type IpVerdict = { blocked: false } | { blocked: true; code: IpBlockCode; description: string }

const ALLOWED: IpVerdict = { blocked: false }

function block(code: IpBlockCode, description: string): IpVerdict {
  return { blocked: true, code, description }
}

/**
 * One row of a range table. The tables below are taken from the IANA IPv4 and IPv6
 * Special-Purpose Address Registries (both "Last Updated 2025-10-09", as retrieved on
 * 2026-10-09): every entry whose "Globally Reachable" is False is a blocking row. A row
 * with `code: null` is a registry entry whose "Globally Reachable" is True; it blocks
 * nothing, and matters only where it sits inside a blocking row, because the most
 * specific matching row decides (the registry's own rule: "unless allowed by a more
 * specific allocation"). Which rows are null is pinned by ip-policy.test.ts, so a new
 * one cannot be added without that test changing. Rows the registry does not list, or
 * lists as True / N/A / without a value but which are blocked anyway, say so beside them.
 */
interface RangeRow {
  base: string
  prefix: number
  code: IpBlockCode | null
  description: string
}

function mostSpecificFirst(rows: RangeRow[]): RangeRow[] {
  return [...rows].sort((a, b) => b.prefix - a.prefix)
}

function verdictFor(row: RangeRow | undefined): IpVerdict {
  return row === undefined || row.code === null ? ALLOWED : block(row.code, row.description)
}

/**
 * Parses a canonical dotted-decimal IPv4 string (e.g. "127.0.0.1") into 4 octets.
 * Deliberately strict: this only ever receives strings we produced ourselves — either
 * from raw DNS answer bytes, or from WHATWG URL's own IPv4 host-parser output (which
 * already normalizes hex/octal/decimal-integer/short forms like "0x7f000001" into this
 * canonical form before we ever see it) — so no octal/hex obfuscation handling is needed
 * here. See README "Why we trust `new URL().hostname`" for the verification behind that.
 */
function parseIpv4(ip: string): [number, number, number, number] | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  const octets: number[] = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const n = Number(part)
    if (n > 255) return null
    octets.push(n)
  }
  return octets as [number, number, number, number]
}

function ipv4ToInt(octets: [number, number, number, number]): number {
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
}

function inIpv4Range(value: number, base: string, prefixLength: number): boolean {
  const baseOctets = parseIpv4(base)
  if (!baseOctets) throw new Error(`invalid base IP in range table: ${base}`)
  const baseInt = ipv4ToInt(baseOctets)
  const maskBits = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0
  return (value & maskBits) === (baseInt & maskBits)
}

const IPV4_CLOUD_METADATA = '169.254.169.254'

const IPV4_ROWS: RangeRow[] = [
  // IANA IPv4 Special-Purpose Address Registry, in registry order.
  { base: '0.0.0.0', prefix: 8, code: 'THIS_NETWORK', description: '"this network" (0.0.0.0/8, RFC 791)' },
  { base: '0.0.0.0', prefix: 32, code: 'THIS_NETWORK', description: '"this host on this network" (0.0.0.0/32, RFC 1122)' },
  { base: '10.0.0.0', prefix: 8, code: 'PRIVATE_USE', description: 'private-use (10.0.0.0/8, RFC 1918)' },
  { base: '100.64.0.0', prefix: 10, code: 'CGNAT', description: 'shared address space / CGNAT (100.64.0.0/10, RFC 6598)' },
  { base: '127.0.0.0', prefix: 8, code: 'LOOPBACK', description: 'loopback (127.0.0.0/8, RFC 1122)' },
  { base: '169.254.0.0', prefix: 16, code: 'LINK_LOCAL', description: 'link-local (169.254.0.0/16, RFC 3927)' },
  { base: '172.16.0.0', prefix: 12, code: 'PRIVATE_USE', description: 'private-use (172.16.0.0/12, RFC 1918)' },
  { base: '192.0.0.0', prefix: 24, code: 'PROTOCOL_ASSIGNMENT', description: 'IETF protocol assignments (192.0.0.0/24, RFC 6890)' },
  { base: '192.0.0.0', prefix: 29, code: 'PROTOCOL_ASSIGNMENT', description: 'IPv4 service continuity prefix (192.0.0.0/29, RFC 7335)' },
  { base: '192.0.0.8', prefix: 32, code: 'PROTOCOL_ASSIGNMENT', description: 'IPv4 dummy address (192.0.0.8/32, RFC 7600)' },
  { base: '192.0.0.9', prefix: 32, code: null, description: 'Port Control Protocol anycast (192.0.0.9/32, RFC 7723)' },
  { base: '192.0.0.10', prefix: 32, code: null, description: 'TURN anycast (192.0.0.10/32, RFC 8155)' },
  { base: '192.0.0.170', prefix: 32, code: 'PROTOCOL_ASSIGNMENT', description: 'NAT64/DNS64 discovery (192.0.0.170/32, RFC 8880)' },
  { base: '192.0.0.171', prefix: 32, code: 'PROTOCOL_ASSIGNMENT', description: 'NAT64/DNS64 discovery (192.0.0.171/32, RFC 8880)' },
  { base: '192.0.2.0', prefix: 24, code: 'DOCUMENTATION', description: 'documentation / TEST-NET-1 (192.0.2.0/24, RFC 5737)' },
  { base: '192.31.196.0', prefix: 24, code: null, description: 'AS112-v4 (192.31.196.0/24, RFC 7535)' },
  { base: '192.52.193.0', prefix: 24, code: null, description: 'AMT (192.52.193.0/24, RFC 7450)' },
  // The registry gives no "Globally Reachable" value for this one: it was deprecated in 2015
  // and must not be reassigned (RFC 7526). Blocked whole.
  { base: '192.88.99.0', prefix: 24, code: 'DEPRECATED', description: 'deprecated 6to4 relay anycast (192.88.99.0/24, RFC 7526)' },
  { base: '192.88.99.2', prefix: 32, code: 'PROTOCOL_ASSIGNMENT', description: '6a44 relay anycast (192.88.99.2/32, RFC 6751)' },
  { base: '192.168.0.0', prefix: 16, code: 'PRIVATE_USE', description: 'private-use (192.168.0.0/16, RFC 1918)' },
  { base: '192.175.48.0', prefix: 24, code: null, description: 'direct delegation AS112 service (192.175.48.0/24, RFC 7534)' },
  { base: '198.18.0.0', prefix: 15, code: 'BENCHMARKING', description: 'benchmarking (198.18.0.0/15, RFC 2544)' },
  { base: '198.51.100.0', prefix: 24, code: 'DOCUMENTATION', description: 'documentation / TEST-NET-2 (198.51.100.0/24, RFC 5737)' },
  { base: '203.0.113.0', prefix: 24, code: 'DOCUMENTATION', description: 'documentation / TEST-NET-3 (203.0.113.0/24, RFC 5737)' },
  { base: '240.0.0.0', prefix: 4, code: 'RESERVED', description: 'reserved for future use (240.0.0.0/4, RFC 1112)' },
  { base: '255.255.255.255', prefix: 32, code: 'RESERVED', description: 'limited broadcast (255.255.255.255/32, RFC 919)' },
  // Not in the special-purpose registry (it has its own): never a unicast destination.
  { base: '224.0.0.0', prefix: 4, code: 'MULTICAST', description: 'multicast (224.0.0.0/4, RFC 5771)' },
]

const IPV4_TABLE = mostSpecificFirst(IPV4_ROWS)

export function classifyIpv4(ip: string): IpVerdict {
  const octets = parseIpv4(ip)
  if (!octets) return block('MALFORMED', `not a well-formed IPv4 address: ${JSON.stringify(ip)}`)
  if (ip === IPV4_CLOUD_METADATA) {
    return block('CLOUD_METADATA', 'cloud instance metadata address (169.254.169.254)')
  }
  const value = ipv4ToInt(octets)
  return verdictFor(IPV4_TABLE.find((row) => inIpv4Range(value, row.base, row.prefix)))
}

/** Expands a (possibly `::`-compressed) IPv6 literal into 8 16-bit groups. Hex hextets only — no embedded dotted-decimal IPv4 tail, since every string we classify was already normalized to pure hex by either the WHATWG URL host-parser or our own DNS-answer formatter. */
function parseIpv6(ip: string): number[] | null {
  if (ip.includes(':::') || (ip.match(/::/g) ?? []).length > 1) return null
  const [head, tail] = ip.includes('::') ? ip.split('::') : [ip, undefined]
  const headParts = head === '' ? [] : head.split(':')
  const tailParts = tail === undefined ? [] : tail === '' ? [] : tail.split(':')

  if (tail === undefined) {
    if (headParts.length !== 8) return null
  } else {
    if (headParts.length + tailParts.length > 7) return null
  }

  const parsedHead = headParts.map((p) => (/^[0-9a-fA-F]{1,4}$/.test(p) ? parseInt(p, 16) : null))
  const parsedTail = tailParts.map((p) => (/^[0-9a-fA-F]{1,4}$/.test(p) ? parseInt(p, 16) : null))
  if (parsedHead.some((v) => v === null) || parsedTail.some((v) => v === null)) return null

  const fillLength = 8 - parsedHead.length - parsedTail.length
  if (tail === undefined) {
    return parsedHead as number[]
  }
  if (fillLength < 0) return null
  return [...(parsedHead as number[]), ...new Array(fillLength).fill(0), ...(parsedTail as number[])]
}

function inIpv6Range(groups: number[], baseIp: string, prefixLength: number): boolean {
  const baseGroups = parseIpv6(baseIp)
  if (!baseGroups) throw new Error(`invalid base IPv6 in range table: ${baseIp}`)
  let bitsLeft = prefixLength
  for (let i = 0; i < 8; i++) {
    const groupBits = Math.max(0, Math.min(16, bitsLeft))
    bitsLeft -= 16
    if (groupBits === 0) continue
    const mask = groupBits === 16 ? 0xffff : (0xffff << (16 - groupBits)) & 0xffff
    if ((groups[i]! & mask) !== (baseGroups[i]! & mask)) return false
  }
  return true
}

const IPV6_CLOUD_METADATA = 'fd00:ec2::254'

const IPV6_ROWS: RangeRow[] = [
  // IANA IPv6 Special-Purpose Address Registry, in registry order. ::ffff:0:0/96
  // (IPv4-mapped) is not a row: classifyIpv6 unwraps it and judges the embedded IPv4
  // address by the IPv4 table instead (see extractMappedIpv4).
  { base: '::1', prefix: 128, code: 'LOOPBACK', description: 'loopback (::1/128, RFC 4291)' },
  { base: '::', prefix: 128, code: 'UNSPECIFIED', description: 'unspecified address (::/128, RFC 4291)' },
  // The registry marks this prefix Globally Reachable = True. Blocked whole anyway: the
  // address is an IPv4 address handed to a translator on the path, and where that
  // translator forwards it is something this guard cannot see.
  { base: '64:ff9b::', prefix: 96, code: 'NAT64', description: 'IPv4/IPv6 translation, well-known prefix (64:ff9b::/96, RFC 6052)' },
  { base: '64:ff9b:1::', prefix: 48, code: 'NAT64', description: 'IPv4/IPv6 translation, local use (64:ff9b:1::/48, RFC 8215)' },
  { base: '100::', prefix: 64, code: 'DISCARD_ONLY', description: 'discard-only (100::/64, RFC 6666)' },
  { base: '100:0:0:1::', prefix: 64, code: 'DUMMY_PREFIX', description: 'dummy IPv6 prefix (100:0:0:1::/64, RFC 9780)' },
  { base: '2001::', prefix: 23, code: 'PROTOCOL_ASSIGNMENT', description: 'IETF protocol assignments (2001::/23, RFC 2928)' },
  // Globally Reachable is N/A for Teredo in the registry; it tunnels to an IPv4 host
  // this guard cannot see, so it is blocked like its /23 parent.
  { base: '2001::', prefix: 32, code: 'TEREDO', description: 'Teredo (2001::/32, RFC 4380)' },
  { base: '2001:1::1', prefix: 128, code: null, description: 'Port Control Protocol anycast (2001:1::1/128, RFC 7723)' },
  { base: '2001:1::2', prefix: 128, code: null, description: 'TURN anycast (2001:1::2/128, RFC 8155)' },
  { base: '2001:1::3', prefix: 128, code: null, description: 'DNS-SD service registration protocol anycast (2001:1::3/128, RFC 9665)' },
  { base: '2001:2::', prefix: 48, code: 'BENCHMARKING', description: 'benchmarking (2001:2::/48, RFC 5180)' },
  { base: '2001:3::', prefix: 32, code: null, description: 'AMT (2001:3::/32, RFC 7450)' },
  { base: '2001:4:112::', prefix: 48, code: null, description: 'AS112-v6 (2001:4:112::/48, RFC 7535)' },
  // No "Globally Reachable" value in the registry: deprecated in 2014. Blocked like its /23 parent.
  { base: '2001:10::', prefix: 28, code: 'DEPRECATED', description: 'deprecated, previously ORCHID (2001:10::/28, RFC 4843)' },
  { base: '2001:20::', prefix: 28, code: null, description: 'ORCHIDv2 (2001:20::/28, RFC 7343)' },
  { base: '2001:30::', prefix: 28, code: null, description: 'drone remote ID entity tags (2001:30::/28, RFC 9374)' },
  { base: '2001:db8::', prefix: 32, code: 'DOCUMENTATION', description: 'documentation (2001:db8::/32, RFC 3849)' },
  // Globally Reachable is N/A for 6to4 in the registry; it tunnels to the IPv4 address
  // embedded in bits 16-47, which this guard cannot see. Blocked whole.
  { base: '2002::', prefix: 16, code: 'SIX_TO_FOUR', description: '6to4 (2002::/16, RFC 3056)' },
  { base: '2620:4f:8000::', prefix: 48, code: null, description: 'direct delegation AS112 service (2620:4f:8000::/48, RFC 7534)' },
  { base: '3fff::', prefix: 20, code: 'DOCUMENTATION', description: 'documentation (3fff::/20, RFC 9637)' },
  { base: '5f00::', prefix: 16, code: 'SEGMENT_ROUTING', description: 'segment routing (SRv6) SIDs (5f00::/16, RFC 9602)' },
  { base: 'fc00::', prefix: 7, code: 'UNIQUE_LOCAL', description: 'unique local address (fc00::/7, RFC 4193)' },
  { base: 'fe80::', prefix: 10, code: 'LINK_LOCAL', description: 'link-local (fe80::/10, RFC 4291)' },
  // Not in the special-purpose registry (they are in the IPv6 address-space registry).
  { base: '::', prefix: 96, code: 'IPV4_COMPATIBLE', description: 'deprecated IPv4-compatible address (::/96, RFC 4291)' },
  { base: 'fec0::', prefix: 10, code: 'SITE_LOCAL', description: 'deprecated site-local address (fec0::/10, RFC 3879)' },
  { base: 'ff00::', prefix: 8, code: 'MULTICAST', description: 'multicast (ff00::/8, RFC 4291)' },
]

const IPV6_TABLE = mostSpecificFirst(IPV6_ROWS)

/** ::ffff:0:0/96 — the low 32 bits are an embedded IPv4 address that must be unwrapped and re-checked against the IPv4 policy, not treated as opaque IPv6 bits. */
function extractMappedIpv4(groups: number[]): string | null {
  const isMapped = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff
  if (!isMapped) return null
  const g6 = groups[6]!
  const g7 = groups[7]!
  return `${(g6 >> 8) & 0xff}.${g6 & 0xff}.${(g7 >> 8) & 0xff}.${g7 & 0xff}`
}

export function classifyIpv6(ip: string): IpVerdict {
  const groups = parseIpv6(ip)
  if (!groups) return block('MALFORMED', `not a well-formed IPv6 address: ${JSON.stringify(ip)}`)

  const mapped = extractMappedIpv4(groups)
  if (mapped !== null) {
    const v4Verdict = classifyIpv4(mapped)
    if (v4Verdict.blocked) return v4Verdict
    return ALLOWED
  }

  if (ipv6Equals(groups, IPV6_CLOUD_METADATA)) {
    return block('CLOUD_METADATA', 'cloud instance metadata address (fd00:ec2::254)')
  }

  return verdictFor(IPV6_TABLE.find((row) => inIpv6Range(groups, row.base, row.prefix)))
}

function ipv6Equals(groups: number[], other: string): boolean {
  const otherGroups = parseIpv6(other)
  if (!otherGroups) return false
  return groups.every((g, i) => g === otherGroups[i])
}

export function classifyIp(ip: string, family: 4 | 6): IpVerdict {
  return family === 4 ? classifyIpv4(ip) : classifyIpv6(ip)
}
