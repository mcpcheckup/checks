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

export type IpVerdict = { blocked: false } | { blocked: true; code: IpBlockCode; description: string }

const ALLOWED: IpVerdict = { blocked: false }

function block(code: IpBlockCode, description: string): IpVerdict {
  return { blocked: true, code, description }
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

const IPV4_RANGES: Array<{ base: string; prefix: number; code: IpBlockCode; description: string }> = [
  { base: '0.0.0.0', prefix: 8, code: 'THIS_NETWORK', description: '"this network" (0.0.0.0/8, RFC 791)' },
  { base: '10.0.0.0', prefix: 8, code: 'PRIVATE_USE', description: 'private-use (10.0.0.0/8, RFC 1918)' },
  { base: '100.64.0.0', prefix: 10, code: 'CGNAT', description: 'shared address space / CGNAT (100.64.0.0/10, RFC 6598)' },
  { base: '127.0.0.0', prefix: 8, code: 'LOOPBACK', description: 'loopback (127.0.0.0/8, RFC 1122)' },
  { base: '169.254.0.0', prefix: 16, code: 'LINK_LOCAL', description: 'link-local (169.254.0.0/16, RFC 3927)' },
  { base: '172.16.0.0', prefix: 12, code: 'PRIVATE_USE', description: 'private-use (172.16.0.0/12, RFC 1918)' },
  { base: '192.0.2.0', prefix: 24, code: 'DOCUMENTATION', description: 'documentation / TEST-NET-1 (192.0.2.0/24, RFC 5737)' },
  { base: '192.168.0.0', prefix: 16, code: 'PRIVATE_USE', description: 'private-use (192.168.0.0/16, RFC 1918)' },
  { base: '198.18.0.0', prefix: 15, code: 'BENCHMARKING', description: 'benchmarking (198.18.0.0/15, RFC 2544)' },
  { base: '224.0.0.0', prefix: 4, code: 'MULTICAST', description: 'multicast (224.0.0.0/4, RFC 5771)' },
  { base: '240.0.0.0', prefix: 4, code: 'RESERVED', description: 'reserved for future use, incl. broadcast (240.0.0.0/4, RFC 1112)' },
]

export function classifyIpv4(ip: string): IpVerdict {
  const octets = parseIpv4(ip)
  if (!octets) return block('MALFORMED', `not a well-formed IPv4 address: ${JSON.stringify(ip)}`)
  if (ip === IPV4_CLOUD_METADATA) {
    return block('CLOUD_METADATA', 'cloud instance metadata address (169.254.169.254)')
  }
  const value = ipv4ToInt(octets)
  for (const range of IPV4_RANGES) {
    if (inIpv4Range(value, range.base, range.prefix)) {
      return block(range.code, range.description)
    }
  }
  return ALLOWED
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

const IPV6_RANGES: Array<{ base: string; prefix: number; code: IpBlockCode; description: string }> = [
  { base: 'fe80::', prefix: 10, code: 'LINK_LOCAL', description: 'link-local (fe80::/10, RFC 4291)' },
  { base: 'fc00::', prefix: 7, code: 'UNIQUE_LOCAL', description: 'unique local address (fc00::/7, RFC 4193)' },
]

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

  if (groups.every((g) => g === 0)) return block('UNSPECIFIED', 'unspecified address (::/128, RFC 4291)')
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return block('LOOPBACK', 'loopback (::1/128, RFC 4291)')

  const mapped = extractMappedIpv4(groups)
  if (mapped !== null) {
    const v4Verdict = classifyIpv4(mapped)
    if (v4Verdict.blocked) return v4Verdict
    return ALLOWED
  }

  if (ipv6Equals(groups, IPV6_CLOUD_METADATA)) {
    return block('CLOUD_METADATA', 'cloud instance metadata address (fd00:ec2::254)')
  }

  for (const range of IPV6_RANGES) {
    if (inIpv6Range(groups, range.base, range.prefix)) {
      return block(range.code, range.description)
    }
  }
  return ALLOWED
}

function ipv6Equals(groups: number[], other: string): boolean {
  const otherGroups = parseIpv6(other)
  if (!otherGroups) return false
  return groups.every((g, i) => g === otherGroups[i])
}

export function classifyIp(ip: string, family: 4 | 6): IpVerdict {
  return family === 4 ? classifyIpv4(ip) : classifyIpv6(ip)
}
