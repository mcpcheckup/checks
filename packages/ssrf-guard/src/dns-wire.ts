// Minimal RFC 1035 / RFC 8484 (DoH wireformat) DNS message codec — only what we need to
// send a single-question A or AAAA query and read A/AAAA answers back out. We use
// wireformat rather than Cloudflare's DoH JSON API deliberately: Cloudflare's own docs
// say the JSON schema "has no formal RFC and is not guaranteed to be stable... if you
// need a stable format, use the DoH wireformat instead." This is the most security-
// critical resolution path in the product, so we don't build it on a format the vendor
// itself calls unstable. See README "Why wireformat, not JSON".

export const QTYPE_A = 1
export const QTYPE_AAAA = 28
export const QTYPE_TXT = 16
const QCLASS_IN = 1

export function encodeQuery(hostname: string, qtype: number, id: number): Uint8Array<ArrayBuffer> {
  const labels = hostname.split('.').filter((l) => l.length > 0)
  const encoder = new TextEncoder()
  const labelBytes = labels.map((l) => encoder.encode(l))
  for (const lb of labelBytes) {
    if (lb.length > 63) throw new Error(`DNS label too long (max 63 bytes): ${JSON.stringify(hostname)}`)
  }

  const qnameLength = labelBytes.reduce((sum, lb) => sum + 1 + lb.length, 0) + 1 // + root terminator
  const out = new Uint8Array(12 + qnameLength + 4)
  const view = new DataView(out.buffer)

  view.setUint16(0, id, false)
  view.setUint16(2, 0x0100, false) // flags: RD=1
  view.setUint16(4, 1, false) // QDCOUNT
  view.setUint16(6, 0, false) // ANCOUNT
  view.setUint16(8, 0, false) // NSCOUNT
  view.setUint16(10, 0, false) // ARCOUNT

  let offset = 12
  for (const lb of labelBytes) {
    out[offset] = lb.length
    offset += 1
    out.set(lb, offset)
    offset += lb.length
  }
  out[offset] = 0 // root terminator
  offset += 1

  view.setUint16(offset, qtype, false)
  view.setUint16(offset + 2, QCLASS_IN, false)

  return out
}

export interface DecodedAnswer {
  type: number
  /** A / AAAA 记录的地址；TXT 记录上为 undefined。 */
  ip?: string
  /** TXT 记录的完整内容（多个 character-string 已拼接）；A/AAAA 上为 undefined。 */
  text?: string
}

export interface DecodedResponse {
  rcode: number
  answers: DecodedAnswer[]
}

class DnsDecodeError extends Error {}

function requireBytes(bytes: Uint8Array, offset: number, length: number): void {
  if (offset < 0 || offset + length > bytes.length) {
    throw new DnsDecodeError(`DNS message truncated: need ${length} bytes at offset ${offset}, have ${bytes.length}`)
  }
}

/** Advances past one NAME field (label sequence, optionally ending in a compression
 *  pointer). We only need the new offset — the actual name content is never used. */
function skipName(bytes: Uint8Array, offset: number): number {
  let pos = offset
  for (let guard = 0; guard < 128; guard++) {
    requireBytes(bytes, pos, 1)
    const b = bytes[pos]!
    if ((b & 0xc0) === 0xc0) {
      requireBytes(bytes, pos, 2)
      return pos + 2
    }
    if (b === 0) {
      return pos + 1
    }
    if ((b & 0xc0) !== 0) {
      throw new DnsDecodeError(`unsupported DNS label length byte 0x${b.toString(16)} at offset ${pos}`)
    }
    requireBytes(bytes, pos, 1 + b)
    pos += 1 + b
  }
  throw new DnsDecodeError('DNS name too long or contains a pointer loop')
}

function formatIpv4(bytes: Uint8Array, offset: number): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`
}

function formatIpv6(bytes: Uint8Array, offset: number): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 16)
  const groups: string[] = []
  for (let i = 0; i < 8; i++) {
    groups.push(view.getUint16(i * 2, false).toString(16))
  }
  return groups.join(':')
}

export function decodeResponse(bytes: Uint8Array): DecodedResponse {
  requireBytes(bytes, 0, 12)
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

  const flags = view.getUint16(2, false)
  const rcode = flags & 0x000f
  const qdcount = view.getUint16(4, false)
  const ancount = view.getUint16(6, false)

  let offset = 12
  for (let i = 0; i < qdcount; i++) {
    offset = skipName(bytes, offset)
    requireBytes(bytes, offset, 4) // QTYPE + QCLASS
    offset += 4
  }

  const answers: DecodedAnswer[] = []
  for (let i = 0; i < ancount; i++) {
    offset = skipName(bytes, offset)
    requireBytes(bytes, offset, 10) // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
    const type = view.getUint16(offset, false)
    const rdlength = view.getUint16(offset + 8, false)
    const rdataOffset = offset + 10
    requireBytes(bytes, rdataOffset, rdlength)

    if (type === QTYPE_A) {
      if (rdlength !== 4) throw new DnsDecodeError(`A record RDLENGTH must be 4, got ${rdlength}`)
      answers.push({ type, ip: formatIpv4(bytes, rdataOffset) })
    } else if (type === QTYPE_AAAA) {
      if (rdlength !== 16) throw new DnsDecodeError(`AAAA record RDLENGTH must be 16, got ${rdlength}`)
      answers.push({ type, ip: formatIpv6(bytes, rdataOffset) })
    } else if (type === QTYPE_TXT) {
      // RFC 1035 §3.3.14：TXT rdata 是一或多个 <character-string>，
      // 每个以一字节长度开头。一条记录的多个片段按顺序拼接成完整字符串。
      let p = rdataOffset
      const end = rdataOffset + rdlength
      const parts: string[] = []
      const decoder = new TextDecoder()
      while (p < end) {
        const segLen = bytes[p]!
        p += 1
        if (p + segLen > end) {
          throw new DnsDecodeError(`TXT segment at offset ${p} overruns rdlength (rdlength=${rdlength})`)
        }
        parts.push(decoder.decode(bytes.subarray(p, p + segLen)))
        p += segLen
      }
      answers.push({ type, text: parts.join('') })
    }

    offset = rdataOffset + rdlength
  }

  return { rcode, answers }
}
