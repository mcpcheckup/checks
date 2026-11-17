/**
 * DSSE (Dead Simple Signing Envelope) — https://github.com/secure-systems-lab/dsse
 *
 * This is the exact protocol/envelope in-toto and the Sigstore/SLSA ecosystem use.
 * We don't invent a signing envelope; we reuse this one so that generic DSSE
 * tooling can already parse and verify our attestations' outer layer. The only
 * thing specific to MCP Checkup is what goes inside `payload` — see index.ts.
 */

export interface DsseSignature {
  keyid?: string
  sig: string
}

export interface DsseEnvelope {
  payloadType: string
  payload: string
  signatures: DsseSignature[]
}

const DSSE_VERSION = 'DSSEv1'
const SP = ' '

/**
 * PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
 * LEN(s) = ASCII decimal encoding of the byte length of s, no leading zeros.
 * This is what actually gets signed — not the raw payload — so that the
 * payloadType is authenticated too and can't be swapped without invalidating
 * the signature (the "type confusion" attack DSSE is designed to prevent).
 */
export function pae(payloadType: string, serializedBody: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
  const enc = new TextEncoder()
  const typeBytes = enc.encode(payloadType)
  const parts = [
    enc.encode(DSSE_VERSION),
    enc.encode(SP),
    enc.encode(String(typeBytes.length)),
    enc.encode(SP),
    typeBytes,
    enc.encode(SP),
    enc.encode(String(serializedBody.length)),
    enc.encode(SP),
    serializedBody,
  ]
  return concatBytes(parts)
}

function concatBytes(chunks: Uint8Array<ArrayBuffer>[]): Uint8Array<ArrayBuffer> {
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

export function base64Encode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function base64Decode(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

/** Ed25519-sign PAE(payloadType, serializedBody) and produce a standard DSSE JSON envelope. */
export async function signDsseEnvelope(
  payloadType: string,
  serializedBody: Uint8Array<ArrayBuffer>,
  privateKey: CryptoKey,
  opts?: { keyid?: string },
): Promise<DsseEnvelope> {
  const preAuth = pae(payloadType, serializedBody)
  const sigBytes = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, preAuth))
  const signature: DsseSignature = opts?.keyid !== undefined ? { keyid: opts.keyid, sig: base64Encode(sigBytes) } : { sig: base64Encode(sigBytes) }
  return {
    payloadType,
    payload: base64Encode(serializedBody),
    signatures: [signature],
  }
}

/** The atomic verification primitive: does `signature` cover exactly this (payloadType, serializedBody) under `publicKey`? */
export async function verifyDsseSignature(
  payloadType: string,
  serializedBody: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>,
  publicKey: CryptoKey,
): Promise<boolean> {
  const preAuth = pae(payloadType, serializedBody)
  return crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signature, preAuth)
}

/** An Ed25519 signature is exactly 64 bytes. */
const ED25519_SIGNATURE_LENGTH = 64

/**
 * The bytes of `sig`, or null unless it is the canonical standard-base64
 * spelling of exactly 64 bytes: a string, standard alphabet, padded, no
 * whitespace, no stray bits, 64 bytes long. The decoder behind base64Decode is
 * lenient (it skips whitespace, accepts missing padding and leftover bits), so
 * two different texts can decode to the same bytes; accepting only the text
 * that re-encodes to itself leaves one spelling per byte string. Never throws.
 */
function wellFormedSignatureBytes(sig: unknown): Uint8Array<ArrayBuffer> | null {
  if (typeof sig !== 'string') return null
  let bytes: Uint8Array<ArrayBuffer>
  try {
    bytes = base64Decode(sig)
  } catch {
    return null
  }
  if (bytes.length !== ED25519_SIGNATURE_LENGTH) return null
  return base64Encode(bytes) === sig ? bytes : null
}

/**
 * True only if no signature in the envelope is malformed and at least one
 * signature verifies against `publicKey` over PAE(payloadType, decoded
 * payload). An empty `signatures` array is `false`.
 *
 * A signature is malformed unless its `sig` is the canonical standard-base64
 * spelling of exactly 64 bytes (an Ed25519 signature's length). One malformed
 * signature makes the whole envelope `false`, wherever it sits in the array and
 * however many other signatures verify. A well-formed signature that does not
 * verify under `publicKey` (for example one made by another key) is skipped: it
 * fails only itself, and the envelope still passes while another signature
 * verifies. This is the signature rule the command-line verifier in
 * packages/verifier applies.
 *
 * Only the signatures are checked. `keyid` is not read, and no key validity
 * window or revocation is applied; the command-line verifier checks those. The
 * `payload` is decoded as base64Decode reads it, without the canonical-spelling
 * test the signatures get; the command-line verifier applies that test to the
 * payload too.
 *
 * Never throws on a malformed envelope: this is meant to run against envelopes
 * from an untrusted source, and a caller of a Promise<boolean> reasonably writes
 * `if (await verifyDsseEnvelope(...))` with no try/catch. An envelope that is
 * not an object, whose `payloadType` or `payload` is not a string, or whose
 * `signatures` is not an array is `false`, and so is malformed base64 anywhere
 * — in `payload` or in any `signatures[i].sig` — rather than a rejected call.
 * `publicKey` is the caller's own and must be an Ed25519 verification key; any
 * other key rejects, as it does in WebCrypto itself.
 */
export async function verifyDsseEnvelope(envelope: DsseEnvelope, publicKey: CryptoKey): Promise<boolean> {
  if (typeof envelope !== 'object' || envelope === null) return false
  if (typeof envelope.payloadType !== 'string' || typeof envelope.payload !== 'string' || !Array.isArray(envelope.signatures)) return false
  let serializedBody: Uint8Array<ArrayBuffer>
  try {
    serializedBody = base64Decode(envelope.payload)
  } catch {
    return false
  }
  // Check every signature's form before verifying any, so a malformed one anywhere in the
  // array is found even when an earlier signature would already have verified.
  const sigBytes: Uint8Array<ArrayBuffer>[] = []
  for (const signature of envelope.signatures) {
    const bytes = wellFormedSignatureBytes((signature as DsseSignature | null)?.sig)
    if (bytes === null) return false
    sigBytes.push(bytes)
  }
  for (const bytes of sigBytes) {
    if (await verifyDsseSignature(envelope.payloadType, serializedBody, bytes, publicKey)) return true
  }
  return false
}
