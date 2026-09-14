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

/**
 * True if at least one signature in the envelope verifies against `publicKey`.
 * Per the DSSE spec, multiple signatures are equivalent to separate envelopes
 * with individual signatures — this checks "did *this* key sign it", not
 * "did every signer sign it".
 *
 * Never throws: this is meant to run against envelopes from an untrusted
 * source, and a caller of a Promise<boolean> reasonably writes
 * `if (await verifyDsseEnvelope(...))` with no try/catch. Malformed base64
 * anywhere — in `payload` or in any one `signatures[i].sig` — resolves to
 * `false` (or, for a single bad signature among several, is simply skipped)
 * rather than rejecting the whole call.
 */
export async function verifyDsseEnvelope(envelope: DsseEnvelope, publicKey: CryptoKey): Promise<boolean> {
  let serializedBody: Uint8Array<ArrayBuffer>
  try {
    serializedBody = base64Decode(envelope.payload)
  } catch {
    return false
  }
  for (const signature of envelope.signatures) {
    let sigBytes: Uint8Array<ArrayBuffer>
    try {
      sigBytes = base64Decode(signature.sig)
    } catch {
      continue
    }
    const ok = await verifyDsseSignature(envelope.payloadType, serializedBody, sigBytes, publicKey)
    if (ok) return true
  }
  return false
}
