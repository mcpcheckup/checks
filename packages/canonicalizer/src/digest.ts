import { canonicalBytes } from './canonicalize.ts'

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** SHA-256 of the JCS+NFC canonical form, as "sha256:<64 lowercase hex chars>". */
export async function digest(value: unknown): Promise<string> {
  const bytes = canonicalBytes(value)
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
  return 'sha256:' + toHex(hashBuffer)
}
