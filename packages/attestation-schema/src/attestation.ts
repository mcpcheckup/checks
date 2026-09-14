import { canonicalBytes } from '@mcpcheckup/canonicalizer'
import { signDsseEnvelope, type DsseEnvelope } from './dsse.ts'
import type { AttestationPayload } from './generated-types.ts'

/**
 * The DSSE payloadType for MCP Checkup attestations. Encodes both the encoding
 * (JSON) and the schema version, per the DSSE spec's own guidance for
 * PAYLOAD_TYPE — see dsse.ts.
 */
export const ATTESTATION_PAYLOAD_TYPE = 'application/vnd.mcpcheckup.attestation+json;version=0.3'

/**
 * Canonicalize `payload` under nfc-jcs/v1 (@mcpcheckup/canonicalizer) and produce a
 * DSSE envelope over the result. Signing the canonical bytes — not whatever a naive
 * JSON.stringify would produce — is what makes `payload.canonicalization: "nfc-jcs/v1"`
 * a true statement instead of a label nobody enforced.
 */
export async function signAttestationPayload(
  payload: AttestationPayload,
  privateKey: CryptoKey,
  opts?: { keyid?: string },
): Promise<DsseEnvelope> {
  const bytes = canonicalBytes(payload)
  return signDsseEnvelope(ATTESTATION_PAYLOAD_TYPE, bytes, privateKey, opts)
}
