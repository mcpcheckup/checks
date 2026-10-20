import { canonicalBytes } from '@mcpcheckup/canonicalizer'
import { signDsseEnvelope, type DsseEnvelope } from './dsse.ts'
import type { AttestationPayload } from './generated-types.ts'

/**
 * The DSSE payloadType for MCP Checkup attestations. Encodes both the encoding
 * (JSON) and the schema version, per the DSSE spec's own guidance for
 * PAYLOAD_TYPE — see dsse.ts.
 *
 * Still v0.3: this is the payloadType attestations are signed under today, and
 * the one signAttestationPayload below stamps. It moves to
 * ATTESTATION_PAYLOAD_TYPE_V0_4 in the same change that starts producing v0.4
 * payloads, so the label and the shape it labels never disagree in between.
 */
export const ATTESTATION_PAYLOAD_TYPE = 'application/vnd.mcpcheckup.attestation+json;version=0.3'

/**
 * The payloadType for the v0.4 payload shape (schema/attestation.schema.json:
 * `coverage`, `run_id`, `auth_observation`). Accepted for verification by
 * attestationSchemaForPayloadType ahead of any envelope being signed under it.
 */
export const ATTESTATION_PAYLOAD_TYPE_V0_4 = 'application/vnd.mcpcheckup.attestation+json;version=0.4'

/** AttestationPayload's named fields, without the `[k: string]: unknown` index
 *  signature json-schema-to-typescript adds next to an allOf (see README). */
type NamedFields<T> = { [K in keyof T as string extends K ? never : number extends K ? never : K]: T[K] }

/**
 * A v0.3 payload (schema/attestation-payload-v0.3.json), the shape signed under
 * ATTESTATION_PAYLOAD_TYPE today. Written as v0.4 with coverage 'full' minus
 * the two fields v0.4 added, which is exactly the relation the schemas state:
 * the same fields, with protocol_revision and both fingerprints non-null.
 */
export type AttestationPayloadV0_3 = Omit<
  NamedFields<AttestationPayload>,
  'coverage' | 'run_id' | 'auth_observation' | 'protocol_revision' | 'toolset_fingerprint' | 'schema_fingerprint'
> & {
  protocol_revision: string
  toolset_fingerprint: string
  schema_fingerprint: string
}

/**
 * Canonicalize `payload` under nfc-jcs/v1 (@mcpcheckup/canonicalizer) and produce a
 * DSSE envelope over the result. Signing the canonical bytes — not whatever a naive
 * JSON.stringify would produce — is what makes `payload.canonicalization: "nfc-jcs/v1"`
 * a true statement instead of a label nobody enforced.
 */
export async function signAttestationPayload(
  payload: AttestationPayloadV0_3,
  privateKey: CryptoKey,
  opts?: { keyid?: string },
): Promise<DsseEnvelope> {
  const bytes = canonicalBytes(payload)
  return signDsseEnvelope(ATTESTATION_PAYLOAD_TYPE, bytes, privateKey, opts)
}
