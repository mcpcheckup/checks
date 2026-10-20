import { canonicalBytes } from '@mcpcheckup/canonicalizer'
import { signDsseEnvelope, type DsseEnvelope } from './dsse.ts'
import type { AttestationPayload } from './generated-types.ts'

/**
 * The DSSE payloadType for a v0.3 attestation payload. Encodes both the
 * encoding (JSON) and the schema version, per the DSSE spec's own guidance for
 * PAYLOAD_TYPE — see dsse.ts.
 *
 * v0.3 is the shape signAttestationPayload below takes, and the one this label
 * stamps. Attestations have been signed as v0.4 (ATTESTATION_PAYLOAD_TYPE_V0_4)
 * since suite 0.14.0; envelopes signed as v0.3 before that stay verifiable.
 */
export const ATTESTATION_PAYLOAD_TYPE = 'application/vnd.mcpcheckup.attestation+json;version=0.3'

/**
 * The payloadType for the v0.4 payload shape (schema/attestation.schema.json:
 * `coverage`, `run_id`, `auth_observation`), the one attestations are signed
 * under since suite 0.14.0.
 */
export const ATTESTATION_PAYLOAD_TYPE_V0_4 = 'application/vnd.mcpcheckup.attestation+json;version=0.4'

/**
 * The four checks an 'auth_gated' payload may report as observed, in the
 * schema's order: every other assertion in such a payload is UNVERIFIED with
 * an unverified_reason (schema/attestation.schema.json, the second `allOf`
 * entry, which lists the same four; schema-v04.test.ts holds the two equal).
 */
export const AUTH_GATED_CHECK_IDS = ['reachability', 'redirect_policy', 'transport_type', 'auth_metadata'] as const

/** AttestationPayload's named fields, without the `[k: string]: unknown` index
 *  signature json-schema-to-typescript adds next to an allOf (see README). */
type NamedFields<T> = { [K in keyof T as string extends K ? never : number extends K ? never : K]: T[K] }

/** A v0.4 payload (schema/attestation.schema.json): AttestationPayload's named
 *  fields only, so an unknown key is a type error rather than an index-signature
 *  member. */
export type AttestationPayloadV0_4 = NamedFields<AttestationPayload>

/**
 * A v0.3 payload (schema/attestation-payload-v0.3.json), the shape signed under
 * ATTESTATION_PAYLOAD_TYPE. Written as v0.4 with coverage 'full' minus
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
