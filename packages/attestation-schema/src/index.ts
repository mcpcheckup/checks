import attestationSchema from '../schema/attestation.schema.json' with { type: 'json' }
import attestationSchemaV03 from '../schema/attestation-payload-v0.3.json' with { type: 'json' }
import attestationSchemaV02 from '../schema/attestation-payload-v0.2.json' with { type: 'json' }
import attestationSchemaV01 from '../schema/attestation-payload-v0.1.json' with { type: 'json' }
import { ATTESTATION_PAYLOAD_TYPE_V0_4 } from './attestation.ts'

export const ATTESTATION_SCHEMA = attestationSchema

/**
 * ARCHIVED — the payload schema for payloadType
 * 'application/vnd.mcpcheckup.attestation+json;version=0.3', byte-for-byte the
 * schema/attestation.schema.json that v0.3 envelopes were signed against
 * (schema-v04.test.ts pins its sha256). Unlike v0.1 and v0.2 it is still the shape
 * ATTESTATION_PAYLOAD_TYPE signs today; v0.4 is defined ahead of that switch.
 */
export const ATTESTATION_SCHEMA_V0_3 = attestationSchemaV03

/**
 * ARCHIVED — the payload schema for payloadType
 * 'application/vnd.mcpcheckup.attestation+json;version=0.2', retained solely
 * so the v0.2 envelopes signed and published before the v0.3 bump remain
 * independently verifiable. New attestations are never produced under this
 * shape — do not use this for anything but validating an envelope whose
 * `payloadType` literally ends in `;version=0.2`.
 */
export const ATTESTATION_SCHEMA_V0_2 = attestationSchemaV02

/**
 * ARCHIVED — the payload schema for payloadType
 * 'application/vnd.mcpcheckup.attestation+json;version=0.1', retained solely
 * so the small number of v0.1 envelopes signed and published before the
 * v0.2 bump remain independently verifiable. New attestations are never
 * produced under this shape — do not use this for anything but validating an
 * envelope whose `payloadType` literally ends in `;version=0.1`.
 */
export const ATTESTATION_SCHEMA_V0_1 = attestationSchemaV01

/**
 * Every payloadType this package defines, mapped to the schema that
 * validates payloads carrying it.
 *
 * Keyed on the whole payloadType string rather than on a version number parsed
 * out of it: the payloadType is the version declaration the signer put in the
 * signed bytes, and re-parsing it here would invent a second, looser notion of
 * "version" that could disagree with that one.
 *
 * A Map, not a plain object literal: property lookup on an object literal
 * resolves '__proto__', 'constructor' and 'toString' to inherited values, so
 * those three strings would come back as something other than undefined and be
 * dispatched to instead of rejected.
 *
 * The current entry is keyed off ATTESTATION_PAYLOAD_TYPE_V0_4 itself instead of
 * a second copy of the same literal. The archived entries are literals on
 * purpose: ATTESTATION_PAYLOAD_TYPE moves from v0.3 to v0.4 when signing does,
 * and a v0.3 entry keyed off it would then silently collide with the v0.4 one
 * and drop v0.3 from this map.
 */
const SCHEMA_BY_PAYLOAD_TYPE = new Map<string, object>([
  ['application/vnd.mcpcheckup.attestation+json;version=0.1', ATTESTATION_SCHEMA_V0_1],
  ['application/vnd.mcpcheckup.attestation+json;version=0.2', ATTESTATION_SCHEMA_V0_2],
  ['application/vnd.mcpcheckup.attestation+json;version=0.3', ATTESTATION_SCHEMA_V0_3],
  [ATTESTATION_PAYLOAD_TYPE_V0_4, ATTESTATION_SCHEMA],
])

/**
 * The schema a DSSE envelope's own `payloadType` says its payload must satisfy.
 * Pass the envelope's `payloadType` verbatim; compile the returned schema with
 * any draft 2020-12 validator.
 *
 * Before this function existed, ATTESTATION_SCHEMA_V0_1 was an exported constant
 * with no dispatcher anywhere in the repo: "historical envelopes remain
 * verifiable" was a claim with no mechanism behind it, and a caller had nothing
 * to reach for but ATTESTATION_SCHEMA regardless of version. This function is
 * the mechanism.
 *
 * Throws on any other value — including a payloadType carrying no `;version=`
 * parameter at all. Falling back to the current schema would be worse than
 * failing: it would report "does not validate" for an envelope this package
 * really did sign (v0.1's `reason` is a bare string, v0.3's is an object), or
 * "validates" for one it never signed, and in both cases the verifier would
 * have checked the payload against a schema the signer never used.
 */
export function attestationSchemaForPayloadType(payloadType: string): object {
  const schema = SCHEMA_BY_PAYLOAD_TYPE.get(payloadType)
  if (schema === undefined) {
    const known = [...SCHEMA_BY_PAYLOAD_TYPE.keys()].map((k) => JSON.stringify(k)).join(', ')
    throw new Error(`unknown attestation payloadType ${JSON.stringify(payloadType)} — this package accepts only ${known}`)
  }
  return schema
}

export { pae, base64Encode, base64Decode, signDsseEnvelope, verifyDsseEnvelope, verifyDsseSignature } from './dsse.ts'
export type { DsseSignature, DsseEnvelope } from './dsse.ts'

export { ATTESTATION_PAYLOAD_TYPE, ATTESTATION_PAYLOAD_TYPE_V0_4, signAttestationPayload } from './attestation.ts'
export type { AttestationPayloadV0_3 } from './attestation.ts'

export { assertUnverifiedHasReason, AssertionInvariantError } from './invariants.ts'
export type { AssertionInvariantErrorCode, AssertionReasonFields } from './invariants.ts'

export type { AttestationPayload, AuthObservation, RemoteTarget, StdioTarget, Assertion, AssertionBase } from './generated-types.ts'
