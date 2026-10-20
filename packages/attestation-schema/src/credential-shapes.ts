import attestationSchema from '../schema/attestation.schema.json' with { type: 'json' }

/**
 * Finds credential-shaped text in an attestation payload, or in any value
 * shaped like one. The tested server chooses some of the text in a v0.4
 * payload (an auth_gated payload's auth_observation, and the scheme its
 * credential_required reasons carry), and none of it may put a credential into
 * a signed payload. The schema's own shapes exclude most credential forms; what
 * a shape cannot exclude, these rules catch. The probe runs them before
 * recording a scheme, a parameter name or a URL, and the tests run them over
 * whole payloads.
 *
 * Each rule is tried on the string as it stands and on its percent-decoded
 * form, so `%73k_test_…` in a URL path is caught like `sk_test_…`.
 */
export const CREDENTIAL_SHAPE_RULES: ReadonlyArray<readonly [name: string, matches: (s: string) => boolean]> = [
  ['jwt', (s) => /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/.test(s)],
  ['authorization header value', (s) => /\b(?:bearer|basic|token|dpop)\s+[A-Za-z0-9._~+/-]{8,}/i.test(s)],
  ['private key block', (s) => /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)],
  ['vendor key prefix', (s) => /(?:^|[^A-Za-z0-9])(?:(?:sk|rk|pk)_(?:live|test)_|gh[pousr]_|github_pat_|xox[abprs]-|glpat-|whsec_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20})/.test(s)],
  ['long hex run', (s) => /(?:^|[^0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])/.test(s)],
  ['high-entropy token', (s) => s.split(/[^A-Za-z0-9+/=_-]+/).some((p) => p.length >= 24 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p))],
]

/** Every %XX escape replaced by the character with that code, repeated until
 *  nothing changes, so a double-encoded `%2573` is read as `s` too. Ends: each
 *  pass that changes anything makes the string shorter. A malformed escape is
 *  left as it is rather than refused. */
export function percentDecoded(s: string): string {
  let out = s
  for (let next = decodeOnce(out); next !== out; next = decodeOnce(out)) out = next
  return out
}
function decodeOnce(s: string): string {
  return s.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
}

/** Values the probe computes itself (hashes, the commit and the run id). A
 *  string at one of these paths is skipped only when it matches that field's
 *  own schema pattern, read from the schema rather than restated, so anything
 *  else placed there is still scanned. */
const OWN_VALUE_PATHS = [
  ['suite_digest'], ['suite_commit'], ['launch_config_digest'], ['toolset_fingerprint'], ['schema_fingerprint'], ['run_id'],
  ['auth_observation', 'resource_metadata_body_digest'],
]
type SchemaNode = { pattern?: string; oneOf?: Array<{ pattern?: string }> }
function schemaPatternAt(path: string[]): RegExp {
  const schema = attestationSchema as unknown as { properties: Record<string, SchemaNode>; $defs: { authObservation: { properties: Record<string, SchemaNode> } } }
  const node = path.length === 1 ? schema.properties[path[0]!]! : schema.$defs.authObservation.properties[path[1]!]!
  const pattern = node.pattern ?? node.oneOf?.find((branch) => branch.pattern)?.pattern
  if (typeof pattern !== 'string') throw new Error(`no pattern in the schema for ${path.join('.')}`)
  return new RegExp(pattern)
}
const OWN_VALUES = OWN_VALUE_PATHS.map((path) => ({ key: path.join('.'), pattern: schemaPatternAt(path) }))

/** Every credential-shaped string anywhere in `value`, as "<path>: <rule>",
 *  where <path> is the dot-joined key path ('' for a bare string). Empty when
 *  there is none. */
export function credentialShapes(value: unknown, path: string[] = []): string[] {
  if (typeof value === 'string') {
    const own = OWN_VALUES.find((d) => d.key === path.join('.'))
    if (own && own.pattern.test(value)) return []
    const decoded = percentDecoded(value)
    return CREDENTIAL_SHAPE_RULES.filter(([, matches]) => matches(value) || matches(decoded)).map(([rule]) => `${path.join('.')}: ${rule}`)
  }
  if (Array.isArray(value)) return value.flatMap((v, i) => credentialShapes(v, [...path, String(i)]))
  if (value !== null && typeof value === 'object') return Object.entries(value).flatMap(([k, v]) => credentialShapes(v, [...path, k]))
  return []
}
