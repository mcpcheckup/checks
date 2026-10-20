// auth_observation carries text the tested server chose: the challenge's scheme,
// its parameter names and the resource_metadata URL. None of it may ever put a
// credential into a signed payload. Two layers keep it out:
//
//   1. the schema's own shapes (lowercase token, [a-z0-9_-]{1,32} names, an https
//      URL with no userinfo, query or fragment) exclude most credential forms;
//   2. what a shape cannot exclude (a lowercase key in a scheme or a name, anything
//      in a URL path) is caught by credentialShapes() below, run over every string
//      in the payload.
//
// The test proves, for every string slot of auth_observation and every credential
// shape, that a payload carrying it is refused by at least one layer; and it pins
// each layer separately, so neither can stop working while the other hides it.
//
// No credential-shaped text appears in this file: every value is assembled at run
// time from obviously synthetic parts, so nothing here reads as a real secret.
import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const read = (rel: string) => JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8'))
const schema = read('../schema/attestation.schema.json')
const sampleFull = read('../test/fixtures/attestation.sample.json')
const sampleAuthGated = read('../test/fixtures/attestation-auth-gated.sample.json')
const ajv = new Ajv2020({ allErrors: true, strict: true })
addFormats(ajv)
const validate = ajv.compile(schema)

// ---- the detector ------------------------------------------------------------

/** Values we compute ourselves (hashes, commit and run ids). A string at one of
 *  these paths is skipped only when it matches that field's own schema pattern,
 *  read from the schema rather than restated, so anything else placed there is
 *  still scanned. */
const OWN_DIGEST_PATHS = [
  ['suite_digest'], ['suite_commit'], ['launch_config_digest'], ['toolset_fingerprint'], ['schema_fingerprint'], ['run_id'],
  ['auth_observation', 'resource_metadata_body_digest'],
]
function schemaPatternAt(path: string[]): RegExp {
  let node = schema
  for (const [i, key] of path.entries()) node = i === 0 ? node.properties[key] : schema.$defs.authObservation.properties[key]
  const pattern = node.pattern ?? node.oneOf?.find((b: { pattern?: string }) => b.pattern)?.pattern
  assert.equal(typeof pattern, 'string', `no pattern in the schema for ${path.join('.')}`)
  return new RegExp(pattern)
}
const OWN_DIGESTS = OWN_DIGEST_PATHS.map((path) => ({ key: path.join('.'), pattern: schemaPatternAt(path) }))

const RULES: Array<[string, (s: string) => boolean]> = [
  ['jwt', (s) => /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/.test(s)],
  ['authorization header value', (s) => /\b(?:bearer|basic|token|dpop)\s+[A-Za-z0-9._~+/-]{8,}/i.test(s)],
  ['private key block', (s) => /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)],
  ['vendor key prefix', (s) => /(?:^|[^A-Za-z0-9])(?:(?:sk|rk|pk)_(?:live|test)_|gh[pousr]_|github_pat_|xox[abprs]-|glpat-|whsec_|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20})/.test(s)],
  ['long hex run', (s) => /(?:^|[^0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])/.test(s)],
  ['high-entropy token', (s) => s.split(/[^A-Za-z0-9+/=_-]+/).some((p) => p.length >= 24 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p))],
]

/** Every credential-shaped string anywhere in `value`, as "<path>: <rule>". */
function credentialShapes(value: unknown, path: string[] = []): string[] {
  if (typeof value === 'string') {
    const own = OWN_DIGESTS.find((d) => d.key === path.join('.'))
    if (own && own.pattern.test(value)) return []
    return RULES.filter(([, hit]) => hit(value)).map(([rule]) => `${path.join('.')}: ${rule}`)
  }
  if (Array.isArray(value)) return value.flatMap((v, i) => credentialShapes(v, [...path, String(i)]))
  if (value !== null && typeof value === 'object') return Object.entries(value).flatMap(([k, v]) => credentialShapes(v, [...path, k]))
  return []
}

// ---- synthetic credential shapes, assembled at run time ----------------------

const b64url = (text: string) => Buffer.from(text, 'utf8').toString('base64url')
const SHAPES: Record<string, string> = {
  jwt: [b64url('{"alg":"none","typ":"JWT"}'), b64url('{"sub":"synthetic-test-subject"}'), 'X'.repeat(16)].join('.'),
  bearer: ['Bearer', 'SyntheticToken0123456789'].join(' '),
  bearerLowercase: ['bearer', 'synthetic0123456789'].join(' '),
  stripeShaped: ['sk', 'live', 'X'.repeat(24)].join('_'),
  stripeShapedLowercase: ['sk', 'test', 'x'.repeat(16)].join('_'),
  githubShaped: ['gh' + 'p', 'X0'.repeat(18)].join('_'),
  awsShaped: 'AK' + 'IA' + 'X'.repeat(16),
  privateKeyBlock: ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' '),
  hex32: '0123456789abcdef'.repeat(2),
  hex64: '0123456789abcdef'.repeat(4),
  mixedEntropy: 'Synthetic0Value1'.repeat(2),
}

const AO_SLOTS: Record<string, (p: Record<string, any>, v: string) => void> = {
  scheme: (p, v) => { p.auth_observation.scheme = v },
  'param_names[0]': (p, v) => { p.auth_observation.param_names = [v] },
  'resource_metadata_url path': (p, v) => { p.auth_observation.resource_metadata_url = 'https://notes-mcp.example.com/' + v },
}
function withSlot(slot: string, value: string) {
  const payload = JSON.parse(JSON.stringify(sampleAuthGated))
  AO_SLOTS[slot]!(payload, value)
  return payload
}

// ---- the tests ---------------------------------------------------------------

console.log('auth_observation：凭证形状的字符串进不了签名载荷')

t('两份样例载荷都通过 schema，且全载荷扫描为空（检测器不是见什么都报）', () => {
  for (const sample of [sampleFull, sampleAuthGated]) {
    assert.equal(validate(sample), true, JSON.stringify(validate.errors))
    assert.deepEqual(credentialShapes(sample), [])
  }
  for (const benign of ['bearer', 'dpop', 'realm', 'resource_metadata', 'scope', 'error_description', 'https://notes-mcp.example.com/.well-known/oauth-protected-resource']) {
    assert.deepEqual(credentialShapes(benign), [], benign)
  }
})

t('检测器单独认得每一种凭证形状，而且是被它对应的那条规则认出（每条规则各自都在起作用）', () => {
  const RULE_FOR: Record<string, string> = {
    jwt: 'jwt',
    bearer: 'authorization header value',
    bearerLowercase: 'authorization header value',
    stripeShaped: 'vendor key prefix',
    stripeShapedLowercase: 'vendor key prefix',
    githubShaped: 'vendor key prefix',
    awsShaped: 'vendor key prefix',
    privateKeyBlock: 'private key block',
    hex32: 'long hex run',
    hex64: 'long hex run',
    mixedEntropy: 'high-entropy token',
  }
  assert.deepEqual(Object.keys(RULE_FOR).sort(), Object.keys(SHAPES).sort())
  assert.deepEqual([...new Set(Object.values(RULE_FOR))].sort(), RULES.map(([rule]) => rule).sort(), 'every rule must own at least one shape')
  for (const [name, value] of Object.entries(SHAPES)) {
    assert.ok(credentialShapes(value).includes(`: ${RULE_FOR[name]}`), `${name} was not flagged by "${RULE_FOR[name]}": ${JSON.stringify(credentialShapes(value))}`)
  }
})

t('自家摘要字段只在符合自身 schema pattern 时跳过；同一位置放进别的东西照样扫描', () => {
  assert.notDeepEqual(credentialShapes(sampleFull.suite_digest), [], 'the suite_digest value is itself high-entropy, so the skip is what keeps the sample clean')
  const planted = JSON.parse(JSON.stringify(sampleAuthGated))
  planted.auth_observation.resource_metadata_body_digest = SHAPES.mixedEntropy
  assert.deepEqual(credentialShapes(planted), ['auth_observation.resource_metadata_body_digest: high-entropy token'])
})

t('schema 自己就拒收的组合：scheme 与 param_names 里的大写、空格、点号形状', () => {
  const schemaRejects: Array<[string, string]> = [
    ['scheme', 'jwt'], ['scheme', 'bearer'], ['scheme', 'bearerLowercase'], ['scheme', 'stripeShaped'], ['scheme', 'githubShaped'],
    ['scheme', 'awsShaped'], ['scheme', 'privateKeyBlock'], ['scheme', 'mixedEntropy'],
    ['param_names[0]', 'jwt'], ['param_names[0]', 'bearer'], ['param_names[0]', 'bearerLowercase'], ['param_names[0]', 'stripeShaped'],
    ['param_names[0]', 'githubShaped'], ['param_names[0]', 'awsShaped'], ['param_names[0]', 'privateKeyBlock'], ['param_names[0]', 'hex64'],
    ['param_names[0]', 'mixedEntropy'],
    ['resource_metadata_url path', 'bearer'], ['resource_metadata_url path', 'bearerLowercase'], ['resource_metadata_url path', 'privateKeyBlock'],
  ]
  for (const [slot, shape] of schemaRejects) assert.equal(validate(withSlot(slot, SHAPES[shape]!)), false, `${shape} in ${slot} should fail the schema itself`)
})

t('每个槽位 × 每种形状：要么 schema 拒收，要么全载荷扫描报出该槽位', () => {
  const slotPath: Record<string, string> = {
    scheme: 'auth_observation.scheme',
    'param_names[0]': 'auth_observation.param_names.0',
    'resource_metadata_url path': 'auth_observation.resource_metadata_url',
  }
  for (const slot of Object.keys(AO_SLOTS)) {
    for (const [shape, value] of Object.entries(SHAPES)) {
      const payload = withSlot(slot, value)
      if (validate(payload) === false) continue
      const hits = credentialShapes(payload)
      assert.ok(hits.some((h) => h.startsWith(slotPath[slot] + ': ')), `${shape} in ${slot} passed the schema AND the scan: ${JSON.stringify(hits)}`)
    }
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
