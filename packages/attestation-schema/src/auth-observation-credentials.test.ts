// auth_observation carries text the tested server chose: the challenge's scheme,
// its parameter names and the resource_metadata URL. None of it may ever put a
// credential into a signed payload. Two layers keep it out:
//
//   1. the schema's own shapes (lowercase token, [a-z0-9_-]{1,32} names, an https
//      URL with no userinfo, query or fragment) exclude most credential forms;
//   2. what a shape cannot exclude (a lowercase key in a scheme or a name, anything
//      in a URL path) is caught by credentialShapes() (credential-shapes.ts), run
//      over every string in the payload, as written and percent-decoded.
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
import { CREDENTIAL_SHAPE_RULES, credentialShapes, percentDecoded } from './credential-shapes.ts'

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

// ---- the detector: credential-shapes.ts, the one the probe runs too -----------

const RULES = CREDENTIAL_SHAPE_RULES

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

// Percent-encode every character of `s` (escapes in upper or lower case), so a
// shape survives only through the decoder.
const encodeAll = (s: string, lower = false) => [...s].map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')[lower ? 'toLowerCase' : 'toUpperCase']()).join('')

t('百分号编码过的凭证形状：放进 URL 路径能同时过 schema，检测器解码后照样报出', () => {
  // The case TODO 1009 (2) names: a lowercase test key in a path, with its first letter escaped.
  const lowerKey = SHAPES.stripeShapedLowercase!
  const escaped = '%' + lowerKey.charCodeAt(0).toString(16) + lowerKey.slice(1)
  const payload = withSlot('resource_metadata_url path', escaped)
  assert.equal(validate(payload), true, `the escaped key should pass the schema, so only the scan can stop it: ${JSON.stringify(validate.errors)}`)
  assert.deepEqual(credentialShapes(escaped.slice(0)), [': vendor key prefix'])
  assert.ok(credentialShapes(payload).some((h) => h.startsWith('auth_observation.resource_metadata_url: ')), JSON.stringify(credentialShapes(payload)))
  for (const [name, value] of Object.entries(SHAPES)) {
    for (const lower of [false, true]) {
      const hits = credentialShapes(encodeAll(value, lower))
      assert.ok(hits.length > 0, `${name}, every character escaped (${lower ? 'lower' : 'upper'}-case hex), was not flagged`)
    }
    const twice = encodeAll(encodeAll(value)) // %25XX%25YY…: decoded twice
    assert.ok(credentialShapes(twice).length > 0, `${name}, escaped twice, was not flagged`)
  }
})

t('percentDecoded：只解 %XX，坏的转义原样留着，反复解到不再变化', () => {
  assert.equal(percentDecoded('a%2Fb%2fc'), 'a/b/c')
  assert.equal(percentDecoded('%zz%4'), '%zz%4')
  assert.equal(percentDecoded('%2541'), 'A')
  assert.equal(percentDecoded('plain'), 'plain')
})

t('解码不会让良性 URL 变成误报：样例与常见的 RFC 9728 路径照样干净', () => {
  for (const benign of ['https://notes-mcp.example.com/.well-known/oauth-protected-resource/mcp', 'https://notes-mcp.example.com/a%20b', 'https://notes-mcp.example.com/%7Euser/mcp']) {
    assert.deepEqual(credentialShapes(benign), [], benign)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
