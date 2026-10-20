import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8')
const schema = JSON.parse(read('../schema/attestation.schema.json'))
const schemaV03 = JSON.parse(read('../schema/attestation-payload-v0.3.json'))
const sampleFull = JSON.parse(read('../test/fixtures/attestation.sample.json'))
const sampleAuthGated = JSON.parse(read('../test/fixtures/attestation-auth-gated.sample.json'))
const sampleV03 = JSON.parse(read('../test/fixtures/attestation-v0.3.sample.json'))

function compile(s: object) {
  const ajv = new Ajv2020({ allErrors: true, strict: true })
  addFormats(ajv)
  return ajv.compile(s)
}
const validate = compile(schema)
const validateV03 = compile(schemaV03)

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v))
/** A copy of `base` with each [path, value] applied; the value undefined deletes the key. */
function edit(base: Record<string, unknown>, ...changes: Array<[string[], unknown]>): Record<string, unknown> {
  const out = clone(base)
  for (const [path, value] of changes) {
    let cursor: any = out
    for (const key of path.slice(0, -1)) cursor = cursor[key]
    const last = path[path.length - 1]!
    if (value === undefined) delete cursor[last]
    else cursor[last] = value
  }
  return out
}
function accepts(payload: unknown, why: string) {
  const ok = validate(payload)
  assert.equal(ok, true, `${why}: should validate, got ${JSON.stringify(validate.errors)}`)
}
function rejects(payload: unknown, why: string) {
  assert.equal(validate(payload), false, `${why}: should be rejected, but validated`)
}
const AO = ['auth_observation']
const HOST = 'notes-mcp.example.com'
const HTTPS = 'https://'

console.log('attestation-payload-v0.3.json：归档就是 v0.4 之前的 attestation.schema.json，一个字节都没改')

t('归档文件的 sha256 等于 v0.4 之前最后一版 schema/attestation.schema.json 的 sha256', () => {
  // The value is the sha256 of the committed blob of schema/attestation.schema.json
  // as it stood immediately before the v0.4 bump. CRLF is folded to LF first: a
  // checkout with core.autocrlf rewrites line endings on disk, which is not a
  // content change (generated-types-freshness.test.ts does the same).
  const bytes = read('../schema/attestation-payload-v0.3.json').replace(/\r\n/g, '\n')
  assert.equal(createHash('sha256').update(bytes, 'utf8').digest('hex'), '3fbae445952309ab0cfbbcf2ff4963f8820368d97604ec917266e73ba6084cbc')
})

console.log('\nv0.4：coverage=full 恰好是 v0.3 加 coverage 与 run_id')

t('v0.4 的 properties 与 required 相对 v0.3 只多出 coverage / run_id（auth_observation 只是 properties，不是 required）', () => {
  const added = ['coverage', 'run_id', 'auth_observation']
  assert.deepEqual(Object.keys(schema.properties).filter((k) => !added.includes(k)).sort(), Object.keys(schemaV03.properties).sort())
  assert.deepEqual([...schema.required].sort(), [...schemaV03.required, 'coverage', 'run_id'].sort())
})

t('v0.4 full 样例删去 coverage 与 run_id 后通过 v0.3 归档 schema；v0.3 样例补上二者后通过 v0.4', () => {
  const ok = validateV03(edit(sampleFull, [['coverage'], undefined], [['run_id'], undefined]))
  assert.equal(ok, true, JSON.stringify(validateV03.errors))
  accepts(edit(sampleV03, [['coverage'], 'full'], [['run_id'], sampleFull.run_id]), 'v0.3 sample + coverage full + run_id')
})

t('full 下 protocol_revision / toolset_fingerprint / schema_fingerprint 任一为 null → 拒绝', () => {
  for (const field of ['protocol_revision', 'toolset_fingerprint', 'schema_fingerprint']) rejects(edit(sampleFull, [[field], null]), `full with ${field} null`)
})

t('full 下出现 auth_observation（哪怕形状合法）→ 拒绝', () => {
  rejects(edit(sampleFull, [AO, sampleAuthGated.auth_observation]), 'full with auth_observation')
})

console.log('\nv0.4：coverage 与 run_id')

t('coverage 或 run_id 缺失 → 拒绝；coverage 只认 full / auth_gated', () => {
  rejects(edit(sampleFull, [['coverage'], undefined]), 'coverage missing')
  rejects(edit(sampleFull, [['run_id'], undefined]), 'run_id missing')
  for (const bad of ['partial', 'FULL', 'auth-gated', '', null]) rejects(edit(sampleFull, [['coverage'], bad]), `coverage=${JSON.stringify(bad)}`)
})

t('run_id 必须是小写、带连字符的 8-4-4-4-12 UUID', () => {
  for (const good of ['00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff', sampleAuthGated.run_id]) {
    accepts(edit(sampleFull, [['run_id'], good]), `run_id=${good}`)
  }
  const valid: string = sampleFull.run_id
  for (const bad of [
    valid.toUpperCase(),
    valid.replace(/-/g, ''),
    `{${valid}}`,
    `urn:uuid:${valid}`,
    valid.slice(0, -1),
    valid + '0',
    valid.slice(0, -1) + 'g',
    ` ${valid}`,
    valid.slice(0, 8) + valid.slice(9, 13) + '-' + valid.slice(13),
  ]) rejects(edit(sampleFull, [['run_id'], bad]), `run_id=${JSON.stringify(bad)}`)
})

console.log('\nv0.4：coverage=auth_gated')

t('auth_gated 样例通过；protocol_revision 为日期也通过（握手先声明了版本、认证墙后到）', () => {
  accepts(sampleAuthGated, 'auth_gated sample')
  accepts(edit(sampleAuthGated, [['protocol_revision'], '2026-07-28']), 'auth_gated with a declared revision')
})

t('auth_gated 下任一指纹非 null、缺 auth_observation、protocol_revision 形状不对 → 拒绝', () => {
  const digest = 'sha256:' + '0'.repeat(64)
  rejects(edit(sampleAuthGated, [['toolset_fingerprint'], digest]), 'auth_gated with a toolset_fingerprint')
  rejects(edit(sampleAuthGated, [['schema_fingerprint'], digest]), 'auth_gated with a schema_fingerprint')
  rejects(edit(sampleAuthGated, [AO, undefined]), 'auth_gated without auth_observation')
  for (const bad of ['2026-13-01', '2026-07-28T00:00:00Z', '', 'x']) rejects(edit(sampleAuthGated, [['protocol_revision'], bad]), `protocol_revision=${bad}`)
})

t('auth_gated 只对 remote target 成立：stdio target（HTTP 401 无从谈起）→ 拒绝，即使其它 stdio 字段都合法', () => {
  const stdio = edit(
    sampleAuthGated,
    [['target'], { provider: 'example-notes-co', name: 'notes-mcp-stdio', transport: 'stdio', endpoint_url: null, package_ref: 'example-notes-mcp-server' }],
    [['launch_config_digest'], 'sha256:' + '1'.repeat(64)],
    [['probe_dns_answer_changed'], null],
  )
  rejects(stdio, 'auth_gated with a stdio target')
  accepts(edit(stdio, [['coverage'], 'full'], [AO, undefined], [['protocol_revision'], '2026-07-28'], [['toolset_fingerprint'], sampleFull.toolset_fingerprint], [['schema_fingerprint'], sampleFull.schema_fingerprint]), 'the same stdio payload as full')
})

console.log('\nv0.4：auth_observation 的形状')

t('五个键缺一不可，多一个也不行，整体不能是 null', () => {
  for (const key of Object.keys(sampleAuthGated.auth_observation)) rejects(edit(sampleAuthGated, [[...AO, key], undefined]), `auth_observation.${key} missing`)
  rejects(edit(sampleAuthGated, [[...AO, 'realm'], 'mcp']), 'auth_observation with an extra key')
  rejects(edit(sampleAuthGated, [AO, null]), 'auth_observation null')
})

t('scheme：小写 token，1 到 64 个字符', () => {
  for (const good of ['bearer', 'dpop', 'a'.repeat(64), "!#$%&'*+-.^_`|~0z"]) accepts(edit(sampleAuthGated, [[...AO, 'scheme'], good]), `scheme=${good}`)
  for (const bad of ['Bearer', 'bearer realm', '', 'a'.repeat(65), 'bear,er', 'bear"er', 'bear=er']) {
    rejects(edit(sampleAuthGated, [[...AO, 'scheme'], bad]), `scheme=${JSON.stringify(bad)}`)
  }
})

t('param_names：每个 1 到 32 个 [a-z0-9_-]，不重复，最多 16 个；空数组可以', () => {
  const sixteen = Array.from({ length: 16 }, (_, i) => `p${String(i).padStart(2, '0')}`)
  for (const good of [[], ['a'.repeat(32)], sixteen]) accepts(edit(sampleAuthGated, [[...AO, 'param_names'], good]), `param_names=${JSON.stringify(good)}`)
  for (const bad of [['Realm'], ['re.alm'], [''], ['a'.repeat(33)], ['realm', 'realm'], [...sixteen, 'p16'], ['realm', 1], ['realm=mcp'], 'realm']) {
    rejects(edit(sampleAuthGated, [[...AO, 'param_names'], bad]), `param_names=${JSON.stringify(bad)}`)
  }
})

t('resource_metadata_url：只收 https、无 userinfo / query / fragment、不超过 512 个字符的 URL', () => {
  const at512 = HTTPS + HOST + '/' + 'a'.repeat(512 - (HTTPS + HOST + '/').length)
  assert.equal(at512.length, 512)
  for (const good of [at512, HTTPS + HOST, HTTPS + HOST + ':8443/.well-known/oauth-protected-resource/mcp', HTTPS + HOST + '/a%20b']) {
    accepts(edit(sampleAuthGated, [[...AO, 'resource_metadata_url'], good]), `url=${good}`)
  }
  for (const bad of [
    at512 + 'a',
    'http://' + HOST + '/x',
    'HTTPS://' + HOST + '/x',
    HTTPS + 'u' + '@' + HOST + '/x',
    HTTPS + 'u:p' + '@' + HOST + '/x',
    HTTPS + HOST + '/x?y=1',
    HTTPS + HOST + '/x?',
    HTTPS + HOST + '/x#f',
    HTTPS + HOST + '/a b',
    HTTPS + '/x',
    'not a url',
    '',
  ]) rejects(edit(sampleAuthGated, [[...AO, 'resource_metadata_url'], bad]), `url=${JSON.stringify(bad)}`)
})

t('withheld=true 时 URL 必须是 null；withheld=true 加 null URL 通过，body digest 有无都可以', () => {
  rejects(edit(sampleAuthGated, [[...AO, 'resource_metadata_url_withheld'], true]), 'withheld true with a URL')
  const withheld = edit(sampleAuthGated, [[...AO, 'resource_metadata_url_withheld'], true], [[...AO, 'resource_metadata_url'], null])
  accepts(withheld, 'withheld true, URL null, digest present')
  accepts(edit(withheld, [[...AO, 'resource_metadata_body_digest'], null]), 'withheld true, URL null, digest null')
  for (const bad of ['true', 1, null]) rejects(edit(sampleAuthGated, [[...AO, 'resource_metadata_url_withheld'], bad]), `withheld=${JSON.stringify(bad)}`)
})

t('没有 URL 也没有 withheld（质询没给 resource_metadata）时 body digest 必须是 null', () => {
  const noUrl = edit(sampleAuthGated, [[...AO, 'resource_metadata_url'], null])
  rejects(noUrl, 'no URL, not withheld, digest present')
  accepts(edit(noUrl, [[...AO, 'resource_metadata_body_digest'], null]), 'no URL, not withheld, digest null')
})

t('resource_metadata_body_digest：sha256:<64 位小写十六进制> 或 null', () => {
  const hex = '5636c76419a211c1efec547f90d889bf5ee7c42f3ad5b0defefd1703618833f2'
  for (const bad of ['sha256:' + hex.toUpperCase(), hex, 'sha512:' + hex, 'sha256:' + hex.slice(1), '']) {
    rejects(edit(sampleAuthGated, [[...AO, 'resource_metadata_body_digest'], bad]), `digest=${JSON.stringify(bad)}`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
