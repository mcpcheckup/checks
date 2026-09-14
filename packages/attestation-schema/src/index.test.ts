import assert from 'node:assert'
import * as pkg from './index.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('index：公开 API 面')

t('导出 DSSE 原语', () => {
  assert.equal(typeof pkg.pae, 'function')
  assert.equal(typeof pkg.signDsseEnvelope, 'function')
  assert.equal(typeof pkg.verifyDsseEnvelope, 'function')
  assert.equal(typeof pkg.verifyDsseSignature, 'function')
  assert.equal(typeof pkg.base64Encode, 'function')
  assert.equal(typeof pkg.base64Decode, 'function')
})

t('导出 attestation 专属常量与签名助手', () => {
  assert.equal(pkg.ATTESTATION_PAYLOAD_TYPE, 'application/vnd.mcpcheckup.attestation+json;version=0.3')
  assert.equal(typeof pkg.signAttestationPayload, 'function')
})

t('导出 JSON Schema 本体（不是路径，是已经 parse 好的对象）', () => {
  assert.equal(typeof pkg.ATTESTATION_SCHEMA, 'object')
  assert.equal(pkg.ATTESTATION_SCHEMA.$schema, 'https://json-schema.org/draft/2020-12/schema')
})

t('导出代码层不变式检查', () => {
  assert.equal(typeof pkg.assertUnverifiedHasReason, 'function')
  assert.equal(typeof pkg.AssertionInvariantError, 'function')
})

console.log('\nindex：ATTESTATION_SCHEMA_V0_2 —— v0.3 之前签发的信封仍然有对应的 schema')

t('导出归档的 v0.2 schema 本体，且与当前 schema、v0.1 schema 是三个不同对象', () => {
  assert.equal(typeof pkg.ATTESTATION_SCHEMA_V0_2, 'object')
  assert.equal(pkg.ATTESTATION_SCHEMA_V0_2.$id, 'https://mcpcheckup.com/schema/attestation-payload-v0.2.json')
  assert.notEqual(pkg.ATTESTATION_SCHEMA_V0_2, pkg.ATTESTATION_SCHEMA)
  assert.notEqual(pkg.ATTESTATION_SCHEMA_V0_2, pkg.ATTESTATION_SCHEMA_V0_1)
})

console.log('\nattestationSchemaForPayloadType：按 DSSE 的 payloadType 派发 schema')

t('三个已签发过的 payloadType 各自派发到对应的 schema', () => {
  assert.equal(
    pkg.attestationSchemaForPayloadType('application/vnd.mcpcheckup.attestation+json;version=0.1'),
    pkg.ATTESTATION_SCHEMA_V0_1,
  )
  assert.equal(
    pkg.attestationSchemaForPayloadType('application/vnd.mcpcheckup.attestation+json;version=0.2'),
    pkg.ATTESTATION_SCHEMA_V0_2,
  )
  assert.equal(
    pkg.attestationSchemaForPayloadType('application/vnd.mcpcheckup.attestation+json;version=0.3'),
    pkg.ATTESTATION_SCHEMA,
  )
})

t('本包当前签发用的 ATTESTATION_PAYLOAD_TYPE 派发到 ATTESTATION_SCHEMA（签什么就按什么校验，不会各走各的）', () => {
  assert.equal(pkg.attestationSchemaForPayloadType(pkg.ATTESTATION_PAYLOAD_TYPE), pkg.ATTESTATION_SCHEMA)
})

t('未知 / 缺版本的 payloadType → 抛错，绝不静默回落到当前 schema', () => {
  const unknown = [
    'application/vnd.mcpcheckup.attestation+json;version=0.4', // 未来版本
    'application/vnd.mcpcheckup.attestation+json;version=0.0', // 从未签发过
    'application/vnd.mcpcheckup.attestation+json', // 整个 version 参数缺失
    'application/vnd.mcpcheckup.attestation+json;version=0.3 ', // 尾随空格：不是同一个字符串
    'application/vnd.mcpcheckup.attestation+json;VERSION=0.3', // 大小写不同
    'application/vnd.in-toto+json', // 别的应用的信封
    '',
  ]
  for (const payloadType of unknown) {
    assert.throws(
      () => pkg.attestationSchemaForPayloadType(payloadType),
      (e: unknown) => e instanceof Error && e.message.includes('unknown attestation payloadType'),
      `payloadType=${JSON.stringify(payloadType)} 应当抛错，而不是返回任何 schema`,
    )
  }
})

t('原型链上的属性名（__proto__ / constructor / toString）同样抛错——查表用的是 Map，不是对象字面量', () => {
  // 对象字面量做查表时，这三个键会命中继承来的值而不是 undefined，
  // 于是它们会被"派发"到某个根本不是 schema 的东西上，而不是被响亮拒绝。
  for (const payloadType of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.throws(
      () => pkg.attestationSchemaForPayloadType(payloadType),
      (e: unknown) => e instanceof Error && e.message.includes('unknown attestation payloadType'),
      `payloadType=${JSON.stringify(payloadType)} 应当抛错`,
    )
  }
})

t('抛出的错误信息里带上收到的 payloadType 和本包签发过的全部 payloadType（红灯时能自己解释）', () => {
  let message = ''
  try {
    pkg.attestationSchemaForPayloadType('application/vnd.mcpcheckup.attestation+json;version=9.9')
  } catch (e) {
    message = (e as Error).message
  }
  assert.ok(message.includes('version=9.9'), `错误信息应当带上收到的值，实际是 ${JSON.stringify(message)}`)
  for (const known of ['version=0.1', 'version=0.2', 'version=0.3']) {
    assert.ok(message.includes(known), `错误信息应当列出 ${known}，实际是 ${JSON.stringify(message)}`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
