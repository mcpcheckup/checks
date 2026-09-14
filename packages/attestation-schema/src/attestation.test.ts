import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { canonicalize } from '@mcpcheckup/canonicalizer'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import { ATTESTATION_PAYLOAD_TYPE, signAttestationPayload } from './attestation.ts'
import { verifyDsseEnvelope, base64Decode, base64Encode } from './dsse.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

async function generateKeyPair() {
  return crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as Promise<CryptoKeyPair>
}

const schema = JSON.parse(readFileSync(new URL('../schema/attestation.schema.json', import.meta.url), 'utf8'))
const sample = JSON.parse(readFileSync(new URL('../test/fixtures/attestation.sample.json', import.meta.url), 'utf8'))

function validator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true })
  addFormats(ajv)
  return ajv.compile(schema)
}

console.log('attestation: payloadType 常量')

await t('ATTESTATION_PAYLOAD_TYPE 是给定的确切字符串', () => {
  assert.equal(ATTESTATION_PAYLOAD_TYPE, 'application/vnd.mcpcheckup.attestation+json;version=0.3')
})

console.log('\nattestation: signAttestationPayload 端到端')

await t('用真实样例签名 → DSSE 验签通过', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const envelope = await signAttestationPayload(sample, privateKey)
  assert.equal(envelope.payloadType, ATTESTATION_PAYLOAD_TYPE)
  const ok = await verifyDsseEnvelope(envelope, publicKey)
  assert.equal(ok, true)
})

await t('签名覆盖的字节就是 nfc-jcs/v1 canonicalize(payload)，不是随手 JSON.stringify', async () => {
  const { privateKey } = await generateKeyPair()
  const envelope = await signAttestationPayload(sample, privateKey)
  const decoded = new TextDecoder().decode(base64Decode(envelope.payload))
  assert.equal(decoded, canonicalize(sample))
})

await t('signAttestationPayload 产出的 payload 解码后仍然通过 schema 校验（三块拼在一起是自洽的）', async () => {
  const { privateKey } = await generateKeyPair()
  const envelope = await signAttestationPayload(sample, privateKey)
  const decoded = JSON.parse(new TextDecoder().decode(base64Decode(envelope.payload)))
  const validate = validator()
  const ok = validate(decoded)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

await t('篡改已签名 payload 的一个字节 → 验签失败（反例）', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const envelope = await signAttestationPayload(sample, privateKey)
  const tamperedPayload = JSON.parse(canonicalize(sample))
  tamperedPayload.toolset_fingerprint = 'sha256:' + '0'.repeat(64)
  const tamperedBytes = new TextEncoder().encode(canonicalize(tamperedPayload))
  const tampered = { ...envelope, payload: base64Encode(tamperedBytes) }
  const ok = await verifyDsseEnvelope(tampered, publicKey)
  assert.equal(ok, false)
})

await t('keyid 透传给底层 DSSE 签名', async () => {
  const { privateKey } = await generateKeyPair()
  const envelope = await signAttestationPayload(sample, privateKey, { keyid: 'signer-2026-08' })
  assert.equal(envelope.signatures[0]!.keyid, 'signer-2026-08')
})

console.log('\nattestation: suite_commit 进入 canonicalize / 签名字节')

await t('canonicalize 对 suite_commit 的位置不敏感——键的插入顺序不同，规范化后的字节完全一致', () => {
  // 同一份 payload 的两种构造顺序：一种把 suite_commit 放在最后插入，
  // 一种在最前。nfc-jcs/v1 按键排序，所以两者必须产出同一串字节——
  // 否则同一份内容会因为组装顺序不同而得到两个不同的签名。
  const { suite_commit, ...withoutCommit } = sample
  const commitLast = { ...withoutCommit, suite_commit }
  const commitFirst = { suite_commit, ...withoutCommit }
  assert.notDeepStrictEqual(Object.keys(commitLast), Object.keys(commitFirst), '两种构造的键顺序本身必须不同，否则这条断言什么也没测')
  assert.equal(canonicalize(commitLast), canonicalize(commitFirst))
  assert.equal(canonicalize(commitLast), canonicalize(sample))
})

await t('canonicalize 是确定的：同一份带 suite_commit 的 payload 连续规范化多次，字节完全一致', () => {
  const first = canonicalize(sample)
  for (let i = 0; i < 5; i++) assert.equal(canonicalize(sample), first)
})

await t('suite_commit 真的出现在规范化后的字节里（没有被投影悄悄丢掉）', () => {
  const bytes = canonicalize(sample)
  assert.ok(
    bytes.includes(`"suite_commit":"${sample.suite_commit}"`),
    `规范化结果里找不到 suite_commit——它没有进入签名字节：${bytes.slice(0, 200)}`,
  )
})

await t('篡改已签名 payload 的 suite_commit → 验签失败（反例：这个字段确实被签名覆盖，不是旁注）', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const envelope = await signAttestationPayload(sample, privateKey)
  const tamperedPayload = JSON.parse(canonicalize(sample))
  tamperedPayload.suite_commit = 'f'.repeat(40)
  assert.notEqual(tamperedPayload.suite_commit, sample.suite_commit)
  const tamperedBytes = new TextEncoder().encode(canonicalize(tamperedPayload))
  const tampered = { ...envelope, payload: base64Encode(tamperedBytes) }
  assert.equal(await verifyDsseEnvelope(tampered, publicKey), false)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
