#!/usr/bin/env node
/**
 * Regression tests for verify-attestation.mjs, run as a black-box child
 * process exactly like scan-secrets.test.mjs tests scan-secrets.mjs
 * (execFileSync the real script, assert on exit code / stdout / stderr).
 *
 * This file builds its own minimal, valid DSSE envelope using ONLY WebCrypto
 * (an Ed25519 keypair + crypto.subtle.sign) and @mcpcheckup/canonicalizer's
 * canonicalBytes — never by calling into the production signer's own code,
 * and never by importing @mcpcheckup/attestation-schema's dsse.ts. Same independence
 * reasoning as verify-attestation.mjs itself (see that file's own header
 * comment): if this test built its fixtures with the very code the script
 * exists to double-check, a bug shared between the fixture-builder and the
 * thing under test could cancel out and the test would still pass anyway.
 * So this file has its own tiny, independently-written PAE helper below,
 * exactly like verify-attestation.mjs has its own — three separate
 * implementations now exist (production dsse.ts, the script under test, and
 * this test file), and they only have to agree with each other because they
 * each independently implement the same public DSSE spec, not because any
 * of them import from one another.
 *
 * The one exception is the anti-drift test near the end: it imports
 * @mcpcheckup/attestation-schema on purpose, to pin the verifier's local
 * payloadType list against the schema package's. It builds no fixture with it.
 *
 * Every key is generated at runtime; no key material is stored in this file.
 */
import assert from 'node:assert'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalBytes } from '../canonicalizer/src/index.ts'
import { ATTESTATION_PAYLOAD_TYPE, attestationSchemaForPayloadType } from '../attestation-schema/src/index.ts'

const SCRIPT = fileURLToPath(new URL('./verify-attestation.mjs', import.meta.url))
const PAYLOAD_TYPE = 'application/vnd.mcpcheckup.attestation+json;version=0.1'
const OBSERVED_AT = '2026-09-01T12:00:00.000Z'

// Every payloadType the schema package says it has ever signed, taken from what
// the package already exports: attestationSchemaForPayloadType throws on an
// unknown type and its message lists every type it does know. Each listed type is
// then confirmed to dispatch without throwing, and the current ATTESTATION_PAYLOAD_TYPE
// must be among them, so a change in the message's shape fails loudly here.
function schemaPayloadTypes() {
  let message = ''
  try { attestationSchemaForPayloadType('application/x-not-a-payload-type') } catch (e) { message = String(e && e.message) }
  const marker = 'has only ever signed '
  const at = message.indexOf(marker)
  assert.ok(at >= 0, `the schema package's unknown-type message changed shape: ${message}`)
  const types = [...message.slice(at + marker.length).matchAll(/"([^"]+)"/g)].map((m) => m[1])
  assert.ok(types.length >= 3, `expected the schema package to list its payload types, got ${JSON.stringify(types)}`)
  for (const type of types) assert.doesNotThrow(() => attestationSchemaForPayloadType(type), type)
  assert.ok(types.includes(ATTESTATION_PAYLOAD_TYPE), 'the current ATTESTATION_PAYLOAD_TYPE must be one of the listed types')
  return types
}

let pass = 0, fail = 0
async function t(name, fn) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e && e.stack || e)) }
}

// Independently-written PAE, used only to build this test's own fixtures —
// see header comment for why this must not import dsse.ts's pae() or
// verify-attestation.mjs's own copy.
function buildPreAuth(payloadType, bodyBytes) {
  const enc = new TextEncoder()
  const typeBytes = enc.encode(payloadType)
  const chunks = [
    enc.encode('DSSEv1'), enc.encode(' '),
    enc.encode(String(typeBytes.length)), enc.encode(' '), typeBytes, enc.encode(' '),
    enc.encode(String(bodyBytes.length)), enc.encode(' '), bodyBytes,
  ]
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) { out.set(c, offset); offset += c.length }
  return out
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

// A fresh Ed25519 key with everything a published key document says about it.
async function makeKey() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const spkiBytes = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
  const spkiSha256 = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', spkiBytes)))
  return { privateKey, spkiBytes, spkiBase64: Buffer.from(spkiBytes).toString('base64'), spkiSha256, keyId: spkiSha256.slice(0, 16) }
}

// One entry of the published key document, built the way the endpoint builds
// it: standard base64 SPKI, the full sha256, key_id its first 16 characters,
// RFC 3339 UTC times, null (never absent) for the empty ones.
function keyEntry(key, over = {}) {
  return {
    key_id: key.keyId,
    algorithm: 'Ed25519',
    spki: key.spkiBase64,
    spki_sha256: key.spkiSha256,
    valid_from: '2026-08-01T00:00:00.000Z',
    valid_until: null,
    revoked_at: null,
    ...over,
  }
}
const keyDoc = (...entries) => ({ format_version: 1, keys: entries })

// Builds one real, minimal, validly-signed DSSE envelope. `payloadBytes`
// defaults to canonicalBytes(payloadObj); pass explicit `payloadBytes` for a
// signed-but-not-canonical fixture. `key` defaults to a fresh key; `keyid`
// defaults to the key's real keyid (pass null to omit it).
async function buildEnvelope({ payloadObj, payloadBytes, key, keyid, payloadType = PAYLOAD_TYPE } = {}) {
  const k = key ?? await makeKey()
  const finalPayloadObj = payloadObj ?? {
    canonicalization: 'nfc-jcs/v1',
    suite_id: 'remote-baseline-v0.1',
    observed_at: OBSERVED_AT,
    note: 'verify-attestation.test.mjs fixture — not a real attestation',
  }
  const finalPayloadBytes = payloadBytes ?? canonicalBytes(finalPayloadObj)
  const preAuth = buildPreAuth(payloadType, finalPayloadBytes)
  const sigBytes = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, k.privateKey, preAuth))
  const signature = { sig: Buffer.from(sigBytes).toString('base64') }
  const id = keyid === undefined ? k.keyId : keyid
  if (id !== null) signature.keyid = id
  const envelope = {
    payloadType,
    payload: Buffer.from(finalPayloadBytes).toString('base64'),
    signatures: [signature],
  }
  return { envelope, pubkeyBase64: k.spkiBase64, key: k }
}

function flipOneByte(base64Str) {
  const bytes = Buffer.from(base64Str, 'base64')
  const copy = Buffer.from(bytes)
  copy[0] = copy[0] ^ 0xff
  return copy.toString('base64')
}

function runNode(args, cwd) {
  try {
    const stdout = execFileSync(process.execPath, args, { encoding: 'utf8', cwd, stdio: ['ignore', 'pipe', 'pipe'] })
    return { status: 0, stdout, stderr: '' }
  } catch (e) {
    return {
      status: e.status ?? 1,
      stdout: e.stdout ? e.stdout.toString() : '',
      stderr: e.stderr ? e.stderr.toString() : '',
    }
  }
}

// Runs the real verify-attestation.mjs as a child process against throwaway
// files, then cleans up. `opts.pubkey` is passed as a literal string;
// `opts.keys` is a key document (object, written as JSON) or a raw string.
function runVerify(envelope, opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'verify-attestation-test-'))
  try {
    const envelopePath = join(dir, 'envelope.json')
    writeFileSync(envelopePath, JSON.stringify(envelope), 'utf8')
    const args = [SCRIPT, '--envelope', envelopePath]
    if (opts.pubkey !== undefined) args.push('--pubkey', opts.pubkey)
    if (opts.keys !== undefined) {
      const keysPath = join(dir, 'keys.json')
      writeFileSync(keysPath, typeof opts.keys === 'string' ? opts.keys : JSON.stringify(opts.keys), 'utf8')
      args.push('--keys', keysPath)
    }
    return runNode(args, undefined)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

const passed = (r) => r.status === 0 && /RESULT:\s*PASS/.test(r.stdout)
function assertFails(r, reason, label = '') {
  assert.notEqual(r.status, 0, `expected nonzero exit ${label}\nstdout:\n${r.stdout}\nstderr:\n${r.stderr}`)
  assert.ok(!/RESULT:\s*PASS/.test(r.stdout), `must not print RESULT: PASS ${label}\n${r.stdout}`)
  if (reason) assert.ok(reason.test(r.stdout + r.stderr), `expected ${reason} in output ${label}\nstdout:\n${r.stdout}\nstderr:\n${r.stderr}`)
}
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

console.log('verify-attestation.mjs：黑盒子进程测试（独立构造的 DSSE fixture）')

await t('真实最小合法信封 + 正确 pubkey -> exit 0，输出 RESULT: PASS', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  const r = runVerify(envelope, { pubkey: pubkeyBase64 })
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}\nstdout:\n${r.stdout}\nstderr:\n${r.stderr}`)
  assert.ok(/RESULT:\s*PASS/.test(r.stdout), `expected "RESULT: PASS" in stdout, got:\n${r.stdout}`)
})

await t('翻转 payload 的一个字节（不重新签名) -> exit 非 0（签名不再覆盖新字节）', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  envelope.payload = flipOneByte(envelope.payload)
  const r = runVerify(envelope, { pubkey: pubkeyBase64 })
  assert.notEqual(r.status, 0, 'expected nonzero exit for a tampered payload')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
})

await t('翻转签名的一个字节 -> exit 非 0', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  envelope.signatures[0].sig = flipOneByte(envelope.signatures[0].sig)
  const r = runVerify(envelope, { pubkey: pubkeyBase64 })
  assert.notEqual(r.status, 0, 'expected nonzero exit for a tampered signature')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
})

await t('改成另一个被允许的 payloadType 但不重新签名 -> exit 非 0（证明 PAE 的类型混淆防护真的在起作用，不是被白名单顶替）', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  const other = 'application/vnd.mcpcheckup.attestation+json;version=0.2'
  assert.notEqual(other, envelope.payloadType)
  envelope.payloadType = other
  const r = runVerify(envelope, { pubkey: pubkeyBase64 })
  assert.notEqual(r.status, 0, 'expected nonzero exit when payloadType changes post-signing without re-signing')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
  // The allowlist accepted this type, so the failure must come from the signature itself.
  assert.ok(/signature verification[^\n]*FAIL/.test(r.stdout), `expected the signature check to be what failed, got:\n${r.stdout}`)
  assert.ok(!/payloadType check/.test(r.stdout), 'an allowed payloadType must not trip the allowlist')
})

await t('payload 字节是合法 JSON 且签名正确，但不是 nfc-jcs/v1 的规范编码 -> exit 非 0（第 6 步单独起作用）', async () => {
  const payloadObj = { b: 1, a: 2 }
  // Deliberately NOT canonical: plain JSON.stringify's insertion-order key
  // ordering, not canonicalBytes' sorted-keys/no-whitespace encoding — but
  // signed correctly over exactly these (non-canonical) bytes, so the
  // signature check alone would pass. Only the canonical-bytes comparison
  // step should catch this.
  const nonCanonicalBytes = new TextEncoder().encode(JSON.stringify(payloadObj))
  const { envelope, pubkeyBase64 } = await buildEnvelope({ payloadObj, payloadBytes: nonCanonicalBytes })
  const r = runVerify(envelope, { pubkey: pubkeyBase64 })
  assert.notEqual(r.status, 0, 'expected nonzero exit when payload bytes are not canonical')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
  assert.ok(/canonical/i.test(r.stdout), `expected the canonical-bytes failure to be mentioned in stdout, got:\n${r.stdout}`)
  // Sanity check on this fixture itself: the signature must still verify —
  // otherwise this test wouldn't actually isolate the canonical-bytes check.
  assert.ok(/signature verification[^\n]*PASS/.test(r.stdout), `expected signature verification to PASS on its own, got:\n${r.stdout}`)
})

console.log('\npayloadType 白名单')

await t('不在白名单的 payloadType（即使签名对它是有效的）-> exit 非 0，且在任何验签动作之前就失败', async () => {
  const payloadType = 'application/vnd.mcpcheckup.attestation+json;version=9.9'
  const { envelope, pubkeyBase64 } = await buildEnvelope({ payloadType })
  const r = runVerify(envelope, { pubkey: pubkeyBase64 })
  assertFails(r, /payloadType check: FAIL/)
  assert.ok(!/signatures \(/.test(r.stdout), `no signature work may happen before the payloadType check, got:\n${r.stdout}`)
})

await t('--keys 路径下同样先查白名单', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k, payloadType: 'text/plain' })
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(k)) }), /payloadType check: FAIL/)
})

await t('0.1 / 0.2 / 0.3 三个允许的类型各自（被正确签名后）都能通过', async () => {
  for (const v of ['0.1', '0.2', '0.3']) {
    const payloadType = `application/vnd.mcpcheckup.attestation+json;version=${v}`
    const { envelope, pubkeyBase64 } = await buildEnvelope({ payloadType })
    const r = runVerify(envelope, { pubkey: pubkeyBase64 })
    assert.ok(passed(r), `${payloadType}: expected PASS\n${r.stdout}\n${r.stderr}`)
  }
})

console.log('\n--pubkey：keyid 必须等于 sha256(spki) 前 16 位')

await t('签名有效但 keyid 与给定公钥不符 -> exit 非 0，并说明期望的 keyid', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k, keyid: '0123456789abcdef' })
  const r = runVerify(envelope, { pubkey: k.spkiBase64 })
  assertFails(r, new RegExp(`keyid 0123456789abcdef does not match the given public key \\(its keyid is ${k.keyId}\\)`))
})

await t('签名没有 keyid -> exit 非 0', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k, keyid: null })
  assertFails(runVerify(envelope, { pubkey: k.spkiBase64 }), /keyid \(none\) does not match/)
})

await t('两个签名，一个 keyid 对、一个不对 -> 整体失败（每个签名的 keyid 都要对）', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  envelope.signatures.push({ ...envelope.signatures[0], keyid: 'ffffffffffffffff' })
  assertFails(runVerify(envelope, { pubkey: k.spkiBase64 }), /keyid ffffffffffffffff does not match/)
})

console.log('\n--keys：已发布公钥文档')

await t('happy path：keyid 在文档里、未吊销、observed_at 在有效期内 -> exit 0，并打印命中的钥的 key_id / valid_from / valid_until / revoked_at', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  const r = runVerify(envelope, { keys: keyDoc(keyEntry(k)) })
  assert.ok(passed(r), `expected PASS\n${r.stdout}\n${r.stderr}`)
  assert.ok(r.stdout.includes(`key_id=${k.keyId}`), r.stdout)
  assert.ok(r.stdout.includes('valid_from=2026-08-01T00:00:00.000Z'), r.stdout)
  assert.ok(r.stdout.includes('valid_until=(none)'), r.stdout)
  assert.ok(r.stdout.includes('revoked_at=(none)'), r.stdout)
})

await t('文档里有多把钥（含一把已吊销的旧钥）-> 按 keyid 选钥，不相干的钥不影响结果', async () => {
  const k = await makeKey()
  const old = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  const doc = keyDoc(keyEntry(old, { revoked_at: '2026-08-15T00:00:00Z' }), keyEntry(k))
  assert.ok(passed(runVerify(envelope, { keys: doc })))
})

await t('keyid 不在文档里 -> exit 非 0："keyid … is not in the published key set"', async () => {
  const k = await makeKey()
  const other = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(other)) }), new RegExp(`keyid ${k.keyId} is not in the published key set`))
})

await t('签名没有 keyid -> exit 非 0（无法在文档里查找）', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k, keyid: null })
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(k)) }), /no keyid/)
})

await t('文档是空集合 -> keyid 查不到，失败', async () => {
  const { envelope } = await buildEnvelope()
  assertFails(runVerify(envelope, { keys: keyDoc() }), /is not in the published key set/)
})

await t('已吊销的钥 -> 一律失败，原因里写明吊销时间，不论 observed_at 早晚', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  for (const revokedAt of ['2020-01-01T00:00:00Z', '2099-01-01T00:00:00Z']) {
    const r = runVerify(envelope, { keys: keyDoc(keyEntry(k, { revoked_at: revokedAt })) })
    assertFails(r, new RegExp(`was revoked at ${revokedAt}`), `revoked_at=${revokedAt}`)
  }
})

await t('valid_until 在 observed_at 之后（未来）-> 通过', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  const r = runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_until: '2026-12-31T00:00:00Z' })) })
  assert.ok(passed(r), r.stdout + r.stderr)
  assert.ok(r.stdout.includes('valid_until=2026-12-31T00:00:00Z'), r.stdout)
})

await t('valid_until 在 observed_at 之前 -> 失败，原因点名 valid_until', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_until: '2026-08-31T00:00:00Z' })) }), /is after key \w+'s valid_until 2026-08-31T00:00:00Z/)
})

await t('边界（毫秒精度）：observed_at == valid_until 通过；晚 1 毫秒失败', async () => {
  const k = await makeKey()
  const at = Date.parse(OBSERVED_AT)
  const { envelope } = await buildEnvelope({ key: k })
  const eq = runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_until: new Date(at).toISOString() })) })
  assert.ok(passed(eq), `observed_at == valid_until must pass\n${eq.stdout}`)
  const early = runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_until: new Date(at - 1).toISOString() })) })
  assertFails(early, /is after key \w+'s valid_until/, 'valid_until 1 ms before observed_at')
})

await t('边界（毫秒精度）：observed_at == valid_from 通过；早 1 毫秒失败，原因同时写出两个时间', async () => {
  const k = await makeKey()
  const at = Date.parse(OBSERVED_AT)
  const { envelope } = await buildEnvelope({ key: k })
  const eq = runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_from: new Date(at).toISOString() })) })
  assert.ok(passed(eq), `observed_at == valid_from must pass\n${eq.stdout}`)
  const vf = new Date(at + 1).toISOString()
  const r = runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_from: vf })) })
  assertFails(r, new RegExp(`observed_at ${esc(OBSERVED_AT)} is before key \\w+'s valid_from ${esc(vf)}`), 'valid_from 1 ms after observed_at')
})

await t('时间比较按毫秒的 RFC 3339 瞬间，而不是按字符串：无小数位 / 有小数位的写法等价', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  // OBSERVED_AT is 12:00:00.000Z; the same instant spelled without a fraction.
  assert.ok(passed(runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_from: '2026-09-01T12:00:00Z', valid_until: '2026-09-01T12:00:00Z' })) })))
})

await t('payload 没有 observed_at -> 失败（valid_from 一定有值）', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k, payloadObj: { canonicalization: 'nfc-jcs/v1', note: 'no observed_at' } })
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(k)) }), /observed_at \(missing\) is not an RFC 3339 UTC time/)
})

await t('observed_at 无法解析 / 不是 Z 结尾的 UTC / 日期不存在 -> 失败；valid_until 为空时也一样', async () => {
  const k = await makeKey()
  for (const bad of ['yesterday', '2026-09-01T12:00:00+00:00', '2026-02-31T00:00:00Z', 20260901]) {
    const { envelope } = await buildEnvelope({ key: k, payloadObj: { canonicalization: 'nfc-jcs/v1', observed_at: bad } })
    assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(k, { valid_until: null })) }), /is not an RFC 3339 UTC time/, `observed_at=${JSON.stringify(bad)}`)
  }
})

await t('keyid 对但签名是别的钥签的 -> 失败', async () => {
  const k = await makeKey()
  const signer = await makeKey()
  const { envelope } = await buildEnvelope({ key: signer, keyid: k.keyId })
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(k)) }), /signature verification[^\n]*FAIL/)
})

await t('两个签名，一个的钥已吊销、另一个有效 -> 整体失败（不静默跳过）', async () => {
  const good = await makeKey()
  const bad = await makeKey()
  const { envelope } = await buildEnvelope({ key: good })
  const second = await buildEnvelope({ key: bad })
  envelope.signatures.push(second.envelope.signatures[0])
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(good), keyEntry(bad, { revoked_at: '2026-08-20T00:00:00Z' })) }), /was revoked at/)
})

await t('--keys：两个签名，一个有效、一个的 keyid 不在文档里 -> 整体失败（未知 keyid 不能被另一个有效签名掩盖）', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  const unknown = await makeKey()
  const second = await buildEnvelope({ key: unknown })
  envelope.signatures.push(second.envelope.signatures[0])
  const r = runVerify(envelope, { keys: keyDoc(keyEntry(k)) })
  assertFails(r, new RegExp(`keyid ${unknown.keyId} is not in the published key set`))
  // The listed key's own signature still verifies; only the unknown keyid sinks the run.
  assert.ok(/signature verification[^\n]*PASS/.test(r.stdout), r.stdout)
})

await t('--keys 与 --pubkey 同时给 -> 非 0；两个都不给 -> 非 0', async () => {
  const k = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  assertFails(runVerify(envelope, { keys: keyDoc(keyEntry(k)), pubkey: k.spkiBase64 }), /either --keys or --pubkey/)
  assertFails(runVerify(envelope, {}), /one of --keys \/ --pubkey are required/)
})

console.log('\n--keys：坏文档（每一种都必须非 0 退出并给出原因，绝不静默跳过）')

{
  const k = await makeKey()
  const other = await makeKey()
  const { envelope } = await buildEnvelope({ key: k })
  const urlSafe = k.spkiBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const badHeader = new Uint8Array(k.spkiBytes); badHeader[2] ^= 0x01
  const shortSpki = k.spkiBytes.subarray(0, 43)
  const longSpki = new Uint8Array([...k.spkiBytes, 0])
  const dropped = (field) => { const e = keyEntry(k); delete e[field]; return keyDoc(e) }
  const cases = [
    ['文档不是 JSON', '{not json', /not valid JSON/],
    ['顶层是数组', [], /must be a JSON object/],
    ['format_version 不是 1', { format_version: 2, keys: [keyEntry(k)] }, /format_version must be 1/],
    ['缺 format_version', { keys: [keyEntry(k)] }, /format_version must be 1/],
    ['keys 不是数组', { format_version: 1, keys: {} }, /"keys" array/],
    ['algorithm 不是 Ed25519', keyDoc(keyEntry(k, { algorithm: 'ed25519' })), /algorithm must be "Ed25519"/],
    ['缺 valid_until 字段（必须存在，空时为 null）', dropped('valid_until'), /field valid_until is missing/],
    ['缺 revoked_at 字段', dropped('revoked_at'), /field revoked_at is missing/],
    ['spki 是 url-safe base64', keyDoc(keyEntry(k, { spki: urlSafe })), /standard base64/],
    ['spki 解出 43 字节', keyDoc(keyEntry(k, { spki: Buffer.from(shortSpki).toString('base64') })), /decode to 44 bytes, got 43/],
    ['spki 解出 45 字节', keyDoc(keyEntry(k, { spki: Buffer.from(longSpki).toString('base64') })), /decode to 44 bytes, got 45/],
    ['spki 头不是 Ed25519 的', keyDoc(keyEntry(k, { spki: Buffer.from(badHeader).toString('base64') })), /Ed25519 SubjectPublicKeyInfo header/],
    ['spki_sha256 不是 spki 的 sha256（换成别的钥的）', keyDoc(keyEntry(k, { spki_sha256: other.spkiSha256 })), /spki_sha256 is not the sha256/],
    ['spki_sha256 含大写', keyDoc(keyEntry(k, { spki_sha256: k.spkiSha256.toUpperCase() })), /64 lowercase hex/],
    ['spki_sha256 被截成 16 位', keyDoc(keyEntry(k, { spki_sha256: k.keyId })), /64 lowercase hex/],
    ['key_id 不等于 spki_sha256 前 16 位', keyDoc(keyEntry(k, { key_id: other.keyId })), /key_id must equal the first 16 characters of spki_sha256/],
    ['key_id 是标签而不是派生值', keyDoc(keyEntry(k, { key_id: 'prod-2026-08-22' })), /key_id must equal/],
    ['valid_from 不是 RFC 3339 UTC', keyDoc(keyEntry(k, { valid_from: '2026-08-01' })), /valid_from must be an RFC 3339 UTC time/],
    ['valid_from 带数字时区', keyDoc(keyEntry(k, { valid_from: '2026-08-01T00:00:00+00:00' })), /valid_from must be an RFC 3339 UTC time/],
    ['valid_until 既不是 null 也不是时间', keyDoc(keyEntry(k, { valid_until: '' })), /valid_until must be null or/],
    ['revoked_at 既不是 null 也不是时间', keyDoc(keyEntry(k, { revoked_at: 'never' })), /revoked_at must be null or/],
    ['同一 key_id 出现两次', keyDoc(keyEntry(k), keyEntry(k)), /appears more than once/],
    ['好钥旁边有一把坏钥（不能只跳过坏的）', keyDoc(keyEntry(k), keyEntry(other, { spki_sha256: k.spkiSha256 })), /keys\[1\]/],
  ]
  for (const [name, doc, reason] of cases) {
    await t(`坏文档：${name}`, async () => {
      const r = runVerify(envelope, { keys: doc })
      assertFails(r, reason)
      assert.ok(/invalid keys file/.test(r.stderr), `a bad document is a usage-level error, got:\n${r.stderr}`)
    })
  }
  await t('找不到文档文件 -> 非 0', async () => {
    const r = runNode([SCRIPT, '--envelope', join(tmpdir(), 'no-such-envelope.json'), '--keys', join(tmpdir(), 'no-such-keys.json')], undefined)
    assert.notEqual(r.status, 0)
  })
}

console.log('\n防漂移：本地 payloadType 白名单 == attestation-schema 的列表')

await t('verifier 的 ALLOWED_PAYLOAD_TYPES 与 attestation-schema 自己列出的 payloadType（经 attestationSchemaForPayloadType）逐项相同（含顺序）', () => {
  const src = readFileSync(SCRIPT, 'utf8')
  const m = /const ALLOWED_PAYLOAD_TYPES = Object\.freeze\(\[([\s\S]*?)\]\)/.exec(src)
  assert.ok(m, 'could not find ALLOWED_PAYLOAD_TYPES in verify-attestation.mjs')
  const local = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1])
  assert.ok(local.length > 0)
  assert.deepEqual(local, schemaPayloadTypes())
})

await t('schema 包的每个 payloadType，verifier 实际都接受（行为一致，而不只是文本一致）', async () => {
  for (const payloadType of schemaPayloadTypes()) {
    const { envelope, pubkeyBase64 } = await buildEnvelope({ payloadType })
    const r = runVerify(envelope, { pubkey: pubkeyBase64 })
    assert.ok(passed(r), `${payloadType}: expected PASS\n${r.stdout}\n${r.stderr}`)
  }
})

console.log('\n端到端：按页面上给的两条命令的原样做一遍')

await t('生成钥 -> 按端点的方式拼 keys.json -> 签信封 -> 在放着 <id>.json 和 keys.json 的目录里照抄命令运行 -> exit 0', async () => {
  const k = await makeKey()
  const attestationId = '00000000-0000-4000-8000-000000000001'
  const { envelope } = await buildEnvelope({ key: k })
  // The two commands the site shows, verbatim, with the attestation id filled in.
  const instruction = [
    'curl -fsS https://mcpcheckup.com/.well-known/mcpcheckup-keys.json -o keys.json',
    `node packages/verifier/verify-attestation.mjs --envelope ${attestationId}.json --keys keys.json`,
  ]
  const dir = mkdtempSync(join(tmpdir(), 'verify-attestation-e2e-'))
  try {
    // Stand-in for the curl step: the same bytes the endpoint would serve.
    writeFileSync(join(dir, 'keys.json'), JSON.stringify(keyDoc(keyEntry(k))), 'utf8')
    writeFileSync(join(dir, `${attestationId}.json`), JSON.stringify(envelope), 'utf8')
    const tokens = instruction[1].split(' ')
    assert.equal(tokens[0], 'node')
    assert.equal(tokens[1], 'packages/verifier/verify-attestation.mjs')
    const r = runNode([SCRIPT, ...tokens.slice(2)], dir)
    assert.ok(passed(r), `expected PASS\n${r.stdout}\n${r.stderr}`)
    // The same command against a flipped signature byte must fail.
    const tampered = structuredClone(envelope)
    tampered.signatures[0].sig = flipOneByte(tampered.signatures[0].sig)
    writeFileSync(join(dir, `${attestationId}.json`), JSON.stringify(tampered), 'utf8')
    assertFails(runNode([SCRIPT, ...tokens.slice(2)], dir), /RESULT:\s*FAIL/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
