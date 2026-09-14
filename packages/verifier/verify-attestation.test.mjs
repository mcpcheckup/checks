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
 */
import assert from 'node:assert'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalBytes } from '../canonicalizer/src/index.ts'

const SCRIPT = fileURLToPath(new URL('./verify-attestation.mjs', import.meta.url))
const PAYLOAD_TYPE = 'application/vnd.mcpcheckup.attestation+json;version=0.1'

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

// Builds one real, minimal, validly-signed DSSE envelope + the matching
// SPKI-base64 public key, from a fresh Ed25519 keypair generated via
// WebCrypto. `payloadBytes` defaults to canonicalBytes(payloadObj); pass an
// explicit `payloadBytes` to build a signed-but-not-canonical fixture.
async function buildEnvelope({ payloadObj, payloadBytes } = {}) {
  const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const spkiBytes = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))
  const pubkeyBase64 = Buffer.from(spkiBytes).toString('base64')

  const finalPayloadObj = payloadObj ?? {
    canonicalization: 'nfc-jcs/v1',
    suite_id: 'remote-baseline-v0.1',
    note: 'verify-attestation.test.mjs fixture — not a real attestation',
  }
  const finalPayloadBytes = payloadBytes ?? canonicalBytes(finalPayloadObj)

  const preAuth = buildPreAuth(PAYLOAD_TYPE, finalPayloadBytes)
  const sigBytes = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, preAuth))

  const envelope = {
    payloadType: PAYLOAD_TYPE,
    payload: Buffer.from(finalPayloadBytes).toString('base64'),
    signatures: [{ keyid: 'test-key', sig: Buffer.from(sigBytes).toString('base64') }],
  }
  return { envelope, pubkeyBase64 }
}

function flipOneByte(base64Str) {
  const bytes = Buffer.from(base64Str, 'base64')
  const copy = Buffer.from(bytes)
  copy[0] = copy[0] ^ 0xff
  return copy.toString('base64')
}

// Runs the real verify-attestation.mjs as a child process against a
// throwaway envelope.json, then cleans up. Never writes a pubkey file — the
// script's --pubkey also accepts a raw base64 string directly, which keeps
// this helper simple (both input modes are still exercised: envelope always
// via a file path, pubkey always via a literal string).
function runVerify(envelope, pubkeyBase64) {
  const dir = mkdtempSync(join(tmpdir(), 'verify-attestation-test-'))
  try {
    const envelopePath = join(dir, 'envelope.json')
    writeFileSync(envelopePath, JSON.stringify(envelope), 'utf8')
    try {
      const stdout = execFileSync(
        process.execPath,
        [SCRIPT, '--envelope', envelopePath, '--pubkey', pubkeyBase64],
        { encoding: 'utf8' },
      )
      return { status: 0, stdout, stderr: '' }
    } catch (e) {
      return {
        status: e.status ?? 1,
        stdout: e.stdout ? e.stdout.toString() : '',
        stderr: e.stderr ? e.stderr.toString() : '',
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

console.log('verify-attestation.mjs：黑盒子进程测试（独立构造的 DSSE fixture）')

await t('真实最小合法信封 + 正确 pubkey -> exit 0，输出 RESULT: PASS', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  const r = runVerify(envelope, pubkeyBase64)
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}\nstdout:\n${r.stdout}\nstderr:\n${r.stderr}`)
  assert.ok(/RESULT:\s*PASS/.test(r.stdout), `expected "RESULT: PASS" in stdout, got:\n${r.stdout}`)
})

await t('翻转 payload 的一个字节（不重新签名) -> exit 非 0（签名不再覆盖新字节）', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  envelope.payload = flipOneByte(envelope.payload)
  const r = runVerify(envelope, pubkeyBase64)
  assert.notEqual(r.status, 0, 'expected nonzero exit for a tampered payload')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
})

await t('翻转签名的一个字节 -> exit 非 0', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  envelope.signatures[0].sig = flipOneByte(envelope.signatures[0].sig)
  const r = runVerify(envelope, pubkeyBase64)
  assert.notEqual(r.status, 0, 'expected nonzero exit for a tampered signature')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
})

await t('改动 payloadType 但不重新签名 -> exit 非 0（证明 PAE 的类型混淆防护真的在起作用）', async () => {
  const { envelope, pubkeyBase64 } = await buildEnvelope()
  envelope.payloadType = envelope.payloadType + '.tampered'
  const r = runVerify(envelope, pubkeyBase64)
  assert.notEqual(r.status, 0, 'expected nonzero exit when payloadType changes post-signing without re-signing')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
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
  const r = runVerify(envelope, pubkeyBase64)
  assert.notEqual(r.status, 0, 'expected nonzero exit when payload bytes are not canonical')
  assert.ok(/RESULT:\s*FAIL/.test(r.stdout), `expected "RESULT: FAIL" in stdout, got:\n${r.stdout}`)
  assert.ok(/canonical/i.test(r.stdout), `expected the canonical-bytes failure to be mentioned in stdout, got:\n${r.stdout}`)
  // Sanity check on this fixture itself: the signature must still verify —
  // otherwise this test wouldn't actually isolate the canonical-bytes check.
  assert.ok(/signature verification[^\n]*PASS/.test(r.stdout), `expected signature verification to PASS on its own, got:\n${r.stdout}`)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
