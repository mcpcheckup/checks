import assert from 'node:assert'
import {
  pae,
  base64Encode,
  base64Decode,
  signDsseEnvelope,
  verifyDsseEnvelope,
  verifyDsseSignature,
} from './dsse.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

async function generateKeyPair() {
  return crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as Promise<CryptoKeyPair>
}

console.log('DSSE: PAE (Pre-Authentication Encoding)')

await t('官方 test vector（secure-systems-lab/dsse protocol.md「Test Vectors」）：逐字节匹配', () => {
  // PAYLOAD_TYPE = "http://example.com/HelloWorld" (29 字节 UTF-8)
  // SERIALIZED_BODY = "hello world" (11 字节 UTF-8)
  // 官方给出的 PAE 明文：DSSEv1 29 http://example.com/HelloWorld 11 hello world
  // 官方给出的 base64(SERIALIZED_BODY)：aGVsbG8gd29ybGQ=
  const type = 'http://example.com/HelloWorld'
  const body = new TextEncoder().encode('hello world')
  const result = pae(type, body)
  const resultText = new TextDecoder().decode(result)
  assert.equal(resultText, 'DSSEv1 29 http://example.com/HelloWorld 11 hello world')
  assert.equal(base64Encode(body), 'aGVsbG8gd29ybGQ=')
})

await t('LEN() 是十进制、无前导零，空字符串长度是 "0" 不是 "00" 或省略', () => {
  const result = pae('', new Uint8Array(0))
  const resultText = new TextDecoder().decode(result)
  assert.equal(resultText, 'DSSEv1 0  0 ')
})

await t('payloadType 用 UTF-8 编码后参与长度计算，不是 JS 字符串 .length（多字节字符会不同）', () => {
  // U+20AC (€) 是 1 个 UTF-16 code unit，但 UTF-8 是 3 字节——LEN() 必须数字节，不是 code unit。
  const type = String.fromCodePoint(0x20ac)
  const body = new Uint8Array(0)
  const result = pae(type, body)
  const resultText = new TextDecoder().decode(result)
  assert.equal(resultText, `DSSEv1 3 ${type} 0 `)
})

await t('body 是不透明字节，即便内容里恰好出现空格或类似 PAE 语法的文本，也不会打乱边界', () => {
  const type = 'text/plain'
  const body = new TextEncoder().encode('11 hello world DSSEv1 99 injected')
  const result = pae(type, body)
  // 只要长度前缀正确，body 里出现什么内容都不影响解析——这正是 PAE 要显式带长度而不是
  // 用分隔符的原因。这里验证：声明的长度之后，剩下的字节原样就是 body，一个不多一个不少。
  const resultText = new TextDecoder().decode(result)
  const prefix = `DSSEv1 ${new TextEncoder().encode(type).length} ${type} ${body.length} `
  assert.ok(resultText.startsWith(prefix))
  assert.equal(resultText.slice(prefix.length), new TextDecoder().decode(body))
})

console.log('\nDSSE: base64 编解码')

await t('往返：任意字节 → base64 → 字节，不丢不改', () => {
  const bytes = new Uint8Array([0, 1, 2, 254, 255, 128, 127, 16, 32])
  assert.deepEqual(base64Decode(base64Encode(bytes)), bytes)
})

await t('是标准 base64（含 + /），不是 base64url（含 - _）——只测往返相等测不出这个，因为 base64url 编解码器自己和自己往返也会相等', () => {
  const bytes = new Uint8Array([0, 1, 2, 254, 255, 128, 127, 16, 32])
  const encoded = base64Encode(bytes)
  // 独立算出的期望值（Node Buffer.toString('base64')，标准 base64）：'AAEC/v+AfxAg'
  assert.equal(encoded, 'AAEC/v+AfxAg')
  assert.ok(encoded.includes('+') && encoded.includes('/'), '这组字节的标准 base64 输出应该同时含 + 和 /')
  assert.ok(!encoded.includes('-') && !encoded.includes('_'), 'base64url 会用 - 和 _ 代替 + 和 /——不应该出现')
})

console.log('\nDSSE: 签名与验签（Ed25519，通过 WebCrypto）')

await t('sign → verify：合法签名验签通过', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const body = new TextEncoder().encode('{"a":1}')
  const envelope = await signDsseEnvelope('application/vnd.example+json', body, privateKey)
  const ok = await verifyDsseEnvelope(envelope, publicKey)
  assert.equal(ok, true)
})

await t('envelope 形状符合 DSSE 标准 JSON envelope（payload/payloadType/signatures[].sig 为 base64）', async () => {
  const { privateKey } = await generateKeyPair()
  const body = new TextEncoder().encode('hello world')
  const envelope = await signDsseEnvelope('http://example.com/HelloWorld', body, privateKey)
  assert.equal(envelope.payloadType, 'http://example.com/HelloWorld')
  assert.equal(envelope.payload, 'aGVsbG8gd29ybGQ=')
  assert.equal(envelope.signatures.length, 1)
  assert.equal(typeof envelope.signatures[0]!.sig, 'string')
  assert.ok(/^[A-Za-z0-9+/]+=*$/.test(envelope.signatures[0]!.sig))
})

await t('keyid 是可选的：给了就出现在 envelope 里，不给就不出现（DSSE 规定 keyid 可以整个不设置）', async () => {
  const { privateKey } = await generateKeyPair()
  const body = new TextEncoder().encode('x')
  const withKeyid = await signDsseEnvelope('t', body, privateKey, { keyid: 'key-1' })
  assert.equal(withKeyid.signatures[0]!.keyid, 'key-1')

  const withoutKeyid = await signDsseEnvelope('t', body, privateKey)
  assert.ok(!('keyid' in withoutKeyid.signatures[0]!))
})

await t('篡改 payload 一个字节 → 验签失败（反例）', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const body = new TextEncoder().encode('{"amount":100}')
  const envelope = await signDsseEnvelope('application/vnd.example+json', body, privateKey)

  const tamperedBody = new TextEncoder().encode('{"amount":900}')
  const tampered = { ...envelope, payload: base64Encode(tamperedBody) }
  const ok = await verifyDsseEnvelope(tampered, publicKey)
  assert.equal(ok, false)
})

await t('篡改 payloadType（不改 payload 或签名）→ 验签失败（反例：这正是 PAE 把 payloadType 纳入签名要防的类型混淆攻击）', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const body = new TextEncoder().encode('{"a":1}')
  const envelope = await signDsseEnvelope('application/vnd.mcpcheckup.attestation+json;version=0.1', body, privateKey)

  const retyped = { ...envelope, payloadType: 'application/vnd.something-else+json' }
  const ok = await verifyDsseEnvelope(retyped, publicKey)
  assert.equal(ok, false, 'payloadType 是签名覆盖范围的一部分，换一个类型必须让验签失败')
})

await t('用另一把公钥验签 → 失败（反例）', async () => {
  const signer = await generateKeyPair()
  const impostor = await generateKeyPair()
  const body = new TextEncoder().encode('hello')
  const envelope = await signDsseEnvelope('t', body, signer.privateKey)
  const ok = await verifyDsseEnvelope(envelope, impostor.publicKey)
  assert.equal(ok, false)
})

await t('多签名 envelope：只要有一个签名对得上给定公钥就算验签通过', async () => {
  const signerA = await generateKeyPair()
  const signerB = await generateKeyPair()
  const body = new TextEncoder().encode('multi-sig payload')
  const payloadType = 't'

  const preAuth = pae(payloadType, body)
  const sigA = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signerA.privateKey, preAuth))
  const sigB = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signerB.privateKey, preAuth))

  const envelope = {
    payloadType,
    payload: base64Encode(body),
    signatures: [
      { keyid: 'a', sig: base64Encode(sigA) },
      { keyid: 'b', sig: base64Encode(sigB) },
    ],
  }

  assert.equal(await verifyDsseEnvelope(envelope, signerA.publicKey), true)
  assert.equal(await verifyDsseEnvelope(envelope, signerB.publicKey), true)
  const outsider = await generateKeyPair()
  assert.equal(await verifyDsseEnvelope(envelope, outsider.publicKey), false)
})

await t('payload 不是合法 base64 → verifyDsseEnvelope 解析为 false，不是抛异常（反例：保住 Promise<boolean> 的契约）', async () => {
  const { publicKey } = await generateKeyPair()
  const malformed = { payloadType: 't', payload: 'not valid base64!!!', signatures: [{ sig: 'AAAA' }] }
  const ok = await verifyDsseEnvelope(malformed, publicKey)
  assert.equal(ok, false)
})

await t('某个签名的 sig 不是合法 base64 → 不影响验证同一 envelope 里其它合法签名（反例：一条垃圾数据不该拖累别的签名）', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const body = new TextEncoder().encode('multi-sig with one corrupt entry')
  const envelope = await signDsseEnvelope('t', body, privateKey)
  const withGarbageFirst = {
    ...envelope,
    signatures: [{ sig: 'not valid base64!!!' }, ...envelope.signatures],
  }
  const ok = await verifyDsseEnvelope(withGarbageFirst, publicKey)
  assert.equal(ok, true, '第一个签名是垃圾数据，但第二个是真签名，整体应该验签通过')
})

await t('verifyDsseSignature：底层原子操作，直接对 (type, body, signature, key) 验签', async () => {
  const { privateKey, publicKey } = await generateKeyPair()
  const body = new TextEncoder().encode('atomic')
  const preAuth = pae('t', body)
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, preAuth))
  assert.equal(await verifyDsseSignature('t', body, sig, publicKey), true)
  assert.equal(await verifyDsseSignature('different-type', body, sig, publicKey), false)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
