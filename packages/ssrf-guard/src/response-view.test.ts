import assert from 'node:assert'
import { createSafeResponseHandle } from './response-view.ts'
import { BudgetExceeded } from './errors.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('createSafeResponseHandle: status/headers 透传')

await t('status 与 headers 正确透传（协议判定需要它们，不在限制范围内）', async () => {
  const response = new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json', 'x-mcp-protocol-version': '2026-07-28' } })
  const handle = createSafeResponseHandle(response, 1000)
  assert.equal(handle.status, 200)
  assert.equal(handle.headers.get('content-type'), 'application/json')
  assert.equal(handle.headers.get('x-mcp-protocol-version'), '2026-07-28')
})

console.log('\ncreateSafeResponseHandle: body 读取方法')

await t('text() 正确读出小 body', async () => {
  const handle = createSafeResponseHandle(new Response('hello world'), 1000)
  assert.equal(await handle.text(), 'hello world')
})

await t('json() 正确解析', async () => {
  const handle = createSafeResponseHandle(new Response('{"a":1}'), 1000)
  assert.deepEqual(await handle.json(), { a: 1 })
})

await t('bytes() 返回正确的字节内容', async () => {
  const handle = createSafeResponseHandle(new Response('abc'), 1000)
  assert.deepEqual(Array.from(await handle.bytes()), [97, 98, 99])
})

await t('arrayBuffer() 返回正确长度与内容', async () => {
  const handle = createSafeResponseHandle(new Response('abc'), 1000)
  const buf = await handle.arrayBuffer()
  assert.equal(buf.byteLength, 3)
  assert.deepEqual(Array.from(new Uint8Array(buf)), [97, 98, 99])
})

await t('body 只被底层流读取一次：先 text() 后 json() 不报"body already used"', async () => {
  const handle = createSafeResponseHandle(new Response('{"a":1}'), 1000)
  const asText = await handle.text()
  const asJson = await handle.json()
  assert.equal(asText, '{"a":1}')
  assert.deepEqual(asJson, { a: 1 })
})

console.log('\ncreateSafeResponseHandle: maxBodyBytes 预算')

await t('body 长度恰好等于上限：成功（边界）', async () => {
  const handle = createSafeResponseHandle(new Response('12345'), 5)
  assert.equal(await handle.text(), '12345')
})

await t('body 长度比上限多 1 字节：抛 BudgetExceeded（边界）', async () => {
  const handle = createSafeResponseHandle(new Response('123456'), 5)
  await assert.rejects(() => handle.text(), BudgetExceeded)
})

await t('BudgetExceeded 的错误信息不包含目标返回的原始字节内容', async () => {
  const secretLookingBody = '<REDACTED>-token-that-must-never-leak-into-an-error-message'
  const handle = createSafeResponseHandle(new Response(secretLookingBody), 10)
  try {
    await handle.text()
    assert.fail('expected to throw')
  } catch (e) {
    const message = (e as Error).message
    assert.ok(!message.includes(secretLookingBody), `error message must not echo target body, got: ${message}`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
