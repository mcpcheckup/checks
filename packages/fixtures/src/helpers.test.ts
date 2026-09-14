import assert from 'node:assert'
import { parseJsonRpcCall, jsonRpcResult, jsonRpcError, rawResponse, summarizeResponse } from './helpers.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('parseJsonRpcCall')

await t('解析出 method / id / params，以及请求头', async () => {
  const req = await parseJsonRpcCall('https://notes-mcp.example.com/mcp', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'mcp-protocol-version': '2026-07-28' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'tools/list', params: {} }),
  })
  assert.equal(req.jsonrpcMethod, 'tools/list')
  assert.equal(req.id, 7)
  assert.deepEqual(req.params, {})
  assert.equal(req.headers.get('mcp-protocol-version'), '2026-07-28')
})

await t('body 不是合法 JSON 时 jsonrpcMethod 为 null，不抛错', async () => {
  const req = await parseJsonRpcCall('https://notes-mcp.example.com/mcp', { method: 'POST', body: 'not json' })
  assert.equal(req.jsonrpcMethod, null)
})

await t('notification（无 id 字段）：id 是 undefined', async () => {
  const req = await parseJsonRpcCall('https://notes-mcp.example.com/mcp', {
    method: 'POST',
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  })
  assert.equal(req.jsonrpcMethod, 'notifications/initialized')
  assert.equal(req.id, undefined)
})

console.log('\njsonRpcResult / jsonRpcError / rawResponse')

await t('jsonRpcResult：默认 200，正确的 JSON-RPC 结果外壳', async () => {
  const res = jsonRpcResult(1, { tools: [] })
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('content-type'), 'application/json')
  assert.deepEqual(await res.json(), { jsonrpc: '2.0', id: 1, result: { tools: [] } })
})

await t('jsonRpcError：默认 200（JSON-RPC 错误照惯例走 200 传输层，错误在 body 里），可覆盖 status', async () => {
  const res = jsonRpcError(1, -32601, 'Method not found')
  assert.equal(res.status, 200)
  assert.deepEqual(await res.json(), { jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'Method not found' } })
})

await t('jsonRpcError：可覆盖 status（例如现代协议版本不匹配用 400）', async () => {
  const res = jsonRpcError(1, -32022, 'Unsupported protocol version', { status: 400, data: { supported: ['2026-07-28'] } })
  assert.equal(res.status, 400)
  const body = await res.json()
  assert.equal(body.error.code, -32022)
  assert.deepEqual(body.error.data, { supported: ['2026-07-28'] })
})

await t('rawResponse：任意 status/headers/body，用于模拟非 JSON-RPC 场景（如错误页、重定向）', async () => {
  const res = rawResponse(302, { location: 'https://mirror.example.com/mcp' }, '')
  assert.equal(res.status, 302)
  assert.equal(res.headers.get('location'), 'https://mirror.example.com/mcp')
})

console.log('\nsummarizeResponse：确定性摘要')

await t('提取 status / headers / bodyText', async () => {
  const res = jsonRpcResult(1, { ok: true })
  const summary = await summarizeResponse(res)
  assert.equal(summary.status, 200)
  assert.equal(summary.headers['content-type'], 'application/json')
  assert.deepEqual(JSON.parse(summary.bodyText), { jsonrpc: '2.0', id: 1, result: { ok: true } })
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
