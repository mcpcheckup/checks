import assert from 'node:assert'
import {
  parseJsonRpcBody,
  performHandshake,
  performToolsList,
  performUnknownToolCall,
  RECOGNIZED_MODERN_ERROR_CODES,
} from './protocol.ts'
import { createProbeContext } from './wire.ts'
import {
  modernBaselineClean,
  legacyBaselineClean,
  legacyStrictAcceptEnforcement,
  legacyNoSessionId,
  legacySseFramedResponses,
  legacyDiscover401Unauthorized,
  staleProtocolVersion,
  toolsListIllegalStructure,
  legacyEverythingRequiresAuthStillFails,
} from '@mcpcheckup/fixtures'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const BUDGET: ProbeBudget = { maxRedirects: 3, maxDurationMs: 10_000, maxBodyBytes: 2_097_152, maxRequests: 8 }
let seq = 0
const newId = () => `probe-${++seq}`

console.log('parseJsonRpcBody')

await t('合法的 result 响应', () => {
  const p = parseJsonRpcBody(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { ok: true } }))
  assert.equal(p.isJsonRpc, true)
  assert.deepEqual(p.result, { ok: true })
})

await t('合法的 error 响应', () => {
  const p = parseJsonRpcBody(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'nope' } }))
  assert.equal(p.isJsonRpc, true)
  assert.equal(p.error?.code, -32601)
})

await t('反例：不是合法 JSON', () => {
  const p = parseJsonRpcBody('{not json')
  assert.equal(p.isJsonRpc, false)
})

await t('反例：是 JSON 但既没有 result 也没有合法 error', () => {
  const p = parseJsonRpcBody(JSON.stringify({ jsonrpc: '2.0', id: 1 }))
  assert.equal(p.isJsonRpc, false)
})

await t('反例：jsonrpc 字段不是 "2.0"', () => {
  const p = parseJsonRpcBody(JSON.stringify({ jsonrpc: '1.0', id: 1, result: {} }))
  assert.equal(p.isJsonRpc, false)
})

console.log('\nRECOGNIZED_MODERN_ERROR_CODES')

await t('三个 2026-07-28 规范定义的现代错误码都在集合里', () => {
  assert.ok(RECOGNIZED_MODERN_ERROR_CODES.has(-32020)) // HeaderMismatch
  assert.ok(RECOGNIZED_MODERN_ERROR_CODES.has(-32021)) // MissingRequiredClientCapability
  assert.ok(RECOGNIZED_MODERN_ERROR_CODES.has(-32022)) // UnsupportedProtocolVersion
  assert.equal(RECOGNIZED_MODERN_ERROR_CODES.has(-32601), false) // 普通 "Method not found" 不是现代错误
})

console.log('\nperformHandshake：针对真实 fixture handler')

await t('modern-baseline-clean：一次 server/discover 即握手成功，mode=modern', async () => {
  const fetchImpl = modernBaselineClean.createHandler()
  const ctx = createProbeContext(Date.now())
  const r = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(r.mode, 'modern')
  assert.equal(r.handshakeOk, true)
  assert.equal(r.protocolVersionDeclared, '2026-07-28')
})

await t('legacy-baseline-clean：现代探测被 400 拒绝后正确回退到 initialize，mode=legacy，拿到 session id', async () => {
  const fetchImpl = legacyBaselineClean.createHandler()
  const ctx = createProbeContext(Date.now())
  const r = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(r.mode, 'legacy')
  assert.equal(r.handshakeOk, true)
  assert.equal(r.protocolVersionDeclared, '2025-06-18')
  assert.ok(r.sessionId && r.sessionId.length > 0)
})

await t('legacy-strict-accept-enforcement：合规 legacy 实现要求 Accept 头，握手/工具列表全部成功', async () => {
  const fetchImpl = legacyStrictAcceptEnforcement.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(handshake.mode, 'legacy')
  assert.equal(handshake.handshakeOk, true)
  assert.equal(handshake.protocolVersionDeclared, '2025-06-18')
  assert.ok(handshake.sessionId && handshake.sessionId.length > 0)
  const tools = await performToolsList({ fetchImpl, budget: BUDGET, ctx, newId, handshake })
  assert.equal(tools.ok, true)
  assert.equal(tools.tools?.length, 2)
})

await t('legacy-no-session-id：合规 legacy 实现从不分配 Mcp-Session-Id，握手/工具列表全部成功', async () => {
  const fetchImpl = legacyNoSessionId.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(handshake.mode, 'legacy')
  assert.equal(handshake.handshakeOk, true)
  assert.equal(handshake.protocolVersionDeclared, '2025-06-18')
  assert.equal(handshake.sessionId, undefined)
  const tools = await performToolsList({ fetchImpl, budget: BUDGET, ctx, newId, handshake })
  assert.equal(tools.ok, true)
  assert.equal(tools.tools?.length, 2)
})

await t('legacy-sse-framed-responses：合规 legacy 实现用 SSE 帧回复 initialize/tools/list，握手/工具列表全部成功', async () => {
  const fetchImpl = legacySseFramedResponses.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(handshake.mode, 'legacy')
  assert.equal(handshake.handshakeOk, true)
  assert.equal(handshake.protocolVersionDeclared, '2025-06-18')
  assert.ok(handshake.sessionId && handshake.sessionId.length > 0)
  const tools = await performToolsList({ fetchImpl, budget: BUDGET, ctx, newId, handshake })
  assert.equal(tools.ok, true)
  assert.equal(tools.tools?.length, 2)
})

await t('stale-protocol-version：握手机制本身仍然成功（版本号是否在矩阵里由上层 protocol_revision 检查判断，不是这一步的事）', async () => {
  const fetchImpl = staleProtocolVersion.createHandler()
  const ctx = createProbeContext(Date.now())
  const r = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(r.mode, 'legacy')
  assert.equal(r.handshakeOk, true)
  assert.equal(r.protocolVersionDeclared, '2023-01-01')
})

// droproom/mcp 误报调查（2026-08-30）判责结论 (b) 的双向负向回归测试：见 packages/checks/src/protocol.ts
// performHandshake 的放宽 `discover.status === 400` → `discover.status >= 400 && discover.status < 500`。

await t('legacy-discover-401-unauthorized：server/discover 收到非 400 的 4xx（401，非 JSON-RPC body）仍正确回退到 initialize，mode=legacy，握手成功——此前会被误判 handshakeOk=false（真实观测：droproom/mcp）', async () => {
  const fetchImpl = legacyDiscover401Unauthorized.createHandler()
  const ctx = createProbeContext(Date.now())
  const r = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(r.mode, 'legacy')
  assert.equal(r.handshakeOk, true)
  assert.equal(r.protocolVersionDeclared, '2025-06-18')
  assert.ok(r.sessionId && r.sessionId.length > 0)
})

await t('legacy-everything-requires-auth-still-fails：放宽到 4xx 触发回退之后，initialize 本身真的失败（同样 401）时握手依然正确判 FAILED——fail-closed 语义未被这次放宽打开新洞', async () => {
  const fetchImpl = legacyEverythingRequiresAuthStillFails.createHandler()
  const ctx = createProbeContext(Date.now())
  const r = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(r.mode, 'legacy')
  assert.equal(r.handshakeOk, false)
  assert.equal(r.protocolVersionDeclared, null)
})

console.log('\nT96（suite 0.10.0）：server/discover 的 2xx 回答既不是可用的 discover 结果、也不是已识别的现代错误码 ⇒ 回退 initialize（规范原句 "Anything else identifies a legacy server."）；4xx / 3xx / 5xx 不变')

/** A server whose server/discover answer is `discover()` and whose legacy
 *  handshake succeeds; records the JSON-RPC method of every request. */
function t96Server(discover: () => Response): { fetchImpl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>; methods: string[] } {
  const methods: string[] = []
  const fetchImpl = async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const method = String((JSON.parse(String(init?.body)) as { method?: unknown }).method)
    methods.push(method)
    if (method === 'server/discover') return discover()
    if (method === 'initialize') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { protocolVersion: '2025-06-18', capabilities: {} } }), { status: 200, headers: { 'content-type': 'application/json', 'mcp-session-id': 's-1' } })
    }
    if (method === 'notifications/initialized') return new Response(null, { status: 202 })
    return new Response('', { status: 404 })
  }
  return { fetchImpl, methods }
}

const json = (status: number, body: unknown) => () => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

async function t96Handshake(discover: () => Response) {
  const server = t96Server(discover)
  const r = await performHandshake({ fetchImpl: server.fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx: createProbeContext(Date.now()), newId })
  return { r, methods: server.methods }
}

for (const [label, discover] of [
  ['200 + JSON-RPC error -32601（Method not found）', json(200, { jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'Method not found' } })],
  ['200 + JSON-RPC result 但没有 supportedVersions', json(200, { jsonrpc: '2.0', id: 1, result: { capabilities: {} } })],
  ['200 + text/html（不是 JSON）', () => new Response('<html><body>MCP</body></html>', { status: 200, headers: { 'content-type': 'text/html' } })],
  ['200 + error 对象缺字符串 message（解析器不当它是 JSON-RPC，即便 code 是 -32022）', json(200, { jsonrpc: '2.0', id: 1, error: { code: -32022 } })],
  ['202 + 空 body（T96：每个 2xx 都按 200 的新规则判）', () => new Response(null, { status: 202 })],
] as const) {
  await t(`T96 红证：discover 回 ${label} ⇒ 发出 initialize 与 notifications/initialized，mode=legacy，握手成功`, async () => {
    const { r, methods } = await t96Handshake(discover)
    assert.deepStrictEqual(methods, ['server/discover', 'initialize', 'notifications/initialized'])
    assert.deepStrictEqual(r, { mode: 'legacy', handshakeOk: true, protocolVersionDeclared: '2025-06-18', sessionId: 's-1', currentEndpoint: 'https://notes-mcp.example.com/mcp' })
  })
}

for (const code of [...RECOGNIZED_MODERN_ERROR_CODES]) {
  await t(`T96 红证：discover 回 200 + 已识别的现代错误码 ${code} ⇒ 不发 initialize，key 为 handshake_discover_rejected {status:200}`, async () => {
    const { r, methods } = await t96Handshake(json(200, { jsonrpc: '2.0', id: 1, error: { code, message: 'rejected' } }))
    assert.deepStrictEqual(methods, ['server/discover'])
    assert.deepStrictEqual(r, { mode: 'modern', handshakeOk: false, protocolVersionDeclared: null, currentEndpoint: 'https://notes-mcp.example.com/mcp', failure: { key: 'handshake_discover_rejected', params: { status: 200, jsonrpc_error_code: code } } })
  })
}

await t('T96：200 以外的 2xx 带可用的 discover 结果 ⇒ 同 200 一样判 modern 成功，不发 initialize', async () => {
  const { r, methods } = await t96Handshake(json(202, { jsonrpc: '2.0', id: 1, result: { supportedVersions: ['2026-07-28'] } }))
  assert.deepStrictEqual(methods, ['server/discover'])
  assert.deepStrictEqual(r, { mode: 'modern', handshakeOk: true, protocolVersionDeclared: '2026-07-28', currentEndpoint: 'https://notes-mcp.example.com/mcp' })
})

await t('T96 不变：4xx 带「可用的 discover 结果」仍不是 modern，照旧回退 initialize', async () => {
  const { r, methods } = await t96Handshake(json(400, { jsonrpc: '2.0', id: 1, result: { supportedVersions: ['2026-07-28'] } }))
  assert.deepStrictEqual(methods, ['server/discover', 'initialize', 'notifications/initialized'])
  assert.equal(r.mode, 'legacy')
})

for (const status of [500, 503, 302]) {
  await t(`T96 不变：discover 回 ${status}（3xx / 5xx）⇒ 不回退，handshake_discover_http_error {status:${status}}`, async () => {
    const { r, methods } = await t96Handshake(() => new Response(null, { status, headers: status === 302 ? { location: 'https://elsewhere.example.com/' } : {} }))
    assert.deepStrictEqual(methods, ['server/discover'])
    assert.deepStrictEqual(r.failure, { key: 'handshake_discover_http_error', params: { status } })
  })
}

console.log('\nperformToolsList：针对真实 fixture handler')

await t('modern-baseline-clean：拿到合法工具数组', async () => {
  const fetchImpl = modernBaselineClean.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  const r = await performToolsList({ fetchImpl, budget: BUDGET, ctx, newId, handshake })
  assert.equal(r.ok, true)
  assert.equal(Array.isArray(r.tools), true)
  assert.equal(r.tools?.length, 2)
})

await t('legacy-baseline-clean：用握手拿到的 session id 也能正确取到工具数组', async () => {
  const fetchImpl = legacyBaselineClean.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  const r = await performToolsList({ fetchImpl, budget: BUDGET, ctx, newId, handshake })
  assert.equal(r.ok, true)
  assert.equal(r.tools?.length, 2)
})

await t('tools-list-illegal-structure：result.tools 不是数组 → ok=false', async () => {
  const fetchImpl = toolsListIllegalStructure.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  const r = await performToolsList({ fetchImpl, budget: BUDGET, ctx, newId, handshake })
  assert.equal(r.ok, false)
  assert.equal(r.tools, null)
})

console.log('\nT86 performToolsList.hasNextCursor：只在 ok 的清单上出现（值恒为 true）；nextCursor 只要存在且不是 null / undefined 就算——空串与非字符串都算')

/** A modern server whose discover succeeds and whose tools/list answers with
 *  `result` (any JSON value), optionally as a 401 + valid challenge. */
function toolsListServer(result: unknown, challenged = false): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  return async (_input, init) => {
    const call = JSON.parse(String(init?.body)) as { id: unknown; method: string }
    const body = (r: unknown) => JSON.stringify({ jsonrpc: '2.0', id: call.id, result: r })
    if (call.method === 'server/discover') return new Response(body({ supportedVersions: ['2026-07-28'] }), { status: 200, headers: { 'content-type': 'application/json' } })
    const headers: Record<string, string> = { 'content-type': 'application/json', ...(challenged ? { 'www-authenticate': 'Bearer realm="mcp"' } : {}) }
    return new Response(body(result), { status: challenged ? 401 : 200, headers })
  }
}

async function toolsListFor(result: unknown, challenged = false) {
  const fetchImpl = toolsListServer(result, challenged)
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  assert.equal(handshake.handshakeOk, true)
  return performToolsList({ fetchImpl, budget: BUDGET, ctx, newId, handshake })
}

const TOOL = { name: 'list_notes', inputSchema: { type: 'object' } }

await t('nextCursor 为 "page-2" / "" / 0 / false / {} / [] ⇒ hasNextCursor === true，其余字段与不带 nextCursor 时逐字段相同', async () => {
  const plain = await toolsListFor({ tools: [TOOL] })
  assert.equal('hasNextCursor' in plain, false)
  for (const cursor of ['page-2', '', 0, false, {}, []]) {
    const r = await toolsListFor({ tools: [TOOL], nextCursor: cursor })
    assert.equal(r.hasNextCursor, true, `nextCursor=${JSON.stringify(cursor)}`)
    const { hasNextCursor: _dropped, ...rest } = r
    assert.deepStrictEqual(rest, plain, `nextCursor=${JSON.stringify(cursor)}: 其余字段不应改变`)
  }
})

await t('nextCursor 为 null 或缺席 ⇒ 没有 hasNextCursor 字段（不是 false）', async () => {
  for (const result of [{ tools: [TOOL], nextCursor: null }, { tools: [TOOL] }]) {
    const r = await toolsListFor(result)
    assert.equal(r.ok, true)
    assert.equal('hasNextCursor' in r, false, JSON.stringify(result))
  }
})

await t('清单不 ok 时（没有 tools 数组 / 401 + challenge 否决）即使带 nextCursor 也没有 hasNextCursor 字段', async () => {
  const noTools = await toolsListFor({ nextCursor: 'page-2' })
  assert.equal(noTools.ok, false)
  assert.equal('hasNextCursor' in noTools, false)
  const vetoed = await toolsListFor({ tools: [TOOL], nextCursor: 'page-2' }, true)
  assert.equal(vetoed.ok, false)
  assert.equal('hasNextCursor' in vetoed, false)
})

await t('只看 result 自身的 nextCursor：嵌在某个工具对象里的 nextCursor 不算', async () => {
  const r = await toolsListFor({ tools: [{ ...TOOL, nextCursor: 'x' }] })
  assert.equal(r.ok, true)
  assert.equal('hasNextCursor' in r, false)
})

console.log('\nperformUnknownToolCall：针对真实 fixture handler')

await t('modern-baseline-clean：调用不存在的工具，拿到合法 JSON-RPC 错误响应（HTTP 200）', async () => {
  const fetchImpl = modernBaselineClean.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx, newId })
  const r = await performUnknownToolCall({ fetchImpl, budget: BUDGET, ctx, newId, handshake, toolName: '__mcpcheckup_probe_nonexistent_tool__' })
  assert.equal(r.status, 200)
  const parsed = parseJsonRpcBody(r.bodyText)
  assert.equal(parsed.isJsonRpc, true)
  assert.ok(parsed.error)
})

console.log('\nT86b credentialChallenge：{ scheme, status, wwwAuthenticate }——status 恒 401，header 与收到的逐字相同，不带 body；403 与无头 401 仍然没有这个字段')

await t('initialize / notifications/initialized / tools/list 三处门控都带上 status 与原样的 WWW-Authenticate；403（带头）与 401 无头都不算门控', async () => {
  const header = 'Bearer realm="mcp", resource_metadata="https://notes-mcp.example.com/.well-known/oauth-protected-resource", scope="a b"'
  const scripted = (answers: Record<string, () => Response>) => async (_input: RequestInfo | URL, init?: RequestInit) => {
    const method = typeof init?.body === 'string' ? (JSON.parse(init.body) as { method: string }).method : 'GET'
    const answer = answers[method]
    return answer ? answer() : new Response('{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}', { status: 400, headers: { 'content-type': 'application/json' } })
  }
  const gate = (status: number, withHeader = true) => () => new Response('{"secret":"body"}', { status, headers: withHeader ? { 'www-authenticate': header } : {} })
  const initOk = () => new Response('{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}', { status: 200, headers: { 'content-type': 'application/json' } })
  const ackOk = () => new Response(null, { status: 202 })
  const want = { scheme: 'bearer', status: 401, wwwAuthenticate: header }

  const hsInit = await performHandshake({ fetchImpl: scripted({ initialize: gate(401) }), endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx: createProbeContext(Date.now()), newId })
  assert.deepStrictEqual(hsInit.credentialChallenge, want)
  const hsAck = await performHandshake({ fetchImpl: scripted({ initialize: initOk, 'notifications/initialized': gate(401) }), endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx: createProbeContext(Date.now()), newId })
  assert.deepStrictEqual(hsAck.credentialChallenge, want)
  const hsOk = await performHandshake({ fetchImpl: scripted({ initialize: initOk, 'notifications/initialized': ackOk }), endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx: createProbeContext(Date.now()), newId })
  const list = await performToolsList({ fetchImpl: scripted({ 'tools/list': gate(401) }), budget: BUDGET, ctx: createProbeContext(Date.now()), newId, handshake: hsOk })
  assert.deepStrictEqual(list.credentialChallenge, want)

  for (const answer of [gate(403), gate(401, false)]) {
    const hs = await performHandshake({ fetchImpl: scripted({ initialize: answer }), endpoint: 'https://notes-mcp.example.com/mcp', budget: BUDGET, ctx: createProbeContext(Date.now()), newId })
    assert.ok(!('credentialChallenge' in hs), 'no gate at initialize')
    const tl = await performToolsList({ fetchImpl: scripted({ 'tools/list': answer }), budget: BUDGET, ctx: createProbeContext(Date.now()), newId, handshake: hsOk })
    assert.ok(!('credentialChallenge' in tl), 'no gate at tools/list')
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
