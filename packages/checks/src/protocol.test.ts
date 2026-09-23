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

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
