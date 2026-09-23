import assert from 'node:assert'
import { judgeErrorTaxonomy } from './error-taxonomy.ts'
import { performHandshake, performUnknownToolCall } from './protocol.ts'
import type { ProbeCallResult } from './protocol.ts'
import { createProbeContext } from './wire.ts'
import { modernBaselineClean, errorResponseNonconformantShape, noCredentialsUnverifiableAuth } from '@mcpcheckup/fixtures'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const BUDGET: ProbeBudget = { maxRedirects: 3, maxDurationMs: 10_000, maxBodyBytes: 2_097_152, maxRequests: 8 }
let seq = 0
const newId = () => `probe-${++seq}`
const ENDPOINT = 'https://notes-mcp.example.com/mcp'

async function callResultFor(fixture: { createHandler: () => import('@mcpcheckup/fixtures').FetchHandler }) {
  const fetchImpl = fixture.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: ENDPOINT, budget: BUDGET, ctx, newId })
  return performUnknownToolCall({ fetchImpl, budget: BUDGET, ctx, newId, handshake, toolName: '__mcpcheckup_probe_nonexistent_tool__' })
}

/** A synthetic tools/call(unknown tool) response. `contentType: null` means the
 *  header is absent altogether (not present-but-empty — that is `''`). */
function cr(status: number, contentType: string | null, bodyText: string): ProbeCallResult {
  const headers = new Headers()
  if (contentType !== null) headers.set('content-type', contentType)
  return { status, headers, bodyText, currentEndpoint: ENDPOINT }
}

const SCENARIO = 'tools_call_unknown_tool'

/** The full reason ref judgeErrorTaxonomy must return — compared with
 *  deepStrictEqual, so an extra param (or a missing one) is red, not tolerated. */
function expected(cls: string, status: number, mediaType: string, jsonrpcErrorCode?: number) {
  return {
    status: 'OBSERVED_RISK',
    reason: {
      key: `error_taxonomy_${cls}`,
      params: {
        scenario: SCENARIO,
        status,
        media_type: mediaType,
        ...(jsonrpcErrorCode === undefined ? {} : { jsonrpc_error_code: jsonrpcErrorCode }),
      },
    },
  }
}

const J = 'application/json'
const SSE = 'text/event-stream'
const RESULT_IS_ERROR = '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Unknown tool"}],"isError":true}}'
const RESULT_OK = '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}'
const WELL_FORMED_ERROR = '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool"}}'
const NOTIFICATION = '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}'

console.log('judgeErrorTaxonomy：针对真实 fixture handler')

await t('modern-baseline-clean：合法 JSON-RPC 错误响应 → VERIFIED', async () => {
  const callResult = await callResultFor(modernBaselineClean)
  const v = judgeErrorTaxonomy(callResult)
  assert.deepStrictEqual(v, { status: 'VERIFIED' })
})

await t('error-response-nonconformant-shape：纯文本 500 → OBSERVED_RISK / error_taxonomy_not_json {status 500, text/plain}', async () => {
  const callResult = await callResultFor(errorResponseNonconformantShape)
  assert.deepStrictEqual(judgeErrorTaxonomy(callResult), expected('not_json', 500, 'text/plain'))
})

await t('no-credentials-unverifiable-auth：裸 401 是 JSON-RPC 分发之前的合法拒绝，不算错误形状问题 → VERIFIED', async () => {
  const callResult = await callResultFor(noCredentialsUnverifiableAuth)
  assert.deepStrictEqual(judgeErrorTaxonomy(callResult), { status: 'VERIFIED' })
})

console.log('\njudgeErrorTaxonomy：VERIFIED 两支逻辑不变，且不带任何 reason')

await t('401 / 403 无论 body 是什么 → VERIFIED（没有 reason 字段）', () => {
  for (const status of [401, 403]) {
    for (const body of ['', 'Unauthorized', RESULT_IS_ERROR, NOTIFICATION]) {
      assert.deepStrictEqual(judgeErrorTaxonomy(cr(status, J, body)), { status: 'VERIFIED' }, `${status} ${JSON.stringify(body)}`)
    }
  }
})

await t('合法 JSON-RPC error（JSON 与 SSE 两种 framing，任意状态码）→ VERIFIED', () => {
  for (const status of [200, 400, 404, 500]) {
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(status, J, WELL_FORMED_ERROR)), { status: 'VERIFIED' })
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(status, SSE, `event: message\ndata: ${WELL_FORMED_ERROR}\n\n`)), { status: 'VERIFIED' })
  }
})

console.log('\n分类 1：empty_body（严格零长度，SSE 处理之前）')

await t('裸 503、无 content-type、空 body → empty_body {503, none}', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(503, null, '')), expected('empty_body', 503, 'none'))
})

await t('空 body 优先于 event_stream_no_data：SSE content-type + 空 body → empty_body', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, '')), expected('empty_body', 200, 'text/event-stream'))
})

await t('只有空白的 body 不是 empty_body（规则是严格零长度，不 trim）→ not_json', () => {
  for (const body of [' ', '\n', '\r\n\r\n', '\t ']) {
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(500, J, body)), expected('not_json', 500, 'application/json'), JSON.stringify(body))
  }
})

console.log('\n分类 2：event_stream_no_data（SSE content-type 且一个 data 载荷都没有）')

await t('只有注释行 ": ping" 的事件流 → event_stream_no_data', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, ': ping\n\n')), expected('event_stream_no_data', 200, 'text/event-stream'))
})

await t('SSE content-type 下未分帧的裸 JSON（即使本身是 isError result）→ event_stream_no_data', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, RESULT_IS_ERROR)), expected('event_stream_no_data', 200, 'text/event-stream'))
})

await t('"data:" 行载荷为空、或行首有空格而不是 "data:" → event_stream_no_data', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, 'data:\n\n')), expected('event_stream_no_data', 200, 'text/event-stream'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, ` data: ${RESULT_OK}\n\n`)), expected('event_stream_no_data', 200, 'text/event-stream'))
})

await t('非 SSE content-type 下同样的注释行 body → not_json（不是 event_stream_no_data）', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, 'text/plain', ': ping\n\n')), expected('not_json', 200, 'text/plain'))
})

console.log('\n分类 3：result_is_error / result_ok（第一个被接受为 JSON-RPC 的候选带 result）')

await t('application/json 的 result.isError === true → result_is_error', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, RESULT_IS_ERROR)), expected('result_is_error', 200, 'application/json'))
})

await t('SSE framing 的各种写法都认：有/无空格的 "data:"、CRLF、多行 data', () => {
  const cases = [
    `event: message\ndata: ${RESULT_IS_ERROR}\n\n`,
    `data:${RESULT_IS_ERROR}\n\n`,
    `event: message\r\ndata: ${RESULT_IS_ERROR}\r\n\r\n`,
    'data: {"jsonrpc":"2.0",\ndata: "id":1,\ndata: "result":{"isError":true}}\n\n',
    `data: ${RESULT_IS_ERROR}`,
  ]
  for (const body of cases) {
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, body)), expected('result_is_error', 200, 'text/event-stream'), JSON.stringify(body))
  }
})

await t('SSE 第一个事件是 notification，第二个才是 JSON-RPC 响应 → 按第二个分类', () => {
  const body = `data: ${NOTIFICATION}\n\ndata: ${RESULT_IS_ERROR}\n\n`
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, body)), expected('result_is_error', 200, 'text/event-stream'))
})

await t('isError 只认严格布尔 true："true" / 1 / false / 缺失 → result_ok', () => {
  for (const isError of ['"true"', '1', 'false', 'null']) {
    const body = `{"jsonrpc":"2.0","id":1,"result":{"isError":${isError}}}`
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, body)), expected('result_ok', 200, 'application/json'), body)
  }
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, RESULT_OK)), expected('result_ok', 200, 'application/json'))
})

await t('result 不是对象（null / 数组 / 数字）→ result_ok', () => {
  for (const result of ['null', '[]', '7', '"x"']) {
    const body = `{"jsonrpc":"2.0","id":1,"result":${result}}`
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, body)), expected('result_ok', 200, 'application/json'), body)
  }
})

await t('result 与 error 同时出现：解析器按 result 接受（判定仍是 OBSERVED_RISK）→ result_ok / result_is_error', () => {
  const both = '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32602,"message":"m"}}'
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, both)), expected('result_ok', 200, 'application/json'))
  const bothIsError = '{"jsonrpc":"2.0","id":1,"result":{"isError":true},"error":{"code":-32602,"message":"m"}}'
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, bothIsError)), expected('result_is_error', 200, 'application/json'))
})

await t('前后带空白的 JSON（JSON.parse 容忍）→ 照常分类', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, `  ${RESULT_IS_ERROR}\n`)), expected('result_is_error', 200, 'application/json'))
})

console.log('\n分类 4：jsonrpc_malformed（自称 jsonrpc 2.0，但既无 result 也无格式正确的 error）')

await t('缺 message 的 error，code 是安全整数 → jsonrpc_malformed + jsonrpc_error_code', () => {
  const body = '{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}'
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, body)), expected('jsonrpc_malformed', 200, 'application/json', -32601))
})

await t('message 不是字符串，code 是安全整数 → 带 code', () => {
  const body = '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":5}}'
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(400, J, body)), expected('jsonrpc_malformed', 400, 'application/json', -32602))
})

await t('code 不是安全整数（字符串 / 1.5 / 2^53+1 / 1e400=Infinity / 缺失）→ jsonrpc_malformed，参数里根本没有 jsonrpc_error_code 这个键', () => {
  const codes = ['"x"', '"-32602"', '1.5', '9007199254740993', '1e400', 'null', '{}', '[1]']
  for (const code of codes) {
    const body = `{"jsonrpc":"2.0","id":1,"error":{"code":${code}}}`
    const v = judgeErrorTaxonomy(cr(500, J, body))
    assert.deepStrictEqual(v, expected('jsonrpc_malformed', 500, 'application/json'), body)
    assert.ok(v.status === 'OBSERVED_RISK' && v.reason && !('jsonrpc_error_code' in (v.reason.params ?? {})), `${body}: jsonrpc_error_code 必须整体缺席，不是 null`)
  }
  const noCode = '{"jsonrpc":"2.0","id":1,"error":{"message":"m"}}'
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(500, J, noCode)), expected('jsonrpc_malformed', 500, 'application/json'))
})

await t('code 是 -0 → 记为 0（签名字节里 -0 本来就被规范化成 0，内存值与之一致）', () => {
  const v = judgeErrorTaxonomy(cr(200, J, '{"jsonrpc":"2.0","id":1,"error":{"code":-0}}'))
  assert.deepStrictEqual(v, expected('jsonrpc_malformed', 200, 'application/json', 0))
  assert.ok(v.status === 'OBSERVED_RISK' && Object.is(v.reason!.params!.jsonrpc_error_code, 0), '必须是 +0')
})

await t('error 为 null / 数组 / 字符串 → jsonrpc_malformed，无 code', () => {
  for (const err of ['null', '[]', '"boom"']) {
    const body = `{"jsonrpc":"2.0","id":1,"error":${err}}`
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, body)), expected('jsonrpc_malformed', 200, 'application/json'), body)
  }
})

await t('服务器 notification / request（有 method、无 result/error）→ jsonrpc_malformed，无 code', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, NOTIFICATION)), expected('jsonrpc_malformed', 200, 'application/json'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, `data: ${NOTIFICATION}\n\n`)), expected('jsonrpc_malformed', 200, 'text/event-stream'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, '{"jsonrpc":"2.0"}')), expected('jsonrpc_malformed', 200, 'application/json'))
})

await t('SSE 里有多个自称 2.0 的候选时，jsonrpc_error_code 取第一个这样的候选', () => {
  const body = `data: ${NOTIFICATION}\n\ndata: {"jsonrpc":"2.0","id":1,"error":{"code":-32000}}\n\n`
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, body)), expected('jsonrpc_malformed', 200, 'text/event-stream'))
  const reversed = `data: {"jsonrpc":"2.0","id":1,"error":{"code":-32000}}\n\ndata: ${NOTIFICATION}\n\n`
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, reversed)), expected('jsonrpc_malformed', 200, 'text/event-stream', -32000))
})

await t('一个自称 2.0 的候选排在一个 JSON 数组之后 → 仍是 jsonrpc_malformed（规则 4 看任意候选，先于规则 5）', () => {
  const body = `data: [1]\n\ndata: ${NOTIFICATION}\n\n`
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, body)), expected('jsonrpc_malformed', 200, 'text/event-stream'))
})

console.log('\n分类 5：not_jsonrpc（是 JSON，但不是 JSON-RPC 消息）')

await t('各种非 JSON-RPC 的 JSON：普通对象、jsonrpc "1.0"、数字 2.0、批量数组、原始值 → not_jsonrpc', () => {
  const bodies = [
    '{"error":"unknown tool"}',
    '{}',
    '{"jsonrpc":"1.0","id":1,"error":{"code":-32602,"message":"m"}}',
    '{"jsonrpc":2.0,"id":1,"error":{"code":-32602,"message":"m"}}',
    `[${WELL_FORMED_ERROR}]`,
    '42', 'null', 'true', '"Unknown tool"',
  ]
  for (const body of bodies) {
    assert.deepStrictEqual(judgeErrorTaxonomy(cr(400, J, body)), expected('not_jsonrpc', 400, 'application/json'), body)
  }
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, 'data: 42\n\n')), expected('not_jsonrpc', 200, 'text/event-stream'))
})

console.log('\n分类 6：not_json')

await t('HTML、纯文本、带 BOM 的 JSON、截断的 JSON、SSE 里的非 JSON data → not_json', () => {
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(404, 'text/html; charset=UTF-8', '<html><body>Not Found</body></html>')), expected('not_json', 404, 'text/html'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(500, 'text/plain', 'Internal Server Error')), expected('not_json', 500, 'text/plain'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, `﻿${RESULT_IS_ERROR}`)), expected('not_json', 200, 'application/json'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, '{"jsonrpc":"2.0","id":1,"err')), expected('not_json', 200, 'application/json'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, SSE, 'data: hello\n\n')), expected('not_json', 200, 'text/event-stream'))
  assert.deepStrictEqual(judgeErrorTaxonomy(cr(200, J, `event: message\ndata: ${RESULT_IS_ERROR}\n\n`)), expected('not_json', 200, 'application/json'))
})

console.log('\nmedia_type 归一化（只取 ; 之前、trim、小写；四个已知值之外一律 other）')

await t('参数、大小写、空白、缺失、空值、problem+json、逗号合并值', () => {
  const cases: [string | null, string][] = [
    ['application/json', 'application/json'],
    ['application/json; charset=utf-8', 'application/json'],
    ['APPLICATION/JSON', 'application/json'],
    ['Application/Json ; charset=UTF-8', 'application/json'],
    ['text/event-stream', 'text/event-stream'],
    ['Text/HTML;charset=UTF-8', 'text/html'],
    ['text/plain', 'text/plain'],
    [null, 'none'],
    ['', 'none'],
    ['application/problem+json', 'other'],
    ['application/json, text/html', 'other'],
    ['application/jsonx', 'other'],
    ['; charset=utf-8', 'other'],
  ]
  for (const [ct, want] of cases) {
    // The same non-JSON body throughout; under an SSE content-type it classifies
    // as event_stream_no_data (it has no `data:` line), everywhere else as not_json.
    const cls = ct !== null && ct.toLowerCase().includes('text/event-stream') ? 'event_stream_no_data' : 'not_json'
    const v = judgeErrorTaxonomy(cr(500, ct, 'Internal Server Error'))
    assert.deepStrictEqual(v, expected(cls, 500, want), `content-type ${JSON.stringify(ct)}`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
