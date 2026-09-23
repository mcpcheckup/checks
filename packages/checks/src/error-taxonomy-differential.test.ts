/**
 * T73 differential invariant test — the primary evidence that recording a
 * bounded classification of the unknown-tool response changed NO verdict.
 *
 * Three independent parties, deliberately not sharing code:
 *
 *   1. judgeErrorTaxonomy (the implementation under test, ./error-taxonomy.ts).
 *   2. FROZEN_PRE_T73 — a verbatim copy of the judge AND of the parser it
 *      depended on (protocol.ts's isSseContentType / extractSseDataPayloads /
 *      parseJsonRpcText / parseJsonRpcBody) as they stood in
 *      @mcpcheckup/checks 0.4.0 (the last suite version before T73). Copying the parser too (not
 *      importing it) is what makes invariant (a) a real differential: a change
 *      to the live parser would otherwise move both sides at once and stay
 *      green. DO NOT "update" this copy to match a later judge — its only job
 *      is to be the pre-T73 behaviour.
 *   3. ORACLE — its own SSE splitter (a line scanner, not a regex split), its
 *      own JSON-RPC acceptance test, its own media-type normaliser, and the
 *      T73 rules as an ordered table. It imports nothing from
 *      ./error-taxonomy.ts or ./protocol.ts.
 *
 * Invariants, asserted for every input of a deterministic cartesian product
 * (statuses × content-types × bodies):
 *   (a) judge(x).status === FROZEN_PRE_T73(x).status
 *   (b) VERIFIED ⇒ no reason; OBSERVED_RISK ⇒ reason deep-equals the oracle's
 *       (key is one of the seven T73 keys)
 *   (c) params bounded: exactly the allowed keys, status an integer equal to
 *       the HTTP status, media_type in the six-value set, scenario constant,
 *       jsonrpc_error_code only on jsonrpc_malformed and only a safe integer
 *   (d) every emitted key renders in en and zh; no rendered string contains a
 *       banned word or any 8-character window of the input body (nor the
 *       canary planted in several bodies).
 *
 * Spec basis for the classification: cited once, on
 * classifyUnknownToolResponse in ./error-taxonomy.ts (app/CLAUDE.md 审查纪律 #4).
 */
import assert from 'node:assert'
import { judgeErrorTaxonomy } from './error-taxonomy.ts'
import type { ProbeCallResult } from './protocol.ts'
import { REASON_MESSAGES } from './reason-messages.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// 2. FROZEN_PRE_T73 — verbatim from @mcpcheckup/checks 0.4.0 (protocol.ts:17-78,
//    error-taxonomy.ts:14-23). Identifiers prefixed `frozen` only to avoid
//    colliding with anything imported above; bodies are unchanged.
// ---------------------------------------------------------------------------

interface FrozenParsedJsonRpc {
  isJsonRpc: boolean
  id?: unknown
  result?: unknown
  error?: { code: number; message: string; data?: unknown }
}

function frozenIsSseContentType(contentType?: string | null): boolean {
  return (contentType ?? '').toLowerCase().includes('text/event-stream')
}

function frozenExtractSseDataPayloads(bodyText: string): string[] {
  return bodyText
    .split(/\r?\n\r?\n/)
    .map((eventBlock) =>
      eventBlock
        .split(/\r?\n/)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice('data:'.length).replace(/^ /, ''))
        .join('\n'),
    )
    .filter((payload) => payload.length > 0)
}

function frozenParseJsonRpcText(bodyText: string): FrozenParsedJsonRpc {
  let parsed: unknown
  try {
    parsed = JSON.parse(bodyText)
  } catch {
    return { isJsonRpc: false }
  }
  if (typeof parsed !== 'object' || parsed === null) return { isJsonRpc: false }
  const obj = parsed as Record<string, unknown>
  if (obj.jsonrpc !== '2.0') return { isJsonRpc: false }
  if ('result' in obj) return { isJsonRpc: true, id: obj.id, result: obj.result }
  if (
    typeof obj.error === 'object' &&
    obj.error !== null &&
    typeof (obj.error as Record<string, unknown>).code === 'number' &&
    typeof (obj.error as Record<string, unknown>).message === 'string'
  ) {
    return { isJsonRpc: true, id: obj.id, error: obj.error as { code: number; message: string; data?: unknown } }
  }
  return { isJsonRpc: false }
}

function frozenParseJsonRpcBody(bodyText: string, contentType?: string | null): FrozenParsedJsonRpc {
  const candidates = frozenIsSseContentType(contentType) ? frozenExtractSseDataPayloads(bodyText) : [bodyText]
  for (const candidate of candidates) {
    const parsed = frozenParseJsonRpcText(candidate)
    if (parsed.isJsonRpc) return parsed
  }
  return { isJsonRpc: false }
}

function frozenJudgeErrorTaxonomy(callResult: ProbeCallResult): { status: 'VERIFIED' | 'OBSERVED_RISK' } {
  if (callResult.status === 401 || callResult.status === 403) {
    return { status: 'VERIFIED' }
  }
  const parsed = frozenParseJsonRpcBody(callResult.bodyText, callResult.headers.get('content-type'))
  if (parsed.isJsonRpc && parsed.error) {
    return { status: 'VERIFIED' }
  }
  return { status: 'OBSERVED_RISK' }
}

// ---------------------------------------------------------------------------
// 3. ORACLE — independent. Nothing below is imported from or copied out of
//    error-taxonomy.ts / protocol.ts.
// ---------------------------------------------------------------------------

const ORACLE_KEYS = [
  'error_taxonomy_empty_body',
  'error_taxonomy_event_stream_no_data',
  'error_taxonomy_result_is_error',
  'error_taxonomy_result_ok',
  'error_taxonomy_jsonrpc_malformed',
  'error_taxonomy_not_jsonrpc',
  'error_taxonomy_not_json',
] as const
const ORACLE_MEDIA_TYPES = ['application/json', 'text/event-stream', 'text/html', 'text/plain', 'none', 'other'] as const
const ORACLE_SCENARIO = 'tools_call_unknown_tool'

/** Line scanner: a line ends at LF; one CR immediately before that LF is part
 *  of the terminator. A blank line ends an event. Only lines beginning with the
 *  five characters `data:` contribute; one following space is dropped. An
 *  event whose data is the empty string yields nothing. */
function oracleSseData(raw: string): string[] {
  const events: string[] = []
  let current: string[] = []
  const endEvent = () => {
    const payload = current.join('\n')
    if (payload !== '') events.push(payload)
    current = []
  }
  let start = 0
  for (let i = 0; i <= raw.length; i++) {
    if (i < raw.length && raw[i] !== '\n') continue
    let line = raw.slice(start, i)
    if (i < raw.length && line.endsWith('\r')) line = line.slice(0, -1)
    start = i + 1
    if (line === '') { endEvent(); continue }
    if (line.slice(0, 5) === 'data:') current.push(line[5] === ' ' ? line.slice(6) : line.slice(5))
  }
  endEvent()
  return events
}

type Parsed = { ok: true; value: unknown } | { ok: false }
function oracleParse(s: string): Parsed {
  try { return { ok: true, value: JSON.parse(s) } } catch { return { ok: false } }
}
const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)

/** The pre-existing acceptance rule, restated from the MCP / JSON-RPC 2.0 shape:
 *  jsonrpc exactly "2.0", and either a `result` member, or an `error` object
 *  with a numeric code and a string message. */
function oracleAccepted(v: unknown): v is Record<string, unknown> {
  if (!isPlainObject(v) || v.jsonrpc !== '2.0') return false
  if (Object.prototype.hasOwnProperty.call(v, 'result')) return true
  const e = v.error
  return isPlainObject(e) && typeof e.code === 'number' && typeof e.message === 'string'
}

function oracleMediaType(ct: string | null): string {
  if (ct === null || ct.trim() === '') return 'none'
  const cut = ct.indexOf(';')
  const base = (cut < 0 ? ct : ct.substring(0, cut)).trim().toLowerCase()
  return (['application/json', 'text/event-stream', 'text/html', 'text/plain'] as string[]).indexOf(base) >= 0 ? base : 'other'
}

interface OracleCtx { raw: string; sse: boolean; parsed: Parsed[] }

const ORACLE_RULES: [string, (c: OracleCtx) => boolean][] = [
  ['empty_body', (c) => c.raw.length === 0],
  ['event_stream_no_data', (c) => c.sse && c.parsed.length === 0],
  ['result_is_error', (c) => {
    const first = c.parsed.find((p) => p.ok && oracleAccepted(p.value))
    if (!first || !first.ok) return false
    const result = (first.value as Record<string, unknown>).result
    return isPlainObject(result) && result.isError === true
  }],
  ['result_ok', (c) => c.parsed.some((p) => p.ok && oracleAccepted(p.value))],
  ['jsonrpc_malformed', (c) => c.parsed.some((p) => p.ok && isPlainObject(p.value) && p.value.jsonrpc === '2.0')],
  ['not_jsonrpc', (c) => c.parsed.some((p) => p.ok)],
  ['not_json', () => true],
]

function oracle(status: number, ct: string | null, raw: string): { key: string; params: Record<string, string | number> } {
  const sse = ct !== null && /text\/event-stream/i.test(ct)
  const texts = sse ? oracleSseData(raw) : [raw]
  const c: OracleCtx = { raw, sse, parsed: texts.map(oracleParse) }
  const cls = ORACLE_RULES.find(([, when]) => when(c))![0]
  const params: Record<string, string | number> = { scenario: ORACLE_SCENARIO, status, media_type: oracleMediaType(ct) }
  if (cls === 'jsonrpc_malformed') {
    const first = c.parsed.find((p) => p.ok && isPlainObject(p.value) && p.value.jsonrpc === '2.0') as { ok: true; value: Record<string, unknown> }
    const e = first.value.error
    if (isPlainObject(e) && Number.isSafeInteger(e.code)) params.jsonrpc_error_code = (e.code as number) === 0 ? 0 : (e.code as number)
  }
  return { key: `error_taxonomy_${cls}`, params }
}

// ---------------------------------------------------------------------------
// The adversarial input set.
// ---------------------------------------------------------------------------

const CANARY = 'CANARYq7Zx'
const STATUSES = [200, 202, 204, 400, 401, 403, 404, 405, 406, 415, 429, 500, 503]
const CONTENT_TYPES: (string | null)[] = [
  null,
  '',
  'application/json',
  'application/json; charset=utf-8',
  'APPLICATION/JSON',
  'text/event-stream',
  'Text/Event-Stream; charset=utf-8',
  'text/html; charset=UTF-8',
  'text/plain',
  'application/problem+json',
  'application/json, text/event-stream',
  '; charset=utf-8',
]

const ERR_OK = `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool ${CANARY}"}}`
const RES_ISERR = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"${CANARY}"}],"isError":true}}`
const RES_OK = '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}'
const NOTIF = '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}'

const BODIES: [string, string][] = [
  ['empty', ''],
  ['space', ' '],
  ['lf', '\n'],
  ['crlf-crlf', '\r\n\r\n'],
  ['tabs', '\t\t'],
  ['text', `Internal Server Error ${CANARY}`],
  ['html', `<html><body><h1>Not Found</h1><p>${CANARY}</p></body></html>`],
  ['bom-error', `﻿${ERR_OK}`],
  ['bom-result', `﻿${RES_ISERR}`],
  ['error-ok', ERR_OK],
  ['error-ok-ws', `  ${ERR_OK}\n`],
  ['error-code-string', '{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"m"}}'],
  ['error-no-message', '{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}'],
  ['error-message-number', '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":5}}'],
  ['error-null', '{"jsonrpc":"2.0","id":1,"error":null}'],
  ['error-array', '{"jsonrpc":"2.0","id":1,"error":[]}'],
  ['error-string', `{"jsonrpc":"2.0","id":1,"error":"${CANARY}"}`],
  ['error-code-1.5', '{"jsonrpc":"2.0","id":1,"error":{"code":1.5}}'],
  ['error-code-huge', '{"jsonrpc":"2.0","id":1,"error":{"code":9007199254740993}}'],
  ['error-code-inf', '{"jsonrpc":"2.0","id":1,"error":{"code":1e400}}'],
  ['error-code-neg0', '{"jsonrpc":"2.0","id":1,"error":{"code":-0}}'],
  ['error-code-max-safe', '{"jsonrpc":"2.0","id":1,"error":{"code":-9007199254740991}}'],
  ['error-code-huge-with-message', '{"jsonrpc":"2.0","id":1,"error":{"code":1e300,"message":"m"}}'],
  ['result-and-error', '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32602,"message":"m"}}'],
  ['result-iserror-true', RES_ISERR],
  ['result-iserror-string', '{"jsonrpc":"2.0","id":1,"result":{"isError":"true"}}'],
  ['result-iserror-1', '{"jsonrpc":"2.0","id":1,"result":{"isError":1}}'],
  ['result-iserror-false', '{"jsonrpc":"2.0","id":1,"result":{"isError":false}}'],
  ['result-ok', RES_OK],
  ['result-null', '{"jsonrpc":"2.0","id":1,"result":null}'],
  ['result-array', '{"jsonrpc":"2.0","id":1,"result":[{"isError":true}]}'],
  ['jsonrpc-1.0', '{"jsonrpc":"1.0","id":1,"error":{"code":-32602,"message":"m"}}'],
  ['jsonrpc-number', '{"jsonrpc":2.0,"id":1,"error":{"code":-32602,"message":"m"}}'],
  ['no-jsonrpc', `{"error":"${CANARY}"}`],
  ['empty-object', '{}'],
  ['jsonrpc-only', '{"jsonrpc":"2.0"}'],
  ['batch-array', `[${ERR_OK}]`],
  ['primitive-number', '42'],
  ['primitive-null', 'null'],
  ['primitive-true', 'true'],
  ['primitive-string', `"${CANARY}"`],
  ['notification', NOTIF],
  ['truncated', '{"jsonrpc":"2.0","id":1,"err'],
  ['sse-error', `event: message\ndata: ${ERR_OK}\n\n`],
  ['sse-iserror', `event: message\ndata: ${RES_ISERR}\n\n`],
  ['sse-nospace-ok', `data:${RES_OK}\n\n`],
  ['sse-crlf-iserror', `event: message\r\ndata: ${RES_ISERR}\r\n\r\n`],
  ['sse-multiline', 'data: {"jsonrpc":"2.0",\ndata: "id":1,\ndata: "result":{"isError":true}}\n\n'],
  ['sse-comment-only', ': ping\n\n'],
  ['sse-notif-then-iserror', `data: ${NOTIF}\n\ndata: ${RES_ISERR}\n\n`],
  ['sse-notif-then-error', `data: ${NOTIF}\n\ndata: ${ERR_OK}\n\n`],
  ['sse-notif-only', `data: ${NOTIF}\n\n`],
  ['sse-malformed-then-ok', `data: {"jsonrpc":"2.0","id":1,"error":{"code":-32000}}\n\ndata: ${RES_OK}\n\n`],
  ['sse-array-then-notif', `data: [1]\n\ndata: ${NOTIF}\n\n`],
  ['sse-data-text', `data: hello ${CANARY}\n\n`],
  ['sse-data-number', 'data: 42\n\n'],
  ['sse-empty-data', 'data:\n\n'],
  ['sse-leading-space', ` data: ${RES_OK}\n\n`],
  ['sse-two-spaces', `data:  ${RES_ISERR}\n\n`],
  ['sse-no-trailing-blank', `data: ${RES_ISERR}`],
  ['sse-cr-only', `data: ${RES_OK}\r\r`],
  ['sse-triple-lf', `\n\n\ndata: ${RES_ISERR}\n\n\n`],
  ['sse-lf-crlf-mix', `data: ${NOTIF}\n\r\ndata: {"jsonrpc":"2.0","id":1,"error":{"code":7}}\r\n\n`],
]

const BANNED = ['certified', 'secure', 'safe', 'trusted', '评分', '健康度']
const WINDOW = 8

function callResult(status: number, ct: string | null, bodyText: string): ProbeCallResult {
  const headers = new Headers()
  if (ct !== null) headers.set('content-type', ct)
  return { status, headers, bodyText, currentEndpoint: 'https://notes-mcp.example.com/mcp' }
}

console.log('T73 differential invariant：新判定 vs 冻结的 pre-T73 判定 vs 独立 oracle')

const inputCount = STATUSES.length * CONTENT_TYPES.length * BODIES.length
console.log(`  adversarial input set: ${STATUSES.length} statuses × ${CONTENT_TYPES.length} content-types × ${BODIES.length} bodies = ${inputCount} inputs`)

const classCounts = new Map<string, number>()
let verifiedCount = 0
const failures: string[] = []
const failuresByInvariant = { a: 0, b: 0, c: 0, d: 0 }

for (const status of STATUSES) {
  for (const ct of CONTENT_TYPES) {
    for (const [label, body] of BODIES) {
      const id = `status=${status} ct=${JSON.stringify(ct)} body=${label}`
      const input = callResult(status, ct, body)
      const got = judgeErrorTaxonomy(input)
      const frozen = frozenJudgeErrorTaxonomy(callResult(status, ct, body))

      // (a)
      if (got.status !== frozen.status) {
        failuresByInvariant.a++
        failures.push(`(a) ${id}: new=${got.status} pre-T73=${frozen.status}`)
        continue
      }

      if (got.status === 'VERIFIED') {
        verifiedCount++
        // (b) VERIFIED side
        if ('reason' in got) { failuresByInvariant.b++; failures.push(`(b) ${id}: VERIFIED carries a reason`) }
        continue
      }

      // (b) OBSERVED_RISK side
      const want = oracle(status, ct, body)
      const reason = got.reason
      try {
        assert.ok(reason !== null && reason !== undefined, 'OBSERVED_RISK without a reason')
        assert.ok((ORACLE_KEYS as readonly string[]).includes(reason!.key), `key ${reason!.key} is not one of the seven T73 keys`)
        assert.deepStrictEqual(reason, want)
      } catch (e) {
        failuresByInvariant.b++
        failures.push(`(b) ${id}: got ${JSON.stringify(reason)} want ${JSON.stringify(want)} — ${(e as Error).message.split('\n')[0]}`)
        continue
      }
      classCounts.set(reason!.key, (classCounts.get(reason!.key) ?? 0) + 1)

      // (c)
      const params = reason!.params ?? {}
      const keys = Object.keys(params).sort()
      const base = ['media_type', 'scenario', 'status']
      const okKeys =
        JSON.stringify(keys) === JSON.stringify(base) ||
        (reason!.key === 'error_taxonomy_jsonrpc_malformed' && JSON.stringify(keys) === JSON.stringify(['jsonrpc_error_code', ...base]))
      const cProblems: string[] = []
      if (!okKeys) cProblems.push(`param keys ${JSON.stringify(keys)}`)
      if (params.scenario !== ORACLE_SCENARIO) cProblems.push(`scenario ${JSON.stringify(params.scenario)}`)
      if (!Number.isInteger(params.status) || params.status !== status) cProblems.push(`status ${JSON.stringify(params.status)}`)
      if (!(ORACLE_MEDIA_TYPES as readonly unknown[]).includes(params.media_type)) cProblems.push(`media_type ${JSON.stringify(params.media_type)}`)
      if ('jsonrpc_error_code' in params && !Number.isSafeInteger(params.jsonrpc_error_code)) cProblems.push(`jsonrpc_error_code ${String(params.jsonrpc_error_code)}`)
      if (cProblems.length > 0) { failuresByInvariant.c++; failures.push(`(c) ${id}: ${cProblems.join('; ')}`) }

      // (d)
      const entry = REASON_MESSAGES[reason!.key]
      for (const locale of ['en', 'zh'] as const) {
        let rendered: string
        try {
          assert.ok(entry, `no REASON_MESSAGES entry for ${reason!.key}`)
          rendered = entry![locale](reason!.params)
        } catch (e) {
          failuresByInvariant.d++
          failures.push(`(d) ${id}/${locale}: render threw — ${(e as Error).message}`)
          continue
        }
        const dProblems: string[] = []
        if (rendered.length === 0) dProblems.push('empty')
        const lower = rendered.toLowerCase()
        for (const w of BANNED) if (lower.includes(w)) dProblems.push(`banned word ${w}`)
        if (rendered.includes(CANARY)) dProblems.push('canary echoed')
        for (let i = 0; i + WINDOW <= body.length; i++) {
          const w = body.slice(i, i + WINDOW)
          if (rendered.includes(w)) { dProblems.push(`body window ${JSON.stringify(w)} echoed`); break }
        }
        if (dProblems.length > 0) { failuresByInvariant.d++; failures.push(`(d) ${id}/${locale}: ${dProblems.join('; ')}`) }
      }
    }
  }
}

await t(`(a)-(d) hold for all ${inputCount} inputs`, () => {
  if (failures.length > 0) {
    const shown = failures.slice(0, 25).join('\n         ')
    throw new Error(
      `${failures.length} violation(s) — by invariant: ${JSON.stringify(failuresByInvariant)}\n         ${shown}` +
        (failures.length > 25 ? `\n         … and ${failures.length - 25} more` : ''),
    )
  }
})

await t('the input set is not vacuous: every one of the seven classes, and VERIFIED, is hit', () => {
  console.log(`       VERIFIED=${verifiedCount} ${ORACLE_KEYS.map((k) => `${k.replace('error_taxonomy_', '')}=${classCounts.get(k) ?? 0}`).join(' ')}`)
  assert.ok(verifiedCount > 0, 'no VERIFIED input at all')
  for (const k of ORACLE_KEYS) assert.ok((classCounts.get(k) ?? 0) > 0, `${k} never produced — the set does not cover that boundary`)
})

await t('the oracle agrees with itself on the hand-derived anchor cases (guards the oracle, not the judge)', () => {
  assert.equal(oracle(503, null, '').key, 'error_taxonomy_empty_body')
  assert.equal(oracle(200, 'text/event-stream', ': ping\n\n').key, 'error_taxonomy_event_stream_no_data')
  assert.equal(oracle(200, 'application/json', RES_ISERR).key, 'error_taxonomy_result_is_error')
  assert.equal(oracle(200, 'application/json', '{"jsonrpc":"2.0","id":1,"result":{"isError":1}}').key, 'error_taxonomy_result_ok')
  assert.deepStrictEqual(oracle(200, 'application/json', '{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}').params.jsonrpc_error_code, -32601)
  assert.equal(oracle(200, 'application/json', '[1]').key, 'error_taxonomy_not_jsonrpc')
  assert.equal(oracle(200, 'application/json', ' ').key, 'error_taxonomy_not_json')
  assert.deepStrictEqual(oracleSseData('data: a\r\n\r\ndata:b\ndata: c\n\n: x\n\ndata:\n\n'), ['a', 'b\nc'])
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
