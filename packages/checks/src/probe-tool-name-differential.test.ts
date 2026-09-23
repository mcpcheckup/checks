/**
 * T86 differential invariant test — the primary evidence that withholding the
 * tools/call carrying the probe's reserved tool name changed nothing else.
 *
 * Three parties, the same shape as failed-reasons-differential.test.ts (T73b),
 * whose scripted server, T73 corpus, stage generators and oracle reading
 * functions are reused below verbatim (marked):
 *
 *   1. The implementation: runProbe (./probe.ts), end to end.
 *   2. FROZEN 0.6.0 — ./frozen/suite-0.6.0/{probe,protocol,error-taxonomy}.ts,
 *      byte-for-byte the suite 0.6.0 (a05097e) files apart from a four-line
 *      `// FROZEN:` header and `../../` import paths; the first test below
 *      recomputes each file's git blob id to prove it. They still import what
 *      T86 does not touch (wire.ts, auth.ts, hygiene.ts, fingerprint.ts,
 *      registry.ts, types.ts, checks.json — `git diff a05097e` on those is
 *      empty for T86). A later change to one of them must freeze the 0.6.0
 *      version first, or this stops being a differential. DO NOT "update" the
 *      frozen copy to match a later implementation.
 *   3. ORACLE — T73b's independent JSON-RPC / SSE reading and handshake
 *      classification (verbatim), plus the T86 rule as ordered branches. It
 *      imports nothing from ./probe.ts or ./protocol.ts.
 *
 * Invariant, for every input:
 *   - ORACLE says the call is sent (a complete first page with no exact
 *     reserved name, or a credential gate with no readable list — T86 R2:
 *     a readable list is judged even behind a gated handshake), or the run aborts before
 *     the call (a 429 / 503 + Retry-After, or 0.6.0's own throw on a null
 *     tool entry) ⇒ the implementation's ProbeResult is identical to 0.6.0's
 *     (same own keys in the same order at every level, Object.is on every
 *     leaf — stricter than equal JSON bytes), and so is the request sequence.
 *     Nothing is normalized: ProbeResult carries no suite version.
 *   - ORACLE says the call is withheld (exact name on the first page ⇒
 *     probe_tool_name_collision; a nextCursor, or tools/list failed ⇒
 *     probe_tool_name_unverifiable) ⇒ no tools/call is on the wire, the
 *     request sequence is 0.6.0's up to that call, error_taxonomy and
 *     auth_metadata are SKIPPED / UNVERIFIED with reason and unverified_reason
 *     exactly `{ key }` (no params member), and every other row and
 *     ProbeResult field is identical to 0.6.0's run against the same server
 *     answering tools/call with the ordinary unknown-tool error (0.6.0 would
 *     have sent the call; an aborting reply there would cascade rows the new
 *     code legitimately judges, so the comparison fixes a non-aborting one).
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import { runProbe } from './probe.ts'
import { runProbe as frozenRunProbe } from './frozen/suite-0.6.0/probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { FetchLike, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// The frozen copy is what it says it is.
// ---------------------------------------------------------------------------

/** Blob ids of packages/checks/src/{name}.ts at a05097e (suite 0.6.0),
 *  from `git rev-parse a05097e:packages/checks/src/<name>.ts`. */
const FROZEN_BLOBS: Record<string, string> = {
  'probe': 'fb4a0e8666d4afe32d96c2e4ea46b4541867ceaa',
  'protocol': '8edaf3a8dd2c2af90e9702425557ca9601fe0342',
  'error-taxonomy': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
}

await t('the frozen 0.6.0 files are the a05097e blobs: header dropped, import paths restored, git blob id recomputed', () => {
  for (const [name, blob] of Object.entries(FROZEN_BLOBS)) {
    const raw = readFileSync(new URL(`./frozen/suite-0.6.0/${name}.ts`, import.meta.url), 'utf8').replace(/\r\n/g, '\n')
    const lines = raw.split('\n')
    let header = 0
    while (lines[header]!.startsWith('// FROZEN:')) header++
    assert.equal(header, 4, `${name}: expected the four-line FROZEN header`)
    const restored = lines.slice(header).map((l) => (l.startsWith('import ') ? l.replace("from '../../", "from './") : l)).join('\n')
    const bytes = Buffer.from(restored, 'utf8')
    const id = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
    assert.equal(id, blob, `${name}.ts is not the 0.6.0 file`)
  }
})

// ---------------------------------------------------------------------------
// The scripted server — verbatim from failed-reasons-differential.test.ts (T73b).
// ---------------------------------------------------------------------------

const ENDPOINT = 'https://notes-mcp.example.com/mcp'
const CANARY = 'CANARYq7Zx'
const VALID_CHALLENGE = 'Bearer realm="mcp"'

/** `challenge` labels a response the generator gave the known-valid
 *  WWW-Authenticate above — the ORACLE's only source for "is there a
 *  structurally valid challenge", so it never parses the header itself. */
interface Resp { status: number; headers: Headers; body: string; challenge: boolean }

function resp(status: number, ct: string | null, body: string, extra: { location?: string; challenge?: boolean } = {}): Resp {
  const headers = new Headers()
  if (ct !== null) headers.set('content-type', ct)
  if (extra.location !== undefined) headers.set('location', extra.location)
  if (extra.challenge) headers.set('www-authenticate', VALID_CHALLENGE)
  return { status, headers, body, challenge: !!extra.challenge }
}

/** Duck-typed on purpose: sendRequest reads only status, headers and text(),
 *  and a real Response refuses a body on 204 — which would silently drop
 *  (204 × body) cells out of the T73 corpus. */
function toResponse(r: Resp): Response {
  return { status: r.status, headers: r.headers, text: async () => r.body } as unknown as Response
}

interface Script { discover: Resp; initialize: Resp; ack: Resp; toolsList: Resp }

// ---------------------------------------------------------------------------
// T86 additions to the scripted server: a scripted tools/call reply, the
// resource_metadata document a challenged tools/call points at, and a record
// of every request.
// ---------------------------------------------------------------------------

const RESERVED = '__mcpcheckup_probe_nonexistent_tool__'
const METADATA_PATH = '/.well-known/oauth-protected-resource'
const METADATA_CHALLENGE = `Bearer realm="mcp", resource_metadata="https://notes-mcp.example.com${METADATA_PATH}"`

interface T86Script extends Script { toolsCall: Resp }

/** 0.6.0's pinned unknown-tool reply (T73b's TOOLS_CALL_REPLY): an ordinary JSON-RPC error. */
const CALL_DEFAULT = resp(200, 'application/json', '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool"}}')
/** A server that would run the tool: a successful result. */
const CALL_RUNS = resp(200, 'application/json', '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}]}}')
/** Gated invocation: 401 + a challenge whose metadata document is served. */
const CALL_GATED = (() => {
  const r = resp(401, null, '')
  r.headers.set('www-authenticate', METADATA_CHALLENGE)
  return r
})()
/** Rate-limited invocation: aborts the round at tools/call. */
const CALL_429 = resp(429, null, '')
const TOOLS_CALL_REPLIES: [string, Resp][] = [['default', CALL_DEFAULT], ['runs', CALL_RUNS], ['gated', CALL_GATED], ['429', CALL_429]]
const METADATA_DOC = resp(200, 'application/json', '{"resource":"https://notes-mcp.example.com","authorization_servers":["https://notes-mcp.example.com/oauth"]}')

function recordingFetch(s: T86Script, calls: string[]): FetchLike {
  return async (input, init) => {
    const method = typeof init?.body === 'string' ? (JSON.parse(init.body) as { method?: unknown }).method : undefined
    const path = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url).pathname
    calls.push(typeof method === 'string' ? method : `${init?.method ?? 'GET'} ${path}`)
    const r =
      method === 'server/discover' ? s.discover
      : method === 'initialize' ? s.initialize
      : method === 'notifications/initialized' ? s.ack
      : method === 'tools/list' ? s.toolsList
      : method === 'tools/call' ? s.toolsCall
      : path === METADATA_PATH ? METADATA_DOC
      : resp(404, 'text/plain', 'Not Found')
    return toResponse(r)
  }
}

async function run(probe: typeof runProbe, s: T86Script): Promise<{ result: ProbeResult; calls: string[] }> {
  const calls: string[] = []
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: recordingFetch(s, calls),
    budget: DEFAULT_PROBE_BUDGET,
    now: () => '2026-09-23T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  })
  return { result, calls }
}

// ---------------------------------------------------------------------------
// ORACLE — verbatim from failed-reasons-differential.test.ts (T73b): reason
// constructor, SSE / JSON-RPC reading, handshake classification.
// ---------------------------------------------------------------------------

type OReason = { key: string; params?: Record<string, number> }
const K = (key: string, params: Record<string, number> = {}): OReason => (Object.keys(params).length > 0 ? { key, params } : { key })

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

const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)

type OMessage = { kind: 'result'; result: unknown } | { kind: 'error'; code: number } | null

/** The first candidate that is a JSON-RPC 2.0 message: jsonrpc exactly
 *  "2.0" and either a `result` member (which wins over an error), or an
 *  error object with a numeric code and a string message. */
function oracleRead(r: Resp): OMessage {
  const ct = r.headers.get('content-type')
  const texts = ct !== null && /text\/event-stream/i.test(ct) ? oracleSseData(r.body) : [r.body]
  for (const text of texts) {
    let v: unknown
    try { v = JSON.parse(text) } catch { continue }
    if (!isPlainObject(v) || v.jsonrpc !== '2.0') continue
    if (Object.prototype.hasOwnProperty.call(v, 'result')) return { kind: 'result', result: v.result }
    const e = v.error
    if (isPlainObject(e) && typeof e.code === 'number' && typeof e.message === 'string') return { kind: 'error', code: e.code }
  }
  return null
}

function oracleField(m: OMessage, field: string): unknown {
  if (m === null || m.kind !== 'result') return undefined
  const r = m.result
  return r !== null && typeof r === 'object' && !Array.isArray(r) ? (r as Record<string, unknown>)[field] : undefined
}

function oracleCode(m: OMessage): Record<string, number> {
  if (m === null || m.kind !== 'error' || !Number.isSafeInteger(m.code)) return {}
  return { jsonrpc_error_code: Object.is(m.code, -0) ? 0 : m.code }
}

const rateLimited = (r: Resp) => r.status === 429 || (r.status === 503 && r.headers.has('retry-after'))
const challenged = (r: Resp) => r.status === 401 && r.challenge

type OHandshake = { aborted: true } | { aborted: false; ok: boolean; gated: boolean; declared: string | null; fail?: OReason }

function oracleHandshake(s: Script): OHandshake {
  const d = s.discover
  if (rateLimited(d)) return { aborted: true }
  if (d.status === 200) {
    const m = oracleRead(d)
    const sv = oracleField(m, 'supportedVersions')
    if (Array.isArray(sv) && typeof sv[0] === 'string') return { aborted: false, ok: true, gated: false, declared: sv[0] }
    const fail = m === null ? K('handshake_discover_not_jsonrpc') : m.kind === 'error' ? K('handshake_discover_jsonrpc_error', oracleCode(m)) : K('handshake_discover_no_supported_versions')
    return { aborted: false, ok: false, gated: false, declared: null, fail }
  }
  if (d.status >= 400 && d.status <= 499) {
    const m = oracleRead(d)
    if (m !== null && m.kind === 'error' && [-32020, -32021, -32022].includes(m.code)) {
      return { aborted: false, ok: false, gated: false, declared: null, fail: K('handshake_discover_rejected', { status: d.status, jsonrpc_error_code: m.code }) }
    }
    const i = s.initialize
    if (rateLimited(i)) return { aborted: true }
    if (i.status !== 200) return { aborted: false, ok: false, gated: challenged(i), declared: null, fail: K('handshake_initialize_http_error', { status: i.status }) }
    const im = oracleRead(i)
    const pv = oracleField(im, 'protocolVersion')
    if (typeof pv !== 'string') {
      const fail = im === null ? K('handshake_initialize_not_jsonrpc') : im.kind === 'error' ? K('handshake_initialize_jsonrpc_error', oracleCode(im)) : K('handshake_initialize_no_protocol_version')
      return { aborted: false, ok: false, gated: false, declared: null, fail }
    }
    const a = s.ack
    if (rateLimited(a)) return { aborted: true }
    if (a.status < 200 || a.status > 299) return { aborted: false, ok: false, gated: challenged(a), declared: pv, fail: K('handshake_ack_http_error', { status: a.status }) }
    return { aborted: false, ok: true, gated: false, declared: pv }
  }
  return { aborted: false, ok: false, gated: false, declared: null, fail: K('handshake_discover_http_error', { status: d.status }) }
}

// ---------------------------------------------------------------------------
// ORACLE — the T86 rule, as ordered branches over the reading above.
// ---------------------------------------------------------------------------

type Decision = 'abort' | 'send' | OReason

const branchCounts = new Map<string, number>()

function oracleDecision(s: Script): Decision {
  const branch = (name: string, d: Decision): Decision => {
    branchCounts.set(name, (branchCounts.get(name) ?? 0) + 1)
    return d
  }
  const hs = oracleHandshake(s)
  if (hs.aborted) return branch('abort (handshake)', 'abort')
  const tl = s.toolsList
  if (rateLimited(tl)) return branch('abort (tools/list)', 'abort')
  const challenge = challenged(tl)
  const m = oracleRead(tl)
  const tools = oracleField(m, 'tools')
  const readable = Array.isArray(tools) && !challenge
  /** a / b on a readable first page (T86 R2: on every branch, gated or not). */
  const listVerdict = (list: unknown[], where: string): Decision | null => {
    if (list.some((tool) => isPlainObject(tool) && tool.name === RESERVED)) return branch(`a (collision${where})`, K('probe_tool_name_collision'))
    const result = (m as { result: Record<string, unknown> }).result
    if (Object.prototype.hasOwnProperty.call(result, 'nextCursor') && result.nextCursor !== null) return branch(`b (nextCursor${where})`, K('probe_tool_name_unverifiable'))
    return null
  }
  if (hs.gated) {
    // The handshake-gated branch never runs the hygiene check, so a null entry does not throw there.
    if (readable) return listVerdict(tools as unknown[], ', handshake gated') ?? branch('send (handshake gated, readable, no collision)', 'send')
    return branch('c1 (handshake gated, no readable list)', 'send')
  }
  if (hs.ok && challenge) return branch('c1 (tools/list gated)', 'send')
  if (!readable) return branch('c2 (tools/list failed)', K('probe_tool_name_unverifiable'))
  const list = tools as unknown[]
  // Unchanged since 0.6.0: a null entry makes the hygiene check throw, and the
  // catch cascades every check not yet written, these two rows included.
  if (list.includes(null)) return branch('abort (null tool entry)', 'abort')
  return listVerdict(list, '') ?? branch('send (complete, no collision)', 'send')
}

// ---------------------------------------------------------------------------
// The per-input check.
// ---------------------------------------------------------------------------

const T86_ROWS = ['error_taxonomy', 'auth_metadata']
const failures: string[] = []
let violations = 0
const decisionCounts = new Map<string, number>()

function violation(id: string, what: string) {
  violations++
  if (failures.length < 200) failures.push(`${id}: ${what}`)
}

/** Identical own keys in identical order at every level, Object.is on every
 *  leaf (iterative: some tool arrays are deep). */
function identical(a: unknown, b: unknown): boolean {
  const stack: [unknown, unknown][] = [[a, b]]
  while (stack.length > 0) {
    const [x, y] = stack.pop()!
    if (x === null || y === null || typeof x !== 'object' || typeof y !== 'object') {
      if (!Object.is(x, y)) return false
      continue
    }
    if (Array.isArray(x) !== Array.isArray(y)) return false
    const kx = Object.keys(x), ky = Object.keys(y)
    if (kx.length !== ky.length || kx.some((k, i) => k !== ky[i])) return false
    for (const k of kx) stack.push([(x as Record<string, unknown>)[k], (y as Record<string, unknown>)[k]])
  }
  return true
}

const withoutT86Rows = (r: ProbeResult) => ({ ...r, assertions: r.assertions.filter((a) => !T86_ROWS.includes(a.check_id)) })

async function checkInput(id: string, s: T86Script): Promise<void> {
  const want = oracleDecision(s)
  const label = typeof want === 'string' ? want : want.key
  decisionCounts.set(label, (decisionCounts.get(label) ?? 0) + 1)
  const now = await run(runProbe, s)
  const sent = now.calls.includes('tools/call')

  if (typeof want === 'string') {
    const then = await run(frozenRunProbe, s)
    if (want === 'send' && !sent) violation(id, 'oracle says send, implementation withheld tools/call')
    if (want === 'abort' && sent) violation(id, 'oracle says the round aborts before the decision, but tools/call was sent')
    if (!identical(now.calls, then.calls)) violation(id, `requests ${JSON.stringify(now.calls)} vs 0.6.0 ${JSON.stringify(then.calls)}`)
    if (!identical(now.result, then.result)) violation(id, 'ProbeResult differs from 0.6.0')
    return
  }

  const then = await run(frozenRunProbe, { ...s, toolsCall: CALL_DEFAULT })
  if (sent) violation(id, `oracle says withhold (${want.key}), tools/call was sent`)
  const cut = then.calls.indexOf('tools/call')
  if (cut < 0 || !identical(now.calls, then.calls.slice(0, cut))) violation(id, `requests ${JSON.stringify(now.calls)} vs 0.6.0 ${JSON.stringify(then.calls)}`)
  for (const check_id of T86_ROWS) {
    const a = now.result.assertions.find((x) => x.check_id === check_id)!
    if (a.execution_status !== 'SKIPPED' || a.assertion_status !== 'UNVERIFIED' || !identical(a.reason, want) || !identical(a.unverified_reason, want)) {
      violation(id, `${check_id} = ${a.execution_status}/${a.assertion_status} ${JSON.stringify(a.reason)} / ${JSON.stringify(a.unverified_reason)}, oracle ${JSON.stringify(want)}`)
    }
  }
  if (!identical(withoutT86Rows(now.result), withoutT86Rows(then.result))) violation(id, 'outside error_taxonomy / auth_metadata, the result differs from 0.6.0')
}

// ---------------------------------------------------------------------------
// The input set — verbatim from failed-reasons-differential.test.ts (T73b):
// statuses, content types, the T73 corpus, stage-specific bodies, pinned
// stages and the four wire-stage generators.
// ---------------------------------------------------------------------------

const STATUSES = [200, 202, 204, 400, 401, 403, 404, 405, 406, 415, 429, 500, 503]
const REDIRECTS = [301, 302, 303, 307, 308]
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

// The T73 corpus bodies, verbatim (error-taxonomy-differential.test.ts).
const ERR_OK = `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool ${CANARY}"}}`
const RES_ISERR = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"${CANARY}"}],"isError":true}}`
const RES_OK = '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}'
const NOTIF = '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}'
const CORPUS_BODIES: string[] = [
  '', ' ', '\n', '\r\n\r\n', '\t\t',
  `Internal Server Error ${CANARY}`,
  `<html><body><h1>Not Found</h1><p>${CANARY}</p></body></html>`,
  `﻿${ERR_OK}`, `﻿${RES_ISERR}`, ERR_OK, `  ${ERR_OK}\n`,
  '{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"m"}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":5}}',
  '{"jsonrpc":"2.0","id":1,"error":null}',
  '{"jsonrpc":"2.0","id":1,"error":[]}',
  `{"jsonrpc":"2.0","id":1,"error":"${CANARY}"}`,
  '{"jsonrpc":"2.0","id":1,"error":{"code":1.5}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":9007199254740993}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":1e400}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-0}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-9007199254740991}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":1e300,"message":"m"}}',
  '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32602,"message":"m"}}',
  RES_ISERR,
  '{"jsonrpc":"2.0","id":1,"result":{"isError":"true"}}',
  '{"jsonrpc":"2.0","id":1,"result":{"isError":1}}',
  '{"jsonrpc":"2.0","id":1,"result":{"isError":false}}',
  RES_OK,
  '{"jsonrpc":"2.0","id":1,"result":null}',
  '{"jsonrpc":"2.0","id":1,"result":[{"isError":true}]}',
  '{"jsonrpc":"1.0","id":1,"error":{"code":-32602,"message":"m"}}',
  '{"jsonrpc":2.0,"id":1,"error":{"code":-32602,"message":"m"}}',
  `{"error":"${CANARY}"}`,
  '{}',
  '{"jsonrpc":"2.0"}',
  `[${ERR_OK}]`,
  '42', 'null', 'true', `"${CANARY}"`,
  NOTIF,
  '{"jsonrpc":"2.0","id":1,"err',
  `event: message\ndata: ${ERR_OK}\n\n`,
  `event: message\ndata: ${RES_ISERR}\n\n`,
  `data:${RES_OK}\n\n`,
  `event: message\r\ndata: ${RES_ISERR}\r\n\r\n`,
  'data: {"jsonrpc":"2.0",\ndata: "id":1,\ndata: "result":{"isError":true}}\n\n',
  ': ping\n\n',
  `data: ${NOTIF}\n\ndata: ${RES_ISERR}\n\n`,
  `data: ${NOTIF}\n\ndata: ${ERR_OK}\n\n`,
  `data: ${NOTIF}\n\n`,
  `data: {"jsonrpc":"2.0","id":1,"error":{"code":-32000}}\n\ndata: ${RES_OK}\n\n`,
  `data: [1]\n\ndata: ${NOTIF}\n\n`,
  `data: hello ${CANARY}\n\n`,
  'data: 42\n\n',
  'data:\n\n',
  ` data: ${RES_OK}\n\n`,
  `data:  ${RES_ISERR}\n\n`,
  `data: ${RES_ISERR}`,
  `data: ${RES_OK}\r\r`,
  `\n\n\ndata: ${RES_ISERR}\n\n\n`,
  `data: ${NOTIF}\n\r\ndata: {"jsonrpc":"2.0","id":1,"error":{"code":7}}\r\n\n`,
]

const rpcResult = (result: string) => `{"jsonrpc":"2.0","id":1,"result":${result}}`
const rpcError = (code: string, message = `"m ${CANARY}"`) => `{"jsonrpc":"2.0","id":1,"error":{"code":${code},"message":${message}}}`
const sse = (json: string) => `event: message\ndata: ${json}\n\n`

const DISCOVER_BODIES: string[] = [
  rpcResult('{"supportedVersions":["2026-07-28"],"capabilities":{}}'),
  rpcResult(`{"supportedVersions":["${CANARY}-2026"]}`),
  rpcResult('{"supportedVersions":["2025-06-18","2026-07-28"]}'),
  rpcResult('{"supportedVersions":[""]}'),
  rpcResult('{"capabilities":{}}'),
  rpcResult('{"supportedVersions":[]}'),
  rpcResult('{"supportedVersions":[20260728]}'),
  rpcResult('{"supportedVersions":[null,"2026-07-28"]}'),
  rpcResult('{"supportedVersions":"2026-07-28"}'),
  rpcResult('{"supportedVersions":{"0":"2026-07-28"}}'),
  rpcResult('"2026-07-28"'),
  rpcError('-32020'), rpcError('-32021'), rpcError('-32022'),
  rpcError('-32601'), rpcError('-32000'), rpcError('-0'), rpcError('1.5'), rpcError('-32020.5'), rpcError('1e300'),
  '{"jsonrpc":"2.0","id":1,"error":{"code":-32020}}',
  sse(rpcResult('{"supportedVersions":["2026-07-28"]}')),
  sse(rpcError('-32022')),
  `data: ${NOTIF}\n\n${sse(rpcResult('{"supportedVersions":["2025-11-25"]}'))}`,
]

const INITIALIZE_BODIES: string[] = [
  rpcResult('{"protocolVersion":"2025-06-18","capabilities":{}}'),
  rpcResult('{"protocolVersion":"2025-03-26"}'),
  rpcResult('{"protocolVersion":"2024-11-05"}'),
  rpcResult('{"protocolVersion":"2023-01-01"}'),
  rpcResult('{"protocolVersion":"2099-01-01"}'),
  rpcResult(`{"protocolVersion":"${CANARY}"}`),
  rpcResult('{"protocolVersion":""}'),
  rpcResult('{"protocolVersion":20250618}'),
  rpcResult('{"protocolVersion":null}'),
  rpcResult('{"protocolVersion":["2025-06-18"]}'),
  rpcResult('{"capabilities":{}}'),
  rpcResult('null'),
  rpcResult('["2025-06-18"]'),
  rpcError('-32602'), rpcError('-32601'), rpcError('-0'), rpcError('1.5'), rpcError('9007199254740993'), rpcError('-32022'),
  sse(rpcResult('{"protocolVersion":"2025-06-18"}')),
  sse(rpcError('-32603')),
]

const VALID_TOOLS = '[{"name":"search_notes","inputSchema":{"type":"object"}},{"name":"get_note","inputSchema":{"type":"object"}}]'
const TOOLS_BODIES: string[] = [
  rpcResult(`{"tools":${VALID_TOOLS}}`),
  rpcResult('{"tools":[]}'),
  rpcResult(`{"tools":"${CANARY}"}`),
  rpcResult('{"tools":null}'),
  rpcResult('{"tools":{"0":{"name":"a"}}}'),
  rpcResult('{"nextCursor":"x"}'),
  rpcResult('[]'),
  rpcResult('{"tools":[{"description":"no name","inputSchema":{}}]}'),
  rpcResult('{"tools":[{"name":"a"}]}'),
  sse(rpcResult(`{"tools":${VALID_TOOLS}}`)),
  sse(rpcError('-32603')),
  rpcError('-32603'), rpcError('-0'), rpcError('1e300'),
]

// Pinned stages.
const DISCOVER_OK = resp(200, 'application/json', rpcResult('{"supportedVersions":["2026-07-28"]}'))
const DISCOVER_FALLBACK = resp(404, 'text/plain', 'Not Found')
const DISCOVER_FAILED = resp(500, 'text/plain', 'Internal Server Error')
const INIT_OK = resp(200, 'application/json', rpcResult('{"protocolVersion":"2025-06-18","capabilities":{}}'))
const ACK_OK = resp(202, null, '')
const TOOLS_OK = resp(200, 'application/json', rpcResult(`{"tools":${VALID_TOOLS}}`))

function* discoverStage(): Generator<[string, Script, Resp]> {
  const base = { initialize: INIT_OK, ack: ACK_OK, toolsList: TOOLS_OK }
  for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
    const d = resp(status, ct, body)
    yield [`status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { discover: d, ...base }, d]
  }
  for (const status of REDIRECTS) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
    const d = resp(status, ct, body, { location: bi % 2 === 0 ? 'https://notes-mcp.example.com/mcp/v2' : 'https://mirror.example.com/mcp' })
    yield [`redirect=${status} ct=${JSON.stringify(ct)} body#${bi}`, { discover: d, ...base }, d]
  }
  for (const status of [...STATUSES, ...REDIRECTS]) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of DISCOVER_BODIES.entries()) {
    const d = resp(status, ct, body)
    yield [`discover-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { discover: d, ...base }, d]
  }
}

function* initializeStage(): Generator<[string, Script, Resp]> {
  const base = { discover: DISCOVER_FALLBACK, ack: ACK_OK, toolsList: TOOLS_OK }
  for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
    const i = resp(status, ct, body)
    yield [`status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { initialize: i, ...base }, i]
  }
  for (const status of [...STATUSES, ...REDIRECTS]) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of INITIALIZE_BODIES.entries()) {
    const i = resp(status, ct, body)
    yield [`initialize-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { initialize: i, ...base }, i]
  }
}

function* ackStage(): Generator<[string, Script, Resp]> {
  const base = { discover: DISCOVER_FALLBACK, initialize: INIT_OK, toolsList: TOOLS_OK }
  const statuses = [200, 201, 202, 204, 206, 299, ...REDIRECTS, 400, 401, 403, 404, 405, 406, 415, 429, 500, 502, 503]
  const bodies = ['', `Nope ${CANARY}`, rpcError('-32600'), rpcResult('{}')]
  for (const status of statuses) for (const challenge of [false, true]) for (const [bi, body] of bodies.entries()) {
    const a = resp(status, bi === 0 ? null : 'text/plain', body, { challenge })
    yield [`status=${status} challenge=${challenge} body#${bi}`, { ack: a, ...base }, a]
  }
}

function* toolsListStage(): Generator<[string, Script, Resp]> {
  const handshakes: [string, Omit<Script, 'toolsList'>][] = [
    ['modern-ok', { discover: DISCOVER_OK, initialize: INIT_OK, ack: ACK_OK }],
    ['legacy-ok', { discover: DISCOVER_FALLBACK, initialize: INIT_OK, ack: ACK_OK }],
    ['failed-not-gated', { discover: DISCOVER_FAILED, initialize: INIT_OK, ack: ACK_OK }],
  ]
  for (const [hn, hs] of handshakes) for (const challenge of [false, true]) {
    for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
      const tl = resp(status, ct, body, { challenge })
      yield [`${hn} challenge=${challenge} status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: tl }, tl]
    }
    for (const status of STATUSES) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of TOOLS_BODIES.entries()) {
      const tl = resp(status, ct, body, { challenge })
      yield [`${hn} challenge=${challenge} tools-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: tl }, tl]
    }
  }
}


// ---------------------------------------------------------------------------
// T86 stages.
// ---------------------------------------------------------------------------

const GATED = resp(401, null, '', { challenge: true })
/** T73b's three tools/list handshakes plus the two credential-gated ones (c1
 *  at the handshake layer: gated initialize, gated notifications/initialized). */
const T86_HANDSHAKES: [string, Omit<Script, 'toolsList'>][] = [
  ['modern-ok', { discover: DISCOVER_OK, initialize: INIT_OK, ack: ACK_OK }],
  ['legacy-ok', { discover: DISCOVER_FALLBACK, initialize: INIT_OK, ack: ACK_OK }],
  ['failed-not-gated', { discover: DISCOVER_FAILED, initialize: INIT_OK, ack: ACK_OK }],
  ['initialize-gated', { discover: DISCOVER_FALLBACK, initialize: GATED, ack: ACK_OK }],
  ['ack-gated', { discover: DISCOVER_FALLBACK, initialize: INIT_OK, ack: GATED }],
]

/** The T73b stages, each input served with 0.6.0's pinned tools/call reply. */
function* t73bStages(): Generator<[string, T86Script]> {
  for (const [name, stage] of [['discover', discoverStage], ['initialize', initializeStage], ['ack', ackStage], ['tools/list', toolsListStage]] as const) {
    for (const [id, script] of stage()) yield [`${name} ${id}`, { ...script, toolsCall: CALL_DEFAULT }]
  }
}

/** T73b's tools/list corpus behind the two gated handshakes it does not cover. */
function* gatedToolsListStage(): Generator<[string, T86Script]> {
  for (const [hn, hs] of T86_HANDSHAKES.slice(3)) for (const challenge of [false, true]) {
    for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
      yield [`${hn} challenge=${challenge} status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: resp(status, ct, body, { challenge }), toolsCall: CALL_DEFAULT }]
    }
    for (const status of STATUSES) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of TOOLS_BODIES.entries()) {
      yield [`${hn} challenge=${challenge} tools-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: resp(status, ct, body, { challenge }), toolsCall: CALL_DEFAULT }]
    }
  }
}

const tool = (name: string) => `{"name":${JSON.stringify(name)},"inputSchema":{"type":"object"}}`
const CLEAN = `${tool('search_notes')},${tool('get_note')}`
/** tools/list `result` values: exact names, near misses, and nextCursor shapes. */
const T86_RESULTS: string[] = [
  `{"tools":[${tool(RESERVED)}]}`,
  `{"tools":[${CLEAN},${tool(RESERVED)}]}`,
  `{"tools":[${tool(RESERVED)},${CLEAN}]}`,
  `{"tools":[${CLEAN},${tool(RESERVED)},${tool(RESERVED)}]}`,
  `{"tools":[${tool(RESERVED)}],"nextCursor":"p2"}`,
  `{"nextCursor":"p2","tools":[${CLEAN},${tool(RESERVED)}]}`,
  `{"tools":[{"name":"\\u005f_mcpcheckup_probe_nonexistent_tool__","inputSchema":{"type":"object"}}]}`,
  `{"tools":[{"name":"${RESERVED}"}]}`,
  `{"tools":[${CLEAN},${tool(`${RESERVED}x`)}]}`,
  `{"tools":[${tool(RESERVED.toUpperCase())}]}`,
  `{"tools":[${tool(` ${RESERVED}`)}]}`,
  `{"tools":[${tool(`${RESERVED} `)}]}`,
  `{"tools":[${tool(RESERVED.slice(0, -1))}]}`,
  `{"tools":[${tool(RESERVED.slice(1))}]}`,
  `{"tools":[{"name":"n","description":"${RESERVED}","inputSchema":{"type":"object"}}]}`,
  `{"tools":[{"name":"n","meta":{"name":"${RESERVED}"},"inputSchema":{"type":"object"}}]}`,
  `{"tools":["${RESERVED}"]}`,
  `{"tools":[{"name":["${RESERVED}"]}]}`,
  `{"tools":[[{"name":"${RESERVED}"}]]}`,
  `{"tools":[null,${tool('a')}]}`,
  `{"tools":[${CLEAN}],"nextCursor":"p2"}`,
  `{"tools":[${CLEAN}],"nextCursor":""}`,
  `{"tools":[${CLEAN}],"nextCursor":0}`,
  `{"tools":[${CLEAN}],"nextCursor":false}`,
  `{"tools":[${CLEAN}],"nextCursor":{}}`,
  `{"tools":[${CLEAN}],"nextCursor":[]}`,
  `{"tools":[${CLEAN}],"nextCursor":null}`,
  `{"tools":[${CLEAN}],"nextCursor":"p2","nextCursor":null}`,
  `{"tools":[${CLEAN}],"nextCursor":null,"nextCursor":"p2"}`,
  `{"tools":[],"nextCursor":"p2"}`,
  '{"tools":[]}',
  `{"tools":[{"name":"a","nextCursor":"p2","inputSchema":{"type":"object"}}]}`,
  `{"tools":[${CLEAN}],"NextCursor":"p2","next_cursor":"p2"}`,
]
const T86_BODIES: string[] = [
  ...T86_RESULTS.map(rpcResult),
  ...T86_RESULTS.map((r) => sse(rpcResult(r))),
  `{"jsonrpc":"2.0","id":1,"nextCursor":"p2","result":{"tools":[${CLEAN}]}}`,
  `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"${RESERVED}"}}`,
]

function* t86Stage(): Generator<[string, T86Script]> {
  for (const [hn, hs] of T86_HANDSHAKES) for (const challenge of [false, true]) for (const status of [200, 401, 500]) {
    for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of T86_BODIES.entries()) for (const [cn, call] of TOOLS_CALL_REPLIES) {
      yield [`${hn} challenge=${challenge} status=${status} ct=${JSON.stringify(ct)} body#${bi} call=${cn}`, { ...hs, toolsList: resp(status, ct, body, { challenge }), toolsCall: call }]
    }
  }
}

// ---------------------------------------------------------------------------
// Run.
// ---------------------------------------------------------------------------

console.log('T86 differential invariant：新实现 vs 冻结的 0.6.0 vs 独立 oracle（保留名 tools/call 发与不发）')

const stageSizes: [string, number][] = []
const started = Date.now()
for (const [name, inputs] of [['T73b stages', t73bStages()], ['gated handshakes × tools/list corpus', gatedToolsListStage()], ['T86 tools/list bodies × tools/call replies', t86Stage()]] as const) {
  const t0 = Date.now()
  let n = 0
  for (const [id, script] of inputs) {
    n++
    await checkInput(`${name} ${id}`, script)
  }
  stageSizes.push([name, n])
  console.log(`  stage ${name}: ${n} inputs, ${((Date.now() - t0) / 1000).toFixed(1)}s`)
}
const total = stageSizes.reduce((n, [, k]) => n + k, 0)
console.log(`  input set: ${stageSizes.map(([n, k]) => `${n}=${k}`).join(' + ')} = ${total}; ${((Date.now() - started) / 1000).toFixed(1)}s`)
console.log(`  oracle decisions: ${[...decisionCounts.entries()].sort().map(([k, v]) => `${k}=${v}`).join(' ')}`)
console.log(`  oracle branches: ${[...branchCounts.entries()].sort().map(([k, v]) => `${k}=${v}`).join(' ')}`)

await t(`the invariant holds for all ${total} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: every oracle branch is reached', () => {
  for (const branch of ['abort (handshake)', 'abort (tools/list)', 'abort (null tool entry)', 'c1 (handshake gated, no readable list)', 'c1 (tools/list gated)', 'a (collision)', 'b (nextCursor)', 'a (collision, handshake gated)', 'b (nextCursor, handshake gated)', 'send (handshake gated, readable, no collision)', 'c2 (tools/list failed)', 'send (complete, no collision)']) {
    assert.ok((branchCounts.get(branch) ?? 0) > 0, `${branch} never reached`)
  }
})

await t('the oracle agrees with itself on hand-derived anchor cases (guards the oracle, not the implementation)', () => {
  const s = (toolsList: Resp, hs: Omit<Script, 'toolsList'> = T86_HANDSHAKES[0]![1]): Script => ({ ...hs, toolsList })
  const json = (r: string) => resp(200, 'application/json', rpcResult(r))
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[{"name":"\\u005f_mcpcheckup_probe_nonexistent_tool__"}]}`))), { key: 'probe_tool_name_collision' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${tool(RESERVED)}],"nextCursor":"p2"}`))), { key: 'probe_tool_name_collision' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${CLEAN}],"nextCursor":""}`))), { key: 'probe_tool_name_unverifiable' })
  assert.equal(oracleDecision(s(json(`{"tools":[${CLEAN}],"nextCursor":null}`))), 'send')
  assert.equal(oracleDecision(s(json(`{"tools":[${tool(`${RESERVED}x`)}]}`))), 'send')
  assert.deepStrictEqual(oracleDecision(s(resp(502, 'text/html', '<p>x</p>'))), { key: 'probe_tool_name_unverifiable' })
  assert.equal(oracleDecision(s(resp(401, 'application/json', rpcResult(`{"tools":[${tool(RESERVED)}]}`), { challenge: true }))), 'send')
  assert.deepStrictEqual(oracleDecision(s(resp(401, 'application/json', rpcResult(`{"tools":[${CLEAN}]}`), { challenge: true }), T86_HANDSHAKES[2]![1])), { key: 'probe_tool_name_unverifiable' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${tool(RESERVED)}]}`), T86_HANDSHAKES[3]![1])), { key: 'probe_tool_name_collision' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${CLEAN}],"nextCursor":"p2"}`), T86_HANDSHAKES[4]![1])), { key: 'probe_tool_name_unverifiable' })
  assert.equal(oracleDecision(s(json(`{"tools":[${CLEAN}]}`), T86_HANDSHAKES[3]![1])), 'send')
  assert.equal(oracleDecision(s(resp(500, 'text/plain', 'x'), T86_HANDSHAKES[3]![1])), 'send')
  assert.equal(oracleDecision(s(resp(429, null, ''))), 'abort')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
