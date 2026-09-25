/**
 * T73b differential invariant test — the primary evidence that recording a
 * bounded reason on every FAILED discovery_handshake / protocol_revision /
 * tools_list / toolset_fingerprint / schema_fingerprint changed NO verdict.
 *
 * Three parties, deliberately not sharing code:
 *
 *   1. The implementation: performHandshake / performToolsList (./protocol.ts)
 *      and compute*Fingerprint (./fingerprint.ts) called directly, plus
 *      runProbe (./probe.ts) end to end on the same scripted server.
 *   2. FROZEN_PRE_T73b — a verbatim copy, from `git show 70618ee:…`, of
 *      performHandshake / performLegacyHandshake / performToolsList and every
 *      protocol.ts piece they use (the JSON-RPC parser included), both
 *      compute*Fingerprint, and probe.ts's status expressions for
 *      discovery_handshake / protocol_revision / tools_list with their branch
 *      order and credential rules. Bodies unchanged; identifiers prefixed
 *      `frozen`, comments dropped. DO NOT "update" this copy to match a later
 *      implementation — its only job is to be the pre-T73b behaviour.
 *      It still imports what T73b does not touch: wire.ts sendRequest,
 *      auth.ts classifyCredentialChallenge, and @mcpcheckup/canonicalizer's
 *      digest / projectToolset / projectSchemas (`git diff 70618ee` on those
 *      files is empty for T73b). A later change to one of them must copy the
 *      old version in here first, or this stops being a differential.
 *   3. ORACLE — its own SSE line scanner, its own JSON-RPC acceptance, its own
 *      canonical-form validity rules, and the T73b key rules as ordered
 *      branches. It imports nothing from ./protocol.ts, ./fingerprint.ts or
 *      ./probe.ts; it reads checks.json's revision_matrix as data.
 *
 * Input set: the T73 corpus (13 statuses × 12 content-types × 63 bodies =
 * 9,828) opened one stage at a time with the other stages pinned — a full
 * cross of four stages is infeasible:
 *   discover     × corpus, + 3xx statuses × (content-types × bodies), + discover-specific bodies;
 *                  legacy stages pinned to success
 *   initialize   × corpus, + initialize-specific bodies; discover pinned to a 404 non-JSON reply
 *                  (⇒ fallback), ack pinned to 202
 *   ack          statuses × {valid WWW-Authenticate challenge, none} × bodies
 *   tools/list   × (corpus + tools-specific bodies) × handshake {modern ok, legacy ok, failed and
 *                  not gated} × challenge {none, valid}
 *   fingerprint  constructed tool arrays, computed directly and served over tools/list
 *
 * Asserted for every input:
 *   (a) each of the five checks' assertion_status from runProbe is
 *       bit-identical to FROZEN's (and the ORACLE predicts the same status)
 *   (b) the direct HandshakeResult / ToolsListResult / FingerprintVerdict
 *       deep-equal FROZEN's apart from the new field (failure / reason), and
 *       the new field is absent on success
 *   (c) FAILED ⇒ the reason deep-equals the ORACLE's {key, params?};
 *       VERIFIED ⇒ reason null; UNVERIFIED (credential gate, abort cascade)
 *       ⇒ its reason is not a T73b key. ("Null exactly when not FAILED" is
 *       read this way because UNVERIFIED must always carry a reason —
 *       CLAUDE.md product principle 2.)
 *   (d) params bounded: only the allowed names, `status` present exactly on
 *       the seven status keys and equal to that response's HTTP status,
 *       jsonrpc_error_code a safe integer (never -0) and only on the four
 *       keys that allow it, and never an empty params object
 *   (e) every emitted reason renders in en and zh, no banned word, and no
 *       rendered string contains the canary or any 8-character window of the
 *       stage's input body. Named exemptions, all fixed protocol tokens the
 *       approved sentences share with a body by construction: windows lying
 *       inside the two field names the sentences name (supportedVersions,
 *       protocolVersion) and inside the SSE framing line `event: message`
 *       (vs. the sentences' "JSON-RPC message"). Third-party text positions
 *       carry the canary instead, and the canary is never exempt.
 */
import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { digest, projectToolset, projectSchemas } from '@mcpcheckup/canonicalizer'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { performHandshake, performToolsList } from './protocol.ts'
import type { HandshakeResult, ToolsListResult } from './protocol.ts'
import { computeToolsetFingerprint, computeSchemaFingerprint } from './fingerprint.ts'
import { runProbe } from './probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { REASON_MESSAGES } from './reason-messages.ts'
import { sendRequest, createProbeContext } from './wire.ts'
import type { ProbeContext } from './wire.ts'
import { classifyCredentialChallenge } from './auth.ts'
import type { FetchLike, ProbeBudget } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// 2. FROZEN_PRE_T73b — verbatim from 70618ee: packages/checks/src/protocol.ts
//    (CLIENT_INFO … performToolsList), fingerprint.ts (compute*Fingerprint),
//    probe.ts (the discovery_handshake / protocol_revision / tools_list
//    branches of runProbe, restated as a pure function of the two results).
// ---------------------------------------------------------------------------

const FROZEN_CLIENT_INFO = { name: 'mcp-checkup-prober', version: '0.1.0' }
const FROZEN_MODERN_PROBE_VERSION = '2026-07-28'
const FROZEN_LEGACY_PROBE_VERSION = '2025-06-18'

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

function frozenJsonRpcCandidates(bodyText: string, contentType?: string | null): string[] {
  return frozenIsSseContentType(contentType) ? frozenExtractSseDataPayloads(bodyText) : [bodyText]
}

function frozenParseJsonRpcBody(bodyText: string, contentType?: string | null): FrozenParsedJsonRpc {
  for (const candidate of frozenJsonRpcCandidates(bodyText, contentType)) {
    const parsed = frozenParseJsonRpcText(candidate)
    if (parsed.isJsonRpc) return parsed
  }
  return { isJsonRpc: false }
}

const FROZEN_RECOGNIZED_MODERN_ERROR_CODES: ReadonlySet<number> = new Set([-32020, -32021, -32022])

function frozenModernMeta(protocolVersion: string) {
  return {
    'io.modelcontextprotocol/protocolVersion': protocolVersion,
    'io.modelcontextprotocol/clientInfo': FROZEN_CLIENT_INFO,
    'io.modelcontextprotocol/clientCapabilities': {},
  }
}

function frozenModernHeaders(protocolVersion: string, mcpMethod: string, mcpName?: string): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': protocolVersion,
    'mcp-method': mcpMethod,
    ...(mcpName ? { 'mcp-name': mcpName } : {}),
  }
}

function frozenLegacyHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  }
}

async function frozenSendModern(
  fetchImpl: FetchLike,
  endpoint: string,
  budget: ProbeBudget,
  ctx: ProbeContext,
  method: string,
  id: unknown,
  extraParams: Record<string, unknown>,
  protocolVersion: string,
  mcpName?: string,
) {
  return sendRequest(
    fetchImpl,
    endpoint,
    {
      method: 'POST',
      headers: frozenModernHeaders(protocolVersion, method, mcpName),
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params: { ...extraParams, _meta: frozenModernMeta(protocolVersion) } }),
    },
    budget,
    ctx,
  )
}

interface FrozenHandshakeResult {
  mode: 'modern' | 'legacy'
  handshakeOk: boolean
  protocolVersionDeclared: string | null
  sessionId?: string
  currentEndpoint: string
  credentialChallenge?: { scheme: string }
}

function frozenCredentialChallengeFrom(status: number, headers: Headers): { credentialChallenge: { scheme: string } } | Record<string, never> {
  const challenge = classifyCredentialChallenge(status, headers)
  return challenge ? { credentialChallenge: challenge } : {}
}

async function frozenPerformHandshake(opts: {
  fetchImpl: FetchLike
  endpoint: string
  budget: ProbeBudget
  ctx: ProbeContext
  newId: () => string
}): Promise<FrozenHandshakeResult> {
  const { fetchImpl, endpoint, budget, ctx, newId } = opts

  const discover = await frozenSendModern(fetchImpl, endpoint, budget, ctx, 'server/discover', newId(), {}, FROZEN_MODERN_PROBE_VERSION)

  if (discover.status === 200) {
    const parsed = frozenParseJsonRpcBody(discover.bodyText, discover.headers.get('content-type'))
    const result = parsed.isJsonRpc ? (parsed.result as Record<string, unknown> | undefined) : undefined
    const supportedVersions = result?.supportedVersions
    const ok = parsed.isJsonRpc && Array.isArray(supportedVersions) && typeof supportedVersions[0] === 'string'
    return {
      mode: 'modern',
      handshakeOk: !!ok,
      protocolVersionDeclared: ok ? (supportedVersions as string[])[0]! : null,
      currentEndpoint: discover.finalUrl,
    }
  }

  if (discover.status >= 400 && discover.status < 500) {
    const parsed = frozenParseJsonRpcBody(discover.bodyText, discover.headers.get('content-type'))
    if (parsed.isJsonRpc && parsed.error && FROZEN_RECOGNIZED_MODERN_ERROR_CODES.has(parsed.error.code)) {
      return { mode: 'modern', handshakeOk: false, protocolVersionDeclared: null, currentEndpoint: discover.finalUrl }
    }
    return frozenPerformLegacyHandshake(fetchImpl, discover.finalUrl, budget, ctx, newId)
  }

  return { mode: 'modern', handshakeOk: false, protocolVersionDeclared: null, currentEndpoint: discover.finalUrl }
}

async function frozenPerformLegacyHandshake(
  fetchImpl: FetchLike,
  endpoint: string,
  budget: ProbeBudget,
  ctx: ProbeContext,
  newId: () => string,
): Promise<FrozenHandshakeResult> {
  const initRes = await sendRequest(
    fetchImpl,
    endpoint,
    {
      method: 'POST',
      headers: frozenLegacyHeaders(),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: newId(),
        method: 'initialize',
        params: { protocolVersion: FROZEN_LEGACY_PROBE_VERSION, capabilities: {}, clientInfo: FROZEN_CLIENT_INFO },
      }),
    },
    budget,
    ctx,
  )

  const parsed = frozenParseJsonRpcBody(initRes.bodyText, initRes.headers.get('content-type'))
  const result = parsed.isJsonRpc ? (parsed.result as Record<string, unknown> | undefined) : undefined
  const protocolVersion = result?.protocolVersion
  const sessionId = initRes.headers.get('mcp-session-id') ?? undefined

  if (initRes.status !== 200 || typeof protocolVersion !== 'string') {
    return {
      mode: 'legacy',
      handshakeOk: false,
      protocolVersionDeclared: null,
      currentEndpoint: initRes.finalUrl,
      ...frozenCredentialChallengeFrom(initRes.status, initRes.headers),
    }
  }

  const ackRes = await sendRequest(
    fetchImpl,
    initRes.finalUrl,
    {
      method: 'POST',
      headers: frozenLegacyHeaders(sessionId ? { 'mcp-session-id': sessionId } : undefined),
      body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    },
    budget,
    ctx,
  )
  if (ackRes.status < 200 || ackRes.status >= 300) {
    return {
      mode: 'legacy',
      handshakeOk: false,
      protocolVersionDeclared: protocolVersion,
      ...(sessionId ? { sessionId } : {}),
      currentEndpoint: ackRes.finalUrl,
      ...frozenCredentialChallengeFrom(ackRes.status, ackRes.headers),
    }
  }

  return { mode: 'legacy', handshakeOk: true, protocolVersionDeclared: protocolVersion, ...(sessionId ? { sessionId } : {}), currentEndpoint: ackRes.finalUrl }
}

interface FrozenToolsListResult {
  ok: boolean
  tools: unknown[] | null
  currentEndpoint: string
  credentialChallenge?: { scheme: string }
}

async function frozenPerformToolsList(opts: {
  fetchImpl: FetchLike
  budget: ProbeBudget
  ctx: ProbeContext
  newId: () => string
  handshake: FrozenHandshakeResult
}): Promise<FrozenToolsListResult> {
  const { fetchImpl, budget, ctx, newId, handshake } = opts
  const endpoint = handshake.currentEndpoint

  const res =
    handshake.mode === 'modern'
      ? await frozenSendModern(fetchImpl, endpoint, budget, ctx, 'tools/list', newId(), {}, handshake.protocolVersionDeclared ?? FROZEN_MODERN_PROBE_VERSION)
      : await sendRequest(
          fetchImpl,
          endpoint,
          {
            method: 'POST',
            headers: frozenLegacyHeaders({
              'mcp-protocol-version': handshake.protocolVersionDeclared ?? FROZEN_LEGACY_PROBE_VERSION,
              ...(handshake.sessionId ? { 'mcp-session-id': handshake.sessionId } : {}),
            }),
            body: JSON.stringify({ jsonrpc: '2.0', id: newId(), method: 'tools/list', params: {} }),
          },
          budget,
          ctx,
        )

  const challenge = classifyCredentialChallenge(res.status, res.headers)
  const parsed = frozenParseJsonRpcBody(res.bodyText, res.headers.get('content-type'))
  const result = parsed.isJsonRpc ? (parsed.result as Record<string, unknown> | undefined) : undefined
  const tools = result?.tools
  const ok = Array.isArray(tools) && challenge === null
  return {
    ok,
    tools: ok ? (tools as unknown[]) : null,
    currentEndpoint: res.finalUrl,
    ...(challenge ? { credentialChallenge: challenge } : {}),
  }
}

type FrozenFingerprintVerdict = { status: 'VERIFIED'; fingerprint: string } | { status: 'FAILED'; reason: string }

async function frozenComputeToolsetFingerprint(tools: unknown[]): Promise<FrozenFingerprintVerdict> {
  try {
    return { status: 'VERIFIED', fingerprint: await digest(projectToolset(tools)) }
  } catch (e) {
    return { status: 'FAILED', reason: e instanceof Error ? e.message : String(e) }
  }
}

async function frozenComputeSchemaFingerprint(tools: unknown[]): Promise<FrozenFingerprintVerdict> {
  try {
    return { status: 'VERIFIED', fingerprint: await digest(projectSchemas(tools)) }
  } catch (e) {
    return { status: 'FAILED', reason: e instanceof Error ? e.message : String(e) }
  }
}

type Status = Assertion['assertion_status']
type Five = Record<(typeof FIVE)[number], Status>
const FIVE = ['discovery_handshake', 'protocol_revision', 'tools_list', 'toolset_fingerprint', 'schema_fingerprint'] as const

/** probe.ts @ 70618ee, the branch skeleton of runProbe's try block for these
 *  five checks. A throw inside the handshake cascades every check to
 *  UNVERIFIED; a throw inside tools/list leaves the two handshake verdicts
 *  standing (they were asserted first). */
async function frozenStatuses(o: FrozenDirect, revisionMatrix: string[]): Promise<Five> {
  const s: Five = { discovery_handshake: 'UNVERIFIED', protocol_revision: 'UNVERIFIED', tools_list: 'UNVERIFIED', toolset_fingerprint: 'UNVERIFIED', schema_fingerprint: 'UNVERIFIED' }
  if (o.handshake === undefined) return s
  const handshake = o.handshake
  const handshakeCredentialGated = !handshake.handshakeOk && handshake.credentialChallenge !== undefined
  if (handshakeCredentialGated) {
    s.discovery_handshake = 'UNVERIFIED'
    s.protocol_revision = 'UNVERIFIED'
  } else {
    s.discovery_handshake = handshake.handshakeOk ? 'VERIFIED' : 'FAILED'
    if (handshake.protocolVersionDeclared && revisionMatrix.includes(handshake.protocolVersionDeclared)) {
      s.protocol_revision = 'VERIFIED'
    } else {
      s.protocol_revision = 'FAILED'
    }
  }
  if (o.toolsList === undefined) return s
  const toolsList = o.toolsList
  if (handshakeCredentialGated) {
    s.tools_list = 'UNVERIFIED'
  } else if (handshake.handshakeOk && !toolsList.ok && toolsList.credentialChallenge !== undefined) {
    s.tools_list = 'UNVERIFIED'
  } else if (toolsList.ok) {
    s.tools_list = 'VERIFIED'
    s.toolset_fingerprint = (await frozenComputeToolsetFingerprint(toolsList.tools!)).status
    s.schema_fingerprint = (await frozenComputeSchemaFingerprint(toolsList.tools!)).status
  } else {
    s.tools_list = 'FAILED'
  }
  return s
}

// ---------------------------------------------------------------------------
// The scripted server both implementations talk to.
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

const TOOLS_CALL_REPLY = resp(200, 'application/json', '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool"}}')
const NOT_FOUND = resp(404, 'text/plain', 'Not Found')

function fetchFor(s: Script): FetchLike {
  return async (_input, init) => {
    const method = typeof init?.body === 'string' ? (JSON.parse(init.body) as { method?: unknown }).method : undefined
    const r =
      method === 'server/discover' ? s.discover
      : method === 'initialize' ? s.initialize
      : method === 'notifications/initialized' ? s.ack
      : method === 'tools/list' ? s.toolsList
      : method === 'tools/call' ? TOOLS_CALL_REPLY
      : NOT_FOUND
    return toResponse(r)
  }
}

function thrownLabel(e: unknown): string {
  return e instanceof Error ? `${e.name}:${String((e as { code?: unknown }).code ?? '')}` : String(e)
}

interface ImplDirect { handshake?: HandshakeResult; toolsList?: ToolsListResult; thrown?: string }
interface FrozenDirect { handshake?: FrozenHandshakeResult; toolsList?: FrozenToolsListResult; thrown?: string }

async function implDirect(s: Script): Promise<ImplDirect> {
  const fetchImpl = fetchFor(s)
  const ctx = createProbeContext(Date.now())
  let seq = 0
  const newId = () => `id-${++seq}`
  const out: ImplDirect = {}
  try {
    out.handshake = await performHandshake({ fetchImpl, endpoint: ENDPOINT, budget: DEFAULT_PROBE_BUDGET, ctx, newId })
    out.toolsList = await performToolsList({ fetchImpl, budget: DEFAULT_PROBE_BUDGET, ctx, newId, handshake: out.handshake })
  } catch (e) {
    out.thrown = thrownLabel(e)
  }
  return out
}

async function frozenDirect(s: Script): Promise<FrozenDirect> {
  const fetchImpl = fetchFor(s)
  const ctx = createProbeContext(Date.now())
  let seq = 0
  const newId = () => `id-${++seq}`
  const out: FrozenDirect = {}
  try {
    out.handshake = await frozenPerformHandshake({ fetchImpl, endpoint: ENDPOINT, budget: DEFAULT_PROBE_BUDGET, ctx, newId })
    out.toolsList = await frozenPerformToolsList({ fetchImpl, budget: DEFAULT_PROBE_BUDGET, ctx, newId, handshake: out.handshake })
  } catch (e) {
    out.thrown = thrownLabel(e)
  }
  return out
}

async function probeRun(s: Script): Promise<Record<(typeof FIVE)[number], Assertion>> {
  let seq = 0
  const result = await runProbe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: fetchFor(s),
    budget: DEFAULT_PROBE_BUDGET,
    now: () => '2026-09-22T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  })
  const pick = (id: string) => result.assertions.find((a) => a.check_id === id)!
  return {
    discovery_handshake: pick('discovery_handshake'),
    protocol_revision: pick('protocol_revision'),
    tools_list: pick('tools_list'),
    toolset_fingerprint: pick('toolset_fingerprint'),
    schema_fingerprint: pick('schema_fingerprint'),
  }
}

// ---------------------------------------------------------------------------
// 3. ORACLE — independent. Nothing below is imported from or copied out of
//    protocol.ts / fingerprint.ts / probe.ts.
// ---------------------------------------------------------------------------

type OReason = { key: string; params?: Record<string, number> }
const K = (key: string, params: Record<string, number> = {}): OReason => (Object.keys(params).length > 0 ? { key, params } : { key })

const MATRIX: string[] = (
  JSON.parse(readFileSync(new URL('../checks.json', import.meta.url), 'utf8')) as { checks: { check_id: string; revision_matrix?: string[] }[] }
).checks.find((c) => c.check_id === 'protocol_revision')!.revision_matrix!

/** Line scanner: a line ends at LF, one CR right before it belongs to the
 *  terminator; a blank line ends an event; only `data:` lines count, one
 *  following space dropped; an event whose data is empty yields nothing. */
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

/** A UTF-16 code unit sequence with an unpaired surrogate has no UTF-8 form. */
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = i + 1 < s.length ? s.charCodeAt(i + 1) : -1
      if (n >= 0xdc00 && n <= 0xdfff) { i++; continue }
      return true
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true
  }
  return false
}

/** Deeper than this is treated as "cannot be put into canonical form" — the
 *  implementation recurses and runs out of stack somewhere above it. That
 *  threshold belongs to the JS engine, not to a rule, so the input set only
 *  uses depths ≤ 50 or ≥ 100,000 and never probes the gap. */
const ORACLE_TOO_DEEP = 10_000

/** Iterative: plain JSON values only — null, booleans, finite numbers,
 *  strings without a lone surrogate, arrays, and objects whose keys have no
 *  lone surrogate and stay distinct after NFC. */
function oracleCanonical(root: unknown): boolean {
  const stack: [unknown, number][] = [[root, 0]]
  while (stack.length > 0) {
    const [v, depth] = stack.pop()!
    if (depth > ORACLE_TOO_DEEP) return false
    if (v === null || typeof v === 'boolean') continue
    if (typeof v === 'number') { if (!Number.isFinite(v)) return false; continue }
    if (typeof v === 'string') { if (hasLoneSurrogate(v)) return false; continue }
    if (Array.isArray(v)) { for (const x of v) stack.push([x, depth + 1]); continue }
    if (typeof v !== 'object') return false
    const seen = new Set<string>()
    for (const k of Object.keys(v)) {
      if (hasLoneSurrogate(k)) return false
      const n = k.normalize('NFC')
      if (seen.has(n)) return false
      seen.add(n)
      stack.push([(v as Record<string, unknown>)[k], depth + 1])
    }
  }
  return true
}

const hasStringName = (tool: unknown) => tool !== null && typeof tool === 'object' && typeof (tool as { name?: unknown }).name === 'string'
const nameOf = (tool: unknown) => (tool as { name: string }).name

/** toolset: every name first, then the sorted names are serialized. */
function oracleToolset(tools: unknown[]): OReason | null {
  if (!tools.every(hasStringName)) return K('fingerprint_tool_missing_name')
  if (tools.some((tool) => hasLoneSurrogate(nameOf(tool)))) return K('fingerprint_canonicalize_failed')
  return null
}

/** schema: tool by tool — its name, then (when present) its inputSchema as a
 *  sort key — then the {name, inputSchema} pairs are serialized, where a
 *  missing inputSchema or an unencodable name fails. */
function oracleSchema(tools: unknown[]): OReason | null {
  for (const tool of tools) {
    if (!hasStringName(tool)) return K('fingerprint_tool_missing_name')
    const schema = (tool as { inputSchema?: unknown }).inputSchema
    if (schema !== undefined && !oracleCanonical(schema)) return K('fingerprint_canonicalize_failed')
  }
  if (tools.some((tool) => (tool as { inputSchema?: unknown }).inputSchema === undefined || hasLoneSurrogate(nameOf(tool)))) return K('fingerprint_canonicalize_failed')
  return null
}

interface OView { status: Five; reason: Record<(typeof FIVE)[number], OReason | null> }

function oracle(s: Script): OView {
  const status: Five = { discovery_handshake: 'UNVERIFIED', protocol_revision: 'UNVERIFIED', tools_list: 'UNVERIFIED', toolset_fingerprint: 'UNVERIFIED', schema_fingerprint: 'UNVERIFIED' }
  const reason: OView['reason'] = { discovery_handshake: null, protocol_revision: null, tools_list: null, toolset_fingerprint: null, schema_fingerprint: null }
  const hs = oracleHandshake(s)
  if (hs.aborted) return { status, reason }
  if (!hs.gated) {
    if (hs.ok) status.discovery_handshake = 'VERIFIED'
    else { status.discovery_handshake = 'FAILED'; reason.discovery_handshake = hs.fail! }
    if (hs.declared && MATRIX.includes(hs.declared)) status.protocol_revision = 'VERIFIED'
    else { status.protocol_revision = 'FAILED'; reason.protocol_revision = K(hs.declared ? 'protocol_revision_unknown' : 'protocol_revision_missing') }
  }
  const tl = s.toolsList
  if (rateLimited(tl) || hs.gated) return { status, reason }
  const challenge = challenged(tl)
  const m = oracleRead(tl)
  const tools = oracleField(m, 'tools')
  if (hs.ok && challenge) return { status, reason }
  if (Array.isArray(tools) && !challenge) {
    status.tools_list = 'VERIFIED'
    const toolset = oracleToolset(tools)
    const schema = oracleSchema(tools)
    status.toolset_fingerprint = toolset ? 'FAILED' : 'VERIFIED'
    status.schema_fingerprint = schema ? 'FAILED' : 'VERIFIED'
    reason.toolset_fingerprint = toolset
    reason.schema_fingerprint = schema
    return { status, reason }
  }
  status.tools_list = 'FAILED'
  reason.tools_list = challenge
    ? K('tools_list_challenge_after_failed_handshake')
    : m === null ? K('tools_list_not_jsonrpc', { status: tl.status })
    : m.kind === 'error' ? K('tools_list_jsonrpc_error', { status: tl.status, ...oracleCode(m) })
    : K('tools_list_not_array', { status: tl.status })
  return { status, reason }
}

// ---------------------------------------------------------------------------
// (d) / (e) tables.
// ---------------------------------------------------------------------------

const T73B_KEYS = [
  'handshake_discover_not_jsonrpc', 'handshake_discover_jsonrpc_error', 'handshake_discover_no_supported_versions',
  'handshake_discover_rejected', 'handshake_discover_http_error', 'handshake_initialize_http_error',
  'handshake_initialize_not_jsonrpc', 'handshake_initialize_jsonrpc_error', 'handshake_initialize_no_protocol_version',
  'handshake_ack_http_error', 'protocol_revision_missing', 'protocol_revision_unknown',
  'tools_list_challenge_after_failed_handshake', 'tools_list_not_jsonrpc', 'tools_list_jsonrpc_error', 'tools_list_not_array',
  'fingerprint_tool_missing_name', 'fingerprint_canonicalize_failed',
]
const STATUS_KEYS = new Set([
  'handshake_discover_rejected', 'handshake_discover_http_error', 'handshake_initialize_http_error', 'handshake_ack_http_error',
  'tools_list_not_jsonrpc', 'tools_list_jsonrpc_error', 'tools_list_not_array',
])
const CODE_KEYS = new Set(['handshake_discover_jsonrpc_error', 'handshake_initialize_jsonrpc_error', 'tools_list_jsonrpc_error', 'handshake_discover_rejected'])

/** Which response a key's `status` param must be the HTTP status of. */
function statusSource(key: string, s: Script): Resp {
  if (key.startsWith('handshake_discover_')) return s.discover
  if (key.startsWith('handshake_initialize_')) return s.initialize
  if (key.startsWith('handshake_ack_')) return s.ack
  return s.toolsList
}

function paramProblems(key: string, params: Record<string, string | number> | undefined, s: Script): string[] {
  const out: string[] = []
  const names = Object.keys(params ?? {})
  if (params !== undefined && names.length === 0) out.push('empty params object')
  for (const n of names) if (n !== 'status' && n !== 'jsonrpc_error_code') out.push(`param ${n} not allowed`)
  if (STATUS_KEYS.has(key) !== (params?.status !== undefined)) out.push(`status presence wrong (${JSON.stringify(params)})`)
  if (params?.status !== undefined && params.status !== statusSource(key, s).status) out.push(`status ${String(params.status)} ≠ HTTP ${statusSource(key, s).status}`)
  const code = params?.jsonrpc_error_code
  if (code !== undefined) {
    if (!CODE_KEYS.has(key)) out.push('jsonrpc_error_code on a key that does not allow it')
    if (!Number.isSafeInteger(code) || Object.is(code, -0)) out.push(`jsonrpc_error_code ${String(code)} not a safe integer`)
  }
  if (key === 'handshake_discover_rejected' && code === undefined) out.push('discover_rejected without jsonrpc_error_code')
  return out
}

const BANNED = ['certified', 'secure', 'safe', 'trusted', '评分', '健康度']
const WINDOW = 8
const NAMED_FIELDS = ['supportedVersions', 'protocolVersion', 'event: message']
const windowCache = new Map<string, Set<string>>()
function bodyWindows(body: string): Set<string> {
  let set = windowCache.get(body)
  if (set) return set
  set = new Set()
  for (let i = 0; i + WINDOW <= body.length; i++) {
    const w = body.slice(i, i + WINDOW)
    if (!NAMED_FIELDS.some((f) => f.includes(w))) set.add(w)
  }
  windowCache.set(body, set)
  return set
}
const renderCache = new Map<string, [string, string] | string>()
function rendered(reason: { key: string; params?: Record<string, string | number> }): [string, string] | string {
  const id = JSON.stringify(reason)
  let r = renderCache.get(id)
  if (r !== undefined) return r
  try {
    const entry = REASON_MESSAGES[reason.key]
    if (!entry) throw new Error(`no REASON_MESSAGES entry for ${reason.key}`)
    r = [entry.en(reason.params), entry.zh(reason.params)]
  } catch (e) {
    r = `render threw: ${(e as Error).message}`
  }
  renderCache.set(id, r)
  return r
}

function renderProblems(reason: { key: string; params?: Record<string, string | number> }, body: string): string[] {
  const r = rendered(reason)
  if (typeof r === 'string') return [r]
  const out: string[] = []
  const windows = bodyWindows(body)
  for (const text of r) {
    if (text.length === 0) out.push('empty')
    const lower = text.toLowerCase()
    for (const w of BANNED) if (lower.includes(w)) out.push(`banned word ${w}`)
    if (text.includes(CANARY)) out.push('canary echoed')
    for (let i = 0; i + WINDOW <= text.length; i++) {
      const w = text.slice(i, i + WINDOW)
      if (windows.has(w)) { out.push(`body window ${JSON.stringify(w)} echoed`); break }
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// The per-input check.
// ---------------------------------------------------------------------------

const failures: string[] = []
const byInvariant = { a: 0, b: 0, c: 0, d: 0, e: 0 }
const keyCounts = new Map<string, number>()
const statusCounts = new Map<string, number>()
let aborted = 0

function violation(inv: keyof typeof byInvariant, id: string, what: string) {
  byInvariant[inv]++
  if (failures.length < 200) failures.push(`(${inv}) ${id}: ${what}`)
}

function withoutField(o: unknown, field: string): unknown {
  if (o === undefined || o === null || typeof o !== 'object') return o
  const { [field]: _dropped, ...rest } = o as Record<string, unknown>
  return rest
}

/** Iterative structural equality for JSON-parsed values (Object.is on leaves). */
function sameJson(a: unknown, b: unknown): boolean {
  const stack: [unknown, unknown][] = [[a, b]]
  while (stack.length > 0) {
    const [x, y] = stack.pop()!
    if (x === null || y === null || typeof x !== 'object' || typeof y !== 'object') {
      if (!Object.is(x, y)) return false
      continue
    }
    if (Array.isArray(x) !== Array.isArray(y)) return false
    const kx = Object.keys(x), ky = Object.keys(y)
    if (kx.length !== ky.length) return false
    for (const k of kx) {
      if (!Object.prototype.hasOwnProperty.call(y, k)) return false
      stack.push([(x as Record<string, unknown>)[k], (y as Record<string, unknown>)[k]])
    }
  }
  return true
}

/** T86b (suite 0.8.0) widened credentialChallenge from { scheme } to
 *  { scheme, status, wwwAuthenticate } for auth_metadata. The two added
 *  fields are pinned here (status 401, the header value exactly as received)
 *  and then dropped, so (b) still compares everything T73b could change. */
function schemeOnly<T>(r: T): T {
  const c = (r as { credentialChallenge?: { scheme: string; status: number; wwwAuthenticate: string } } | undefined)?.credentialChallenge
  if (c === undefined) return r
  assert.deepStrictEqual(Object.keys(c), ['scheme', 'status', 'wwwAuthenticate'], 'T86b credentialChallenge fields')
  assert.equal(c.status, 401, 'a credential gate is always a 401')
  assert.equal(c.wwwAuthenticate, VALID_CHALLENGE, 'the header value exactly as received')
  return { ...r, credentialChallenge: { scheme: c.scheme } }
}

async function checkInput(id: string, s: Script, varied: Resp): Promise<void> {
  const [impl, frozen] = [await implDirect(s), await frozenDirect(s)]

  // (b) direct results, minus the new field (and T86b's two credentialChallenge fields, see schemeOnly).
  try {
    assert.equal(impl.thrown, frozen.thrown, 'thrown')
    assert.deepStrictEqual(withoutField(schemeOnly(impl.handshake), 'failure'), withoutField(frozen.handshake, 'failure'))
    // tools compared iteratively: assert.deepStrictEqual recurses and runs out
    // of stack on the 100,000-deep tool arrays of the fingerprint stage.
    assert.deepStrictEqual(withoutField(withoutField(schemeOnly(impl.toolsList), 'failure'), 'tools'), withoutField(withoutField(frozen.toolsList, 'failure'), 'tools'))
    assert.ok(sameJson(impl.toolsList?.tools, frozen.toolsList?.tools), 'tools differ')
    if (impl.handshake?.handshakeOk) assert.ok(!('failure' in impl.handshake), 'failure on an ok handshake')
    if (impl.handshake && !impl.handshake.handshakeOk) assert.ok(impl.handshake.failure, 'no failure on a failed handshake')
    if (impl.toolsList?.ok) assert.ok(!('failure' in impl.toolsList), 'failure on an ok tools/list')
  } catch (e) {
    violation('b', id, (e as Error).message.split('\n')[0]!)
  }
  if (impl.thrown !== undefined) aborted++

  const probe = await probeRun(s)
  const frozenStatus = await frozenStatuses(frozen, MATRIX)
  const want = oracle(s)

  for (const check of FIVE) {
    const a = probe[check]
    statusCounts.set(`${check}:${a.assertion_status}`, (statusCounts.get(`${check}:${a.assertion_status}`) ?? 0) + 1)
    // (a)
    if (a.assertion_status !== frozenStatus[check]) violation('a', id, `${check} new=${a.assertion_status} pre-T73b=${frozenStatus[check]}`)
    if (want.status[check] !== frozenStatus[check]) violation('a', id, `${check} oracle=${want.status[check]} pre-T73b=${frozenStatus[check]}`)
    // (c)
    if (a.assertion_status === 'VERIFIED' && a.reason !== null) violation('c', id, `${check} VERIFIED carries ${JSON.stringify(a.reason)}`)
    if (a.assertion_status === 'UNVERIFIED' && (a.reason === null || T73B_KEYS.includes(a.reason.key))) violation('c', id, `${check} UNVERIFIED carries ${JSON.stringify(a.reason)}`)
    if (a.assertion_status !== 'FAILED') continue
    try {
      assert.ok(a.reason !== null, 'FAILED without a reason')
      assert.deepStrictEqual(a.reason, want.reason[check])
    } catch (e) {
      violation('c', id, `${check} got ${JSON.stringify(a.reason)} want ${JSON.stringify(want.reason[check])}`)
      continue
    }
    const reason = a.reason!
    keyCounts.set(reason.key, (keyCounts.get(reason.key) ?? 0) + 1)
    // (d)
    const dp = paramProblems(reason.key, reason.params, s)
    if (dp.length > 0) violation('d', id, `${check} ${reason.key}: ${dp.join('; ')}`)
    // (e)
    const ep = renderProblems(reason, varied.body)
    if (ep.length > 0) violation('e', id, `${check} ${reason.key}: ${ep.join('; ')}`)
  }
}

// ---------------------------------------------------------------------------
// The input set.
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
const SSE_CT = /text\/event-stream/i

const stageSizes: [string, number][] = []
const started = Date.now()

async function runStage(name: string, inputs: Iterable<[string, Script, Resp]>) {
  const t0 = Date.now()
  let n = 0
  for (const [id, script, varied] of inputs) {
    n++
    await checkInput(`${name} ${id}`, script, varied)
  }
  stageSizes.push([name, n])
  console.log(`  stage ${name}: ${n} inputs, ${((Date.now() - t0) / 1000).toFixed(1)}s`)
}

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

/** Tool arrays as raw JSON text (so 1e400 and lone-surrogate escapes survive
 *  to the parser exactly as a server would send them). */
function fingerprintCases(): [string, string][] {
  const ok = (name: string) => `{"name":"${name}","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}`
  let deep = '1'
  for (let i = 0; i < 100_000; i++) deep = `{"d":${deep}`
  deep += '}'.repeat(100_000)
  let shallow = '1'
  for (let i = 0; i < 50; i++) shallow = `{"d":${shallow}}`
  const defects: [string, string][] = [
    ['missing name', '{"inputSchema":{}}'],
    ['name number', '{"name":7,"inputSchema":{}}'],
    ['name null', '{"name":null,"inputSchema":{}}'],
    ['tool null', 'null'],
    ['tool string', `"${CANARY}"`],
    ['tool array', '["a"]'],
    ['lone high surrogate in name', '{"name":"a\\ud800","inputSchema":{}}'],
    ['lone low surrogate in name', '{"name":"\\udc00b","inputSchema":{}}'],
    ['paired surrogates in name', '{"name":"a\\ud83d\\ude00","inputSchema":{}}'],
    ['lone surrogate in schema value', '{"name":"s1","inputSchema":{"const":"x\\ud800"}}'],
    ['lone surrogate in schema key', '{"name":"s2","inputSchema":{"\\ud800":1}}'],
    ['1e400 in schema', '{"name":"s3","inputSchema":{"maximum":1e400}}'],
    ['-1e400 in schema', '{"name":"s4","inputSchema":{"minimum":-1e400}}'],
    ['-0 in schema', '{"name":"s5","inputSchema":{"minimum":-0}}'],
    ['NFC-duplicate keys', `{"name":"s6","inputSchema":{"caf\\u00e9${CANARY}":1,"cafe\\u0301${CANARY}":2}}`],
    ['missing inputSchema', '{"name":"s7"}'],
    ['null inputSchema', '{"name":"s8","inputSchema":null}'],
    ['depth 100000', `{"name":"s9","inputSchema":${deep}}`],
    ['depth 50', `{"name":"s10","inputSchema":${shallow}}`],
  ]
  const cases: [string, string][] = []
  for (const [label, defect] of defects) for (const at of [0, 1, 2]) {
    const tools = [ok('alpha'), ok('beta'), ok('gamma')]
    tools[at] = defect
    cases.push([`${label} @${at}`, `[${tools.join(',')}]`])
  }
  cases.push(['empty array', '[]'])
  cases.push(['schema-canonicalize @0 before missing name @2', `[${'{"name":"z","inputSchema":{"maximum":1e400}}'},${ok('b')},${'{"inputSchema":{}}'}]`])
  cases.push(['missing name @0 before schema-canonicalize @2', `[${'{"inputSchema":{}}'},${ok('b')},${'{"name":"z","inputSchema":{"maximum":1e400}}'}]`])
  cases.push(['duplicate names, different schemas', `[${ok('dup')},{"name":"dup","inputSchema":{"type":"string"}}]`])
  return cases
}

const fingerprintDirectFailures: string[] = []
let fingerprintDirectCount = 0

function* fingerprintStage(): Generator<[string, Script, Resp]> {
  for (const [label, text] of fingerprintCases()) {
    const tl = resp(200, 'application/json', rpcResult(`{"tools":${text}}`))
    yield [label, { discover: DISCOVER_OK, initialize: INIT_OK, ack: ACK_OK, toolsList: tl }, tl]
  }
}

async function fingerprintDirect(): Promise<void> {
  for (const [label, text] of fingerprintCases()) {
    fingerprintDirectCount++
    const tools = JSON.parse(text) as unknown[]
    const pairs: [string, (x: unknown[]) => Promise<{ status: string; fingerprint?: string; reason?: unknown }>, (x: unknown[]) => Promise<FrozenFingerprintVerdict>, (x: unknown[]) => OReason | null][] = [
      ['toolset', computeToolsetFingerprint, frozenComputeToolsetFingerprint, oracleToolset],
      ['schema', computeSchemaFingerprint, frozenComputeSchemaFingerprint, oracleSchema],
    ]
    for (const [which, impl, frozen, orc] of pairs) {
      const got = await impl(tools)
      const old = await frozen(tools)
      const want = orc(tools)
      const problems: string[] = []
      if (got.status !== old.status) problems.push(`status new=${got.status} pre-T73b=${old.status}`)
      if (got.status === 'VERIFIED' && (old.status !== 'VERIFIED' || got.fingerprint !== old.fingerprint)) problems.push('fingerprint differs')
      if (got.status === 'VERIFIED' && 'reason' in got) problems.push('VERIFIED carries a reason')
      if (got.status === 'FAILED' && JSON.stringify(got.reason) !== JSON.stringify(want)) problems.push(`reason ${JSON.stringify(got.reason)} want ${JSON.stringify(want)}`)
      if (got.status === 'VERIFIED' && want !== null) problems.push(`oracle expected ${JSON.stringify(want)}`)
      if (problems.length > 0) fingerprintDirectFailures.push(`${which} ${label}: ${problems.join('; ')}`)
    }
  }
}

console.log('T73b differential invariant：新实现 vs 冻结的 pre-T73b 实现 vs 独立 oracle（五个 check 的 FAILED 原因）')

await runStage('discover', discoverStage())
await runStage('initialize', initializeStage())
await runStage('ack', ackStage())
await runStage('tools/list', toolsListStage())
await runStage('fingerprint (over the wire)', fingerprintStage())
await fingerprintDirect()

const total = stageSizes.reduce((n, [, k]) => n + k, 0)
const seconds = ((Date.now() - started) / 1000).toFixed(1)
console.log(`  input set: ${stageSizes.map(([n, k]) => `${n}=${k}`).join(' + ')} = ${total} runProbe inputs (+ ${fingerprintDirectCount} tool arrays × 2 fingerprints computed directly); ${aborted} of them aborted (429); ${seconds}s`)

await t(`(a)-(e) hold for all ${total} inputs`, () => {
  const count = Object.values(byInvariant).reduce((n, k) => n + k, 0)
  if (count > 0) {
    throw new Error(`${count} violation(s) — by invariant: ${JSON.stringify(byInvariant)}\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? `\n         … and more` : ''}`)
  }
})

await t(`fingerprint verdicts computed directly: new = pre-T73b (status and digest), reason = oracle, for all ${fingerprintDirectCount} tool arrays`, () => {
  if (fingerprintDirectFailures.length > 0) throw new Error(fingerprintDirectFailures.slice(0, 25).join('\n         '))
})

await t('the input set is not vacuous: every one of the 18 T73b keys is produced, and each check is seen VERIFIED and FAILED', () => {
  console.log(`       ${T73B_KEYS.map((k) => `${k}=${keyCounts.get(k) ?? 0}`).join(' ')}`)
  console.log(`       ${[...statusCounts.entries()].sort().map(([k, v]) => `${k}=${v}`).join(' ')}`)
  for (const k of T73B_KEYS) assert.ok((keyCounts.get(k) ?? 0) > 0, `${k} never produced — the set does not reach that cell`)
  for (const check of FIVE) {
    assert.ok((statusCounts.get(`${check}:VERIFIED`) ?? 0) > 0, `${check} never VERIFIED`)
    assert.ok((statusCounts.get(`${check}:FAILED`) ?? 0) > 0, `${check} never FAILED`)
  }
  assert.ok(aborted > 0, 'no aborted (429) input — the abort path is not exercised')
})

await t('the oracle agrees with itself on hand-derived anchor cases (guards the oracle, not the implementation)', () => {
  const script = (over: Partial<Script>): Script => ({ discover: DISCOVER_OK, initialize: INIT_OK, ack: ACK_OK, toolsList: TOOLS_OK, ...over })
  assert.deepStrictEqual(oracle(script({ discover: resp(200, 'text/html', '<p>x</p>') })).reason.discovery_handshake, { key: 'handshake_discover_not_jsonrpc' })
  assert.deepStrictEqual(oracle(script({ discover: resp(200, 'application/json', rpcError('-0')) })).reason.discovery_handshake, { key: 'handshake_discover_jsonrpc_error', params: { jsonrpc_error_code: 0 } })
  assert.deepStrictEqual(oracle(script({ discover: resp(200, 'application/json', rpcError('1.5')) })).reason.discovery_handshake, { key: 'handshake_discover_jsonrpc_error' })
  assert.deepStrictEqual(oracle(script({ discover: resp(401, 'application/json', rpcError('-32021')) })).reason.discovery_handshake, { key: 'handshake_discover_rejected', params: { status: 401, jsonrpc_error_code: -32021 } })
  assert.deepStrictEqual(oracle(script({ discover: resp(204, null, '') })).reason.discovery_handshake, { key: 'handshake_discover_http_error', params: { status: 204 } })
  assert.equal(oracle(script({ discover: resp(429, null, '') })).status.discovery_handshake, 'UNVERIFIED')
  assert.deepStrictEqual(oracle(script({ discover: DISCOVER_FALLBACK, ack: resp(401, null, '', { challenge: true }) })).status, { discovery_handshake: 'UNVERIFIED', protocol_revision: 'UNVERIFIED', tools_list: 'UNVERIFIED', toolset_fingerprint: 'UNVERIFIED', schema_fingerprint: 'UNVERIFIED' })
  assert.deepStrictEqual(oracle(script({ discover: DISCOVER_FAILED, toolsList: resp(401, 'application/json', rpcResult(`{"tools":${VALID_TOOLS}}`), { challenge: true }) })).reason.tools_list, { key: 'tools_list_challenge_after_failed_handshake' })
  assert.equal(oracle(script({ toolsList: resp(401, 'application/json', '', { challenge: true }) })).status.tools_list, 'UNVERIFIED')
  assert.deepStrictEqual(oracleSchema(JSON.parse(`[{"name":"a","inputSchema":{"m":1e400}},{"inputSchema":{}}]`) as unknown[]), { key: 'fingerprint_canonicalize_failed' })
  assert.deepStrictEqual(oracleToolset(JSON.parse(`[{"name":"a","inputSchema":{"m":1e400}},{"inputSchema":{}}]`) as unknown[]), { key: 'fingerprint_tool_missing_name' })
  assert.equal(oracleCanonical(JSON.parse('{"a":[1,"\\ud83d\\ude00",{"b":null}]}')), true)
  assert.deepStrictEqual(oracleSseData('data: a\r\n\r\ndata:b\ndata: c\n\n: x\n\ndata:\n\n'), ['a', 'b\nc'])
  assert.ok(SSE_CT.test('Text/Event-Stream; charset=utf-8'))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
