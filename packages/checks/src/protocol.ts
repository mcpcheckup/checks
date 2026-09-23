import { sendRequest } from './wire.ts'
import type { ProbeContext } from './wire.ts'
import type { FetchLike, ProbeBudget } from './types.ts'
import { classifyCredentialChallenge } from './auth.ts'

const CLIENT_INFO = { name: 'mcp-checkup-prober', version: '0.1.0' }
const MODERN_PROBE_VERSION = '2026-07-28'
const LEGACY_PROBE_VERSION = '2025-06-18'

export interface ParsedJsonRpc {
  isJsonRpc: boolean
  id?: unknown
  result?: unknown
  error?: { code: number; message: string; data?: unknown }
}

/** Exported for error-taxonomy.ts, which must classify over exactly the
 *  candidates the verdict saw (see jsonRpcCandidates below). */
export function isSseContentType(contentType?: string | null): boolean {
  return (contentType ?? '').toLowerCase().includes('text/event-stream')
}

/** SSE frames each message as one or more `data:` lines within a blank-line-delimited
 *  "event" block (html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation).
 *  The 2025-06-18 Streamable HTTP spec's "Sending Messages to the Server" §5 lets the
 *  server answer ANY POST this way instead of a plain JSON body: "the server MUST
 *  either return Content-Type: text/event-stream, to initiate an SSE stream, or
 *  Content-Type: application/json, to return one JSON object. The client MUST support
 *  both these cases." Real observed case: DeepWiki's legacy `initialize` response
 *  (Task Y) — content-type text/event-stream despite being a one-shot POST reply, not
 *  a long-lived push channel. */
function extractSseDataPayloads(bodyText: string): string[] {
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

function parseJsonRpcText(bodyText: string): ParsedJsonRpc {
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

/** The texts parseJsonRpcBody tries, in order: an SSE-framed body's `data:`
 *  payloads (possibly none at all), otherwise the whole body as one candidate.
 *  Exported so error-taxonomy.ts classifies over exactly these candidates and
 *  no others (T73): one definition, so a verdict and its recorded
 *  classification can never be computed over two different readings of the
 *  same response. */
export function jsonRpcCandidates(bodyText: string, contentType?: string | null): string[] {
  return isSseContentType(contentType) ? extractSseDataPayloads(bodyText) : [bodyText]
}

/** Never throws — an unparseable or non-JSON-RPC body is data (isJsonRpc: false), not
 *  an exception, exactly like fixtures' own parseJsonRpcCall on the server side.
 *  contentType is optional for callers that only ever see application/json (and for
 *  the direct unit tests below); pass it whenever it's available so an SSE-framed body
 *  (see extractSseDataPayloads) gets unwrapped before the JSON-RPC parse. */
export function parseJsonRpcBody(bodyText: string, contentType?: string | null): ParsedJsonRpc {
  for (const candidate of jsonRpcCandidates(bodyText, contentType)) {
    const parsed = parseJsonRpcText(candidate)
    if (parsed.isJsonRpc) return parsed
  }
  return { isJsonRpc: false }
}

/** The three error codes the 2026-07-28 Streamable HTTP spec allocates for a
 *  modern server rejecting a request at the HTTP 400 level (HeaderMismatch,
 *  MissingRequiredClientCapability, UnsupportedProtocolVersion, in that order).
 *  Seeing one of these at 400 means "this server IS modern but rejected this
 *  particular request" — anything else at 400 means "this server doesn't
 *  recognize modern requests at all," which is the fallback-to-initialize signal. */
export const RECOGNIZED_MODERN_ERROR_CODES: ReadonlySet<number> = new Set([-32020, -32021, -32022])

function modernMeta(protocolVersion: string) {
  return {
    'io.modelcontextprotocol/protocolVersion': protocolVersion,
    'io.modelcontextprotocol/clientInfo': CLIENT_INFO,
    'io.modelcontextprotocol/clientCapabilities': {},
  }
}

function modernHeaders(protocolVersion: string, mcpMethod: string, mcpName?: string): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': protocolVersion,
    'mcp-method': mcpMethod,
    ...(mcpName ? { 'mcp-name': mcpName } : {}),
  }
}

/** The 2025-06-18 Streamable HTTP transport spec's "Sending Messages to the
 *  Server" §2 requires the client to send an Accept header listing both
 *  application/json and text/event-stream on every POST — and the spec's own
 *  "Backwards Compatibility" section extends this to the first InitializeRequest
 *  itself, not just subsequent requests
 *  (modelcontextprotocol.io/specification/2025-06-18/basic/transports#sending-messages-to-the-server).
 *  A real compliant legacy server (mcp.deepwiki.com/mcp) 406-rejects a legacy
 *  fallback that omits this — Task Y. */
function legacyHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  }
}

async function sendModern(
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
      headers: modernHeaders(protocolVersion, method, mcpName),
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params: { ...extraParams, _meta: modernMeta(protocolVersion) } }),
    },
    budget,
    ctx,
  )
}

export interface HandshakeResult {
  mode: 'modern' | 'legacy'
  handshakeOk: boolean
  /** null when we never got a structurally usable version string at all. */
  protocolVersionDeclared: string | null
  /** legacy mode only. */
  sessionId?: string
  /** Where subsequent requests (tools/list, tools/call) should go — may differ
   *  from the endpoint we started with if the handshake itself redirected. */
  currentEndpoint: string
  /** Set only when handshakeOk is false, derived from classifyCredentialChallenge
   *  against the FINAL response of this handshake attempt — the modern
   *  server/discover response for a modern-branch return, or (after a legacy
   *  fallback) the legacy initialize/notifications-initialized response for a
   *  legacy-branch return. Never set on the RECOGNIZED_MODERN_ERROR_CODES
   *  return — a recognized modern JSON-RPC error is a real client/server
   *  mismatch, not a credential gate (see the handshake- and tools-list-layer
   *  credential-gate rules below). */
  credentialChallenge?: { scheme: string }
}

/** Attaches credentialChallenge only when classifyCredentialChallenge finds one —
 *  exactOptionalPropertyTypes means the property must be entirely absent, not
 *  present-with-undefined, when there's nothing to report. */
function credentialChallengeFrom(status: number, headers: Headers): { credentialChallenge: { scheme: string } } | Record<string, never> {
  const challenge = classifyCredentialChallenge(status, headers)
  return challenge ? { credentialChallenge: challenge } : {}
}

/** Implements the 2026-07-28 spec's own backward-compatibility detection
 *  algorithm: try a modern server/discover first; on ANY 4xx, inspect the body
 *  — a recognized modern error means this IS a modern server rejecting the
 *  specific request (not a fallback trigger); anything else means "doesn't
 *  speak modern MCP," so fall back to the legacy initialize handshake. This is
 *  the concrete mechanism behind checks.json's discovery_handshake
 *  p0_note_zh: judging the newest implementation by whether it passes THIS
 *  algorithm, not by whether it happens to support the old initialize flow.
 *
 *  The 4xx range (not just 400) is deliberate, not a generalization we made
 *  up: the Streamable HTTP transport page's own backward-compatibility note
 *  only illustrates the 400 case, but
 *  modelcontextprotocol.io/specification/2026-07-28/basic/versioning
 *  #compatibility-matrix is explicit — the "Dual-era client / Legacy server"
 *  row says "the modern request returns a `4xx` without a recognized modern
 *  error body, and the client falls back to `initialize`", and the paragraph
 *  above it: "a recognized modern JSON-RPC error ... identifies a modern
 *  server ... Anything else identifies a legacy server." A real observed case
 *  (droproom/mcp, 2026-08-30 fp investigation) returns 401 Unauthorized
 *  (non-JSON-RPC `{"error":"unauthorized"}` body) to `server/discover` — a
 *  perfectly ordinary legacy server whose catch-all for an unrecognized
 *  modern-only method happens to be 401, not 400 — and a legacy `initialize`
 *  against the same endpoint succeeds outright. Checking only `=== 400` here
 *  left every such legacy server stuck at handshakeOk:false with no fallback
 *  attempt ever made — a self-inflicted false positive, not a target defect. */
export async function performHandshake(opts: {
  fetchImpl: FetchLike
  endpoint: string
  budget: ProbeBudget
  ctx: ProbeContext
  newId: () => string
}): Promise<HandshakeResult> {
  const { fetchImpl, endpoint, budget, ctx, newId } = opts

  const discover = await sendModern(fetchImpl, endpoint, budget, ctx, 'server/discover', newId(), {}, MODERN_PROBE_VERSION)

  if (discover.status === 200) {
    const parsed = parseJsonRpcBody(discover.bodyText, discover.headers.get('content-type'))
    const result = parsed.isJsonRpc ? (parsed.result as Record<string, unknown> | undefined) : undefined
    // DiscoverResult's field is `supportedVersions` (modelcontextprotocol.io/specification/2026-07-28/server/discover#data-types),
    // not `protocolVersions`. `serverInfo` lives under `_meta['io.modelcontextprotocol/serverInfo']` and is spec-SHOULD, not
    // MUST ("Servers SHOULD include this field") — it must not gate handshake success.
    const supportedVersions = result?.supportedVersions
    const ok = parsed.isJsonRpc && Array.isArray(supportedVersions) && typeof supportedVersions[0] === 'string'
    // No credentialChallenge attachment here, even when ok is false: this
    // whole branch only runs when discover.status === 200, and
    // classifyCredentialChallenge requires status === 401 (the
    // handshake-layer credential-gate rule's explicit red line) — a 200 response can
    // never classify as credential-gated no matter what headers it carries,
    // so a credentialChallengeFrom(discover.status, ...) call here would be
    // permanently dead code, not a live check (Lead finding B2, round 2).
    return {
      mode: 'modern',
      handshakeOk: !!ok,
      protocolVersionDeclared: ok ? (supportedVersions as string[])[0]! : null,
      currentEndpoint: discover.finalUrl,
    }
  }

  if (discover.status >= 400 && discover.status < 500) {
    const parsed = parseJsonRpcBody(discover.bodyText, discover.headers.get('content-type'))
    if (parsed.isJsonRpc && parsed.error && RECOGNIZED_MODERN_ERROR_CODES.has(parsed.error.code)) {
      // A modern server exists but rejected our probe for a specific reason we
      // didn't work around (e.g. header mismatch). Not a legacy server — don't
      // fall back. No fixture currently exercises this branch. Deliberately no
      // credentialChallenge here even if this happened to be a 401 with a
      // valid WWW-Authenticate — a recognized modern error identifies a real
      // client/server mismatch, not a credential gate (the handshake-layer
      // credential-gate rule: "走既有 modern 分支，不变" — no exemption).
      return { mode: 'modern', handshakeOk: false, protocolVersionDeclared: null, currentEndpoint: discover.finalUrl }
    }
    return performLegacyHandshake(fetchImpl, discover.finalUrl, budget, ctx, newId)
  }

  // No credentialChallenge attachment here either, for the same reason as
  // the discover.status===200 branch above but from the other direction:
  // this line is only reached when discover.status is NOT 200 and NOT in
  // [400,500) (both of those cases return earlier). 401 is inside [400,500),
  // so it is always intercepted by the branch above — either recognized as
  // a modern error, or routed into the legacy fallback — and can never fall
  // through to here. Whatever status DOES land here (e.g. an unfollowed
  // 3xx, a 5xx) can never satisfy classifyCredentialChallenge's
  // status===401 requirement either, so a credentialChallengeFrom(...) call
  // here would, like the 200 branch's, always evaluate to no-op {} — dead
  // code, not a live check (Lead finding B2, round 2).
  return { mode: 'modern', handshakeOk: false, protocolVersionDeclared: null, currentEndpoint: discover.finalUrl }
}

async function performLegacyHandshake(
  fetchImpl: FetchLike,
  endpoint: string,
  budget: ProbeBudget,
  ctx: ProbeContext,
  newId: () => string,
): Promise<HandshakeResult> {
  const initRes = await sendRequest(
    fetchImpl,
    endpoint,
    {
      method: 'POST',
      headers: legacyHeaders(),
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: newId(),
        method: 'initialize',
        params: { protocolVersion: LEGACY_PROBE_VERSION, capabilities: {}, clientInfo: CLIENT_INFO },
      }),
    },
    budget,
    ctx,
  )

  const parsed = parseJsonRpcBody(initRes.bodyText, initRes.headers.get('content-type'))
  const result = parsed.isJsonRpc ? (parsed.result as Record<string, unknown> | undefined) : undefined
  const protocolVersion = result?.protocolVersion
  // Session ID assignment is the server's choice, not a requirement — 2025-06-18 spec,
  // "Session Management" §1: "A server ... MAY assign a session ID at initialization
  // time." A compliant legacy server may issue none at all (observed: mcp.deepwiki.com,
  // Task Y) — only forward it downstream (§2: "MUST include it ... on all of their
  // subsequent HTTP requests") when the server actually sent one.
  const sessionId = initRes.headers.get('mcp-session-id') ?? undefined

  if (initRes.status !== 200 || typeof protocolVersion !== 'string') {
    return {
      mode: 'legacy',
      handshakeOk: false,
      protocolVersionDeclared: null,
      currentEndpoint: initRes.finalUrl,
      ...credentialChallengeFrom(initRes.status, initRes.headers),
    }
  }

  const ackRes = await sendRequest(
    fetchImpl,
    initRes.finalUrl,
    {
      method: 'POST',
      headers: legacyHeaders(sessionId ? { 'mcp-session-id': sessionId } : undefined),
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
      ...credentialChallengeFrom(ackRes.status, ackRes.headers),
    }
  }

  return { mode: 'legacy', handshakeOk: true, protocolVersionDeclared: protocolVersion, ...(sessionId ? { sessionId } : {}), currentEndpoint: ackRes.finalUrl }
}

export interface ToolsListResult {
  ok: boolean
  tools: unknown[] | null
  currentEndpoint: string
  /** Derived from classifyCredentialChallenge against this single
   *  tools/list response — status and headers only, never its body
   *  (the tools-list-layer credential-gate rule). Still only ever
   *  present when `ok` is false, but the causality is now the other way
   *  round: a challenge here FORCES `ok` false. See performToolsList. */
  credentialChallenge?: { scheme: string }
}

export async function performToolsList(opts: {
  fetchImpl: FetchLike
  budget: ProbeBudget
  ctx: ProbeContext
  newId: () => string
  handshake: HandshakeResult
}): Promise<ToolsListResult> {
  const { fetchImpl, budget, ctx, newId, handshake } = opts
  const endpoint = handshake.currentEndpoint

  const res =
    handshake.mode === 'modern'
      ? await sendModern(fetchImpl, endpoint, budget, ctx, 'tools/list', newId(), {}, handshake.protocolVersionDeclared ?? MODERN_PROBE_VERSION)
      : await sendRequest(
          fetchImpl,
          endpoint,
          {
            method: 'POST',
            headers: legacyHeaders({
              'mcp-protocol-version': handshake.protocolVersionDeclared ?? LEGACY_PROBE_VERSION,
              ...(handshake.sessionId ? { 'mcp-session-id': handshake.sessionId } : {}),
            }),
            body: JSON.stringify({ jsonrpc: '2.0', id: newId(), method: 'tools/list', params: {} }),
          },
          budget,
          ctx,
        )

  // Codex PR#19 P2 (round 9): classify the credential
  // challenge from status + headers BEFORE the body is looked at, and let it
  // veto `ok`. Previously the challenge was only attached in the `!ok` arm,
  // so a response that was HTTP 401 with a structurally valid
  // WWW-Authenticate challenge but whose body happened to carry a well-formed
  // `result.tools` array came back ok=true with NO challenge — probe.ts then
  // fell through to its `else if (toolsList.ok)` arm, recorded tools_list
  // VERIFIED, and computed (and on a signed run published) toolset and schema
  // fingerprints from a response the server had marked 401. Not hypothetical:
  // a misconfigured auth proxy stamping 401 onto an otherwise successful
  // upstream response produces exactly this shape.
  //
  // Governing principle: "A 401 is the server declaring the response
  // unauthorized; signed evidence must never be derived from a response the
  // server itself disowned." Nulling `tools` at the source is what makes that
  // unconditional — it closes the cell probe.ts's credential_required branch
  // cannot reach, namely !handshakeOk (finding B6 scopes that branch to
  // handshakeOk, and the tools-list-layer credential-gate rule is unchanged
  // here) plus a challenged 401 carrying a tools array. With `ok` false, that
  // cell lands on probe.ts's final `else` — tools_list FAILED,
  // skipToolsDerivedChecks — instead of on the fingerprint-computing arm. No
  // branch in probe.ts needed reordering.
  //
  // This also brings the code into line with the criterion the credential-gate
  // rule states (status + headers; it never mentioned the body) and with the
  // published tools_list.cannot_* copy, which has no body condition either.
  // The code was narrower than both; no copy changes.
  const challenge = classifyCredentialChallenge(res.status, res.headers)
  const parsed = parseJsonRpcBody(res.bodyText, res.headers.get('content-type'))
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

export interface ProbeCallResult {
  status: number
  headers: Headers
  bodyText: string
  currentEndpoint: string
}

/** Calls a tool name that must not exist on any real server, the protocol-level
 *  way of triggering a safe error scenario (checks.json's error_taxonomy /
 *  auth_metadata both read this same response — never a business tool). */
export async function performUnknownToolCall(opts: {
  fetchImpl: FetchLike
  budget: ProbeBudget
  ctx: ProbeContext
  newId: () => string
  handshake: HandshakeResult
  toolName: string
}): Promise<ProbeCallResult> {
  const { fetchImpl, budget, ctx, newId, handshake, toolName } = opts
  const endpoint = handshake.currentEndpoint

  const res =
    handshake.mode === 'modern'
      ? await sendModern(
          fetchImpl,
          endpoint,
          budget,
          ctx,
          'tools/call',
          newId(),
          { name: toolName, arguments: {} },
          handshake.protocolVersionDeclared ?? MODERN_PROBE_VERSION,
          toolName,
        )
      : await sendRequest(
          fetchImpl,
          endpoint,
          {
            method: 'POST',
            headers: legacyHeaders({
              'mcp-protocol-version': handshake.protocolVersionDeclared ?? LEGACY_PROBE_VERSION,
              ...(handshake.sessionId ? { 'mcp-session-id': handshake.sessionId } : {}),
            }),
            body: JSON.stringify({ jsonrpc: '2.0', id: newId(), method: 'tools/call', params: { name: toolName, arguments: {} } }),
          },
          budget,
          ctx,
        )

  return { status: res.status, headers: res.headers, bodyText: res.bodyText, currentEndpoint: res.finalUrl }
}
