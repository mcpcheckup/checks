import { parseJsonRpcCall, jsonRpcResult, jsonRpcError, notificationAccepted, rawResponse, summarizeResponse } from '../helpers.ts'
import type { ExpectedAssertion, FetchHandler, ResponseSummary } from '../types.ts'

export const HOST = 'notes-mcp.example.com'
export const ENDPOINT = `https://${HOST}/mcp`
export const MIRROR_ENDPOINT = 'https://mirror.example.com/mcp'

/** Fixed, never randomly generated — determinism requires every id a fixture emits to
 *  be a constant, not crypto.randomUUID()/Math.random(). Real servers mint real random
 *  session ids; a fixture is not a real server and must not behave like one here. */
export const FIXED_SESSION_ID = 'fixture-session-000'

export const CLEAN_TOOLS = [
  {
    name: 'list_notes',
    description: 'List all notes for the current user.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'create_note',
    description: 'Create a new note with the given title and body.',
    inputSchema: {
      type: 'object',
      properties: { title: { type: 'string' }, body: { type: 'string' } },
      required: ['title', 'body'],
      additionalProperties: false,
    },
  },
]

export const LARGE_NESTED_TOOLSET = [
  ...CLEAN_TOOLS,
  {
    name: 'update_note',
    description: 'Update an existing note by id, applying a partial patch.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        patch: {
          type: 'object',
          properties: {
            title: { type: 'string' },
            body: { type: 'string' },
            tags: { type: 'array', items: { type: 'string' } },
          },
          additionalProperties: false,
        },
      },
      required: ['id', 'patch'],
      additionalProperties: false,
    },
  },
  {
    name: 'delete_note',
    description: 'Delete a note by id.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false },
  },
  {
    name: 'search_notes',
    description: 'Search notes using a structured query with nested filters.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'object',
          properties: {
            text: { type: 'string' },
            filters: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  field: { type: 'string' },
                  op: { enum: ['eq', 'contains', 'gt', 'lt'] },
                  value: {},
                },
                required: ['field', 'op', 'value'],
                additionalProperties: false,
              },
            },
          },
          additionalProperties: false,
        },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    name: 'list_tags',
    description: 'List all tags currently in use across notes.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'rename_tag',
    description: 'Rename a tag across every note that uses it.',
    inputSchema: {
      type: 'object',
      properties: { from: { type: 'string' }, to: { type: 'string' } },
      required: ['from', 'to'],
      additionalProperties: false,
    },
  },
  {
    name: 'export_notes',
    description: 'Export notes matching a filter to the given format.',
    inputSchema: {
      type: 'object',
      properties: {
        format: { enum: ['markdown', 'json', 'csv'] },
        filter: {
          type: 'object',
          properties: {
            tags: { type: 'array', items: { type: 'string' } },
            before: { type: 'string', format: 'date' },
            after: { type: 'string', format: 'date' },
          },
          additionalProperties: false,
        },
      },
      required: ['format'],
      additionalProperties: false,
    },
  },
]

const CLIENT_META = {
  'io.modelcontextprotocol/clientInfo': { name: 'mcp-checkup-prober', version: '0.1.0' },
  'io.modelcontextprotocol/clientCapabilities': {},
}

function modernMeta(protocolVersion: string) {
  return { 'io.modelcontextprotocol/protocolVersion': protocolVersion, ...CLIENT_META }
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

export function unclaimedDriftAssertions(): ExpectedAssertion[] {
  return [
    { check_id: 'toolset_unchanged_vs_approved', execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'no_baseline_reason', params: { check_id: 'toolset_unchanged_vs_approved' } } },
    { check_id: 'schema_unchanged_vs_approved', execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'no_baseline_reason', params: { check_id: 'schema_unchanged_vs_approved' } } },
  ]
}

export function latencyObserved(): ExpectedAssertion {
  return { check_id: 'latency_profile', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' }
}

/** The full "everything is fine" assertion set for a clean modern or legacy server —
 *  used as the base for both positive fixtures and negative fixtures that isolate a
 *  single divergent check (everything else about the server is unremarkable). */
export function cleanBaselineAssertions(): ExpectedAssertion[] {
  return [
    { check_id: 'reachability', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    latencyObserved(),
    { check_id: 'transport_type', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'protocol_revision', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'discovery_handshake', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'tools_list', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'error_taxonomy', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'redirect_policy', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'auth_metadata', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'tool_description_hygiene', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'toolset_fingerprint', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    { check_id: 'schema_fingerprint', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' },
    ...unclaimedDriftAssertions(),
  ]
}

/** Replaces one entry (by check_id) in a base assertion list — for negative fixtures
 *  that isolate exactly one divergent check against an otherwise-clean baseline. */
export function withOverride(base: ExpectedAssertion[], override: ExpectedAssertion): ExpectedAssertion[] {
  return base.map((a) => (a.check_id === override.check_id ? override : a))
}

export function withOverrides(base: ExpectedAssertion[], overrides: ExpectedAssertion[]): ExpectedAssertion[] {
  return overrides.reduce((acc, o) => withOverride(acc, o), base)
}

// ---- modern (2026-07-28) handler + sample-run engine ----

export interface ModernHandlerOptions {
  protocolVersion?: string
  discoverResponse?: (id: unknown) => Response
  toolsListResponse?: (id: unknown) => Response
  toolsCallResponse?: (id: unknown, name: unknown) => Response
  onOtherPath?: (call: Awaited<ReturnType<typeof parseJsonRpcCall>>) => Response | undefined
}

export function createModernHandler(tools: unknown[], opts: ModernHandlerOptions = {}): FetchHandler {
  const protocolVersion = opts.protocolVersion ?? '2026-07-28'
  return async (input, init) => {
    const call = await parseJsonRpcCall(input, init)

    const fromOther = opts.onOtherPath?.(call)
    if (fromOther) return fromOther

    switch (call.jsonrpcMethod) {
      case 'server/discover':
        return (
          opts.discoverResponse?.(call.id) ??
          jsonRpcResult(call.id, {
            resultType: 'complete',
            supportedVersions: [protocolVersion],
            capabilities: { tools: {} },
            _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'notes-mcp', version: '1.4.0' } },
          })
        )
      case 'tools/list':
        return opts.toolsListResponse?.(call.id) ?? jsonRpcResult(call.id, { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public', tools })
      case 'tools/call': {
        const name = (call.params as { name?: unknown } | undefined)?.name
        if (opts.toolsCallResponse) return opts.toolsCallResponse(call.id, name)
        const known = tools.some((t) => (t as { name: string }).name === name)
        if (!known) return jsonRpcError(call.id, -32602, `Invalid params: unknown tool ${JSON.stringify(name)}`)
        return jsonRpcResult(call.id, { resultType: 'complete', content: [] })
      }
      default:
        return jsonRpcError(call.id, -32601, `Method not found: ${JSON.stringify(call.jsonrpcMethod)}`)
    }
  }
}

export async function modernSampleRun(
  handler: FetchHandler,
  opts: { protocolVersion?: string; endpoint?: string; unknownToolName?: string } = {},
): Promise<ResponseSummary[]> {
  const protocolVersion = opts.protocolVersion ?? '2026-07-28'
  const endpoint = opts.endpoint ?? ENDPOINT
  const meta = modernMeta(protocolVersion)
  const results: ResponseSummary[] = []

  results.push(
    await summarizeResponse(
      await handler(endpoint, {
        method: 'POST',
        headers: modernHeaders(protocolVersion, 'server/discover'),
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: meta } }),
      }),
    ),
  )
  results.push(
    await summarizeResponse(
      await handler(endpoint, {
        method: 'POST',
        headers: modernHeaders(protocolVersion, 'tools/list'),
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: { _meta: meta } }),
      }),
    ),
  )
  const unknownTool = opts.unknownToolName ?? 'nonexistent_tool'
  results.push(
    await summarizeResponse(
      await handler(endpoint, {
        method: 'POST',
        headers: modernHeaders(protocolVersion, 'tools/call', unknownTool),
        body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: unknownTool, arguments: {}, _meta: meta } }),
      }),
    ),
  )
  return results
}

// ---- legacy (pre-2026-07-28, initialize handshake) handler + sample-run engine ----

export interface LegacyHandlerOptions {
  protocolVersion?: string
  discoverProbeResponse?: (id: unknown) => Response
  toolsListResponse?: (id: unknown) => Response
  /** Task Y: models a real, spec-compliant legacy server (observed at
   *  mcp.deepwiki.com/mcp) that enforces transports.md's Streamable HTTP §"Sending
   *  Messages to the Server" step 2 — "The client MUST include an Accept header,
   *  listing both application/json and text/event-stream as supported content
   *  types" — on every POST, including the very first `initialize` (the spec's own
   *  Backwards Compatibility section says so explicitly: "Attempt to POST an
   *  InitializeRequest ... with an Accept header as defined above"). When true,
   *  any request missing either media type in Accept gets the same 406 shape
   *  DeepWiki actually returns, instead of being served normally. */
  enforceAcceptHeader?: boolean
  /** Task Y: models a real, spec-compliant legacy server (observed at mcp.deepwiki.com/mcp)
   *  that never assigns an Mcp-Session-Id at all. 2025-06-18 spec "Session Management" §1:
   *  "A server using the Streamable HTTP transport MAY assign a session ID at initialization
   *  time" — MAY, not MUST. When true, `initialize`'s response omits the header entirely, and
   *  `tools/list` no longer gates on one being present. */
  omitSessionId?: boolean
  /** Task Y: models a real, spec-compliant legacy server (observed at mcp.deepwiki.com/mcp)
   *  that answers every JSON-RPC *request* (initialize, tools/list, tools/call — not the
   *  `notifications/initialized` *notification*, which has no body either way) with
   *  Content-Type: text/event-stream instead of application/json. 2025-06-18 spec "Sending
   *  Messages to the Server" §5: "the server MUST either return Content-Type:
   *  text/event-stream, to initiate an SSE stream, or Content-Type: application/json, to
   *  return one JSON object. The client MUST support both these cases." This is a one-shot
   *  POST reply framed as a single SSE event, not a long-lived push channel. */
  sseFramedResponses?: boolean
  /** T6.9-F: the legacy counterpart of ModernHandlerOptions.toolsCallResponse,
   *  added so a legacy server can gate `tools/call` specifically while leaving
   *  the whole handshake and `tools/list` open. Same signature as the modern
   *  one (id, name) so the two handlers stay interchangeable at the call site.
   *  Absent by default — every pre-existing legacy fixture keeps its exact
   *  previous behaviour. */
  toolsCallResponse?: (id: unknown, name: unknown) => Response
  /** T73b: replaces the `initialize` answer (the session still counts as
   *  initialized), so a fixture can pin one way the legacy handshake fails.
   *  Absent by default — every pre-existing legacy fixture is unchanged. */
  initializeResponse?: (id: unknown) => Response
  /** T73b: replaces the 202 answer to `notifications/initialized`. */
  initializedNotificationResponse?: () => Response
}

function acceptHeaderSatisfied(headers: Headers): boolean {
  const accept = headers.get('accept') ?? ''
  return accept.includes('application/json') && accept.includes('text/event-stream')
}

function notAcceptable406(id: unknown): Response {
  return jsonRpcError(id, -32600, 'Not Acceptable: Client must accept both application/json and text/event-stream', { status: 406 })
}

/** Answers a JSON-RPC *request* (as opposed to a notification) either as a plain
 *  application/json body or, when `sse` is set, as a single SSE `event: message` frame
 *  wrapping the identical JSON-RPC message — see LegacyHandlerOptions.sseFramedResponses. */
function respondToRequest(
  message: { jsonrpc: '2.0'; id: unknown; result?: unknown; error?: unknown },
  opts: { sse?: boolean; status?: number; headers?: Record<string, string> } = {},
): Response {
  const status = opts.status ?? 200
  if (opts.sse) {
    return rawResponse(status, { 'content-type': 'text/event-stream', ...opts.headers }, `event: message\ndata: ${JSON.stringify(message)}\n\n`)
  }
  return rawResponse(status, { 'content-type': 'application/json', ...opts.headers }, JSON.stringify(message))
}

export function createLegacyHandler(tools: unknown[], opts: LegacyHandlerOptions = {}): FetchHandler {
  const protocolVersion = opts.protocolVersion ?? '2025-06-18'
  let sessionInitialized = false

  return async (input, init) => {
    const call = await parseJsonRpcCall(input, init)
    if (opts.enforceAcceptHeader && !acceptHeaderSatisfied(call.headers)) {
      return notAcceptable406(call.id ?? 'server-error')
    }
    switch (call.jsonrpcMethod) {
      case 'server/discover':
        // A legacy server predates server/discover entirely. Per the 2026-07-28 spec's
        // own backward-compatibility algorithm, a modern probe attempt against a
        // legacy server gets a 400 whose body is NOT one of the three recognized
        // modern error names (UnsupportedProtocolVersionError / MissingRequired-
        // ClientCapabilityError / HeaderMismatchError) — here, a bog-standard
        // "Method not found". A correct detector must recognize this as "not a
        // modern error" and fall back to `initialize`, not conclude the server is
        // broken. See README "Why HTTP 400 with a plain JSON-RPC error" for the
        // reasoning — this exact shape is implementation-defined by the spec, and
        // this is our documented, deliberate modeling choice.
        return opts.discoverProbeResponse?.(call.id) ?? jsonRpcError(call.id, -32601, 'Method not found', { status: 400 })
      case 'initialize': {
        sessionInitialized = true
        if (opts.initializeResponse) return opts.initializeResponse(call.id)
        const sessionHeaders = opts.omitSessionId ? {} : { 'mcp-session-id': FIXED_SESSION_ID }
        return respondToRequest(
          {
            jsonrpc: '2.0',
            id: call.id,
            result: { protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'notes-mcp', version: '1.4.0' } },
          },
          { sse: !!opts.sseFramedResponses, headers: sessionHeaders },
        )
      }
      case 'notifications/initialized':
        return opts.initializedNotificationResponse?.() ?? notificationAccepted()
      case 'tools/list': {
        if (!opts.omitSessionId && (!sessionInitialized || call.headers.get('mcp-session-id') !== FIXED_SESSION_ID)) {
          return jsonRpcError(call.id, -32000, 'Session not initialized', { status: 400 })
        }
        if (opts.toolsListResponse) return opts.toolsListResponse(call.id)
        return respondToRequest({ jsonrpc: '2.0', id: call.id, result: { tools } }, { sse: !!opts.sseFramedResponses })
      }
      case 'tools/call': {
        const name = (call.params as { name?: unknown } | undefined)?.name
        if (opts.toolsCallResponse) return opts.toolsCallResponse(call.id, name)
        const known = tools.some((t) => (t as { name: string }).name === name)
        if (!known) {
          return respondToRequest(
            { jsonrpc: '2.0', id: call.id, error: { code: -32602, message: `Invalid params: unknown tool ${JSON.stringify(name)}` } },
            { sse: !!opts.sseFramedResponses },
          )
        }
        return respondToRequest({ jsonrpc: '2.0', id: call.id, result: { content: [] } }, { sse: !!opts.sseFramedResponses })
      }
      default:
        return jsonRpcError(call.id, -32601, `Method not found: ${JSON.stringify(call.jsonrpcMethod)}`)
    }
  }
}

export async function legacySampleRun(
  handler: FetchHandler,
  opts: { protocolVersion?: string; endpoint?: string; unknownToolName?: string; includeAcceptHeader?: boolean } = {},
): Promise<ResponseSummary[]> {
  const protocolVersion = opts.protocolVersion ?? '2025-06-18'
  const endpoint = opts.endpoint ?? ENDPOINT
  const results: ResponseSummary[] = []
  // Task Y: legacy-strict-accept-enforcement's self-documenting example must show
  // the CORRECT traffic (Accept header present on every request, per
  // transports.md's Streamable HTTP §"Sending Messages to the Server" step 2) —
  // not the bug this same fixture exists to catch. Every other legacy fixture
  // keeps the pre-existing (no Accept header) trace so their determinism/shape
  // assertions stay unchanged.
  const legacyHeaders: Record<string, string> = opts.includeAcceptHeader
    ? { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }
    : { 'content-type': 'application/json' }

  // 1. modern probe attempt first, per the spec's own detection algorithm.
  const discoverProbe = await handler(endpoint, {
    method: 'POST',
    headers: modernHeaders('2026-07-28', 'server/discover'),
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: modernMeta('2026-07-28') } }),
  })
  results.push(await summarizeResponse(discoverProbe))

  // 2. fall back to legacy initialize.
  const initRes = await handler(endpoint, {
    method: 'POST',
    headers: legacyHeaders,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'initialize',
      params: { protocolVersion, capabilities: {}, clientInfo: { name: 'mcp-checkup-prober', version: '0.1.0' } },
    }),
  })
  const sessionId = initRes.headers.get('mcp-session-id')
  const sessionIdHeader = sessionId ? { 'mcp-session-id': sessionId } : {}
  results.push(await summarizeResponse(initRes))

  // 3. notifications/initialized.
  results.push(
    await summarizeResponse(
      await handler(endpoint, {
        method: 'POST',
        headers: legacyHeaders,
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      }),
    ),
  )

  // 4. tools/list, with the session header the server minted.
  results.push(
    await summarizeResponse(
      await handler(endpoint, {
        method: 'POST',
        headers: { ...legacyHeaders, 'mcp-protocol-version': protocolVersion, ...sessionIdHeader },
        body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }),
      }),
    ),
  )

  // 5. tools/call with an unknown tool — the error_taxonomy probe.
  const unknownTool = opts.unknownToolName ?? 'nonexistent_tool'
  results.push(
    await summarizeResponse(
      await handler(endpoint, {
        method: 'POST',
        headers: { ...legacyHeaders, 'mcp-protocol-version': protocolVersion, ...sessionIdHeader },
        body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: unknownTool, arguments: {} } }),
      }),
    ),
  )

  return results
}
