import type { ResponseSummary } from './types.ts'

export interface JsonRpcCall {
  url: URL
  httpMethod: string
  headers: Headers
  /** null when the body isn't parseable JSON, or has no string `method` field. */
  jsonrpcMethod: string | null
  id: unknown
  params: unknown
}

/** Parses an incoming fetch()-style call the way a fixture handler receives it. Never
 *  throws on a malformed body — a malformed request is exactly the kind of thing some
 *  fixtures need to simulate a server reacting to, so failure has to be representable
 *  as data (jsonrpcMethod: null), not an exception the handler has to catch. */
export async function parseJsonRpcCall(input: RequestInfo | URL, init?: RequestInit): Promise<JsonRpcCall> {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
  const headers = new Headers(init?.headers)
  const httpMethod = init?.method ?? 'GET'

  let parsed: unknown = null
  const rawBody = init?.body
  if (typeof rawBody === 'string') {
    try {
      parsed = JSON.parse(rawBody)
    } catch {
      parsed = null
    }
  }

  const isJsonRpcShape =
    typeof parsed === 'object' && parsed !== null && 'method' in parsed && typeof (parsed as { method: unknown }).method === 'string'

  return {
    url,
    httpMethod,
    headers,
    jsonrpcMethod: isJsonRpcShape ? (parsed as { method: string }).method : null,
    id: isJsonRpcShape ? (parsed as { id?: unknown }).id : undefined,
    params: isJsonRpcShape ? (parsed as { params?: unknown }).params : undefined,
  }
}

export interface JsonRpcErrorOptions {
  status?: number
  data?: unknown
}

function withHeaders(base: Record<string, string>, extra?: Record<string, string>): Record<string, string> {
  return { 'content-type': 'application/json', ...base, ...extra }
}

/** A successful JSON-RPC response. Defaults to HTTP 200, per Streamable HTTP: the
 *  server responds `Content-Type: application/json` for a single JSON object result. */
export function jsonRpcResult(id: unknown, result: unknown, opts?: { status?: number; headers?: Record<string, string> }): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), {
    status: opts?.status ?? 200,
    headers: withHeaders({}, opts?.headers),
  })
}

/** A JSON-RPC error response. Defaults to HTTP 200 — classic JSON-RPC-over-HTTP
 *  convention keeps the transport status at 200 and carries the error in the body.
 *  The 2026-07-28 revision's version/header-validation errors are the exception (they
 *  use 400), which callers select via opts.status — see the modern-vs-legacy fixtures
 *  for exactly which fixture needs which. */
export function jsonRpcError(id: unknown, code: number, message: string, opts?: JsonRpcErrorOptions): Response {
  const error: Record<string, unknown> = { code, message }
  if (opts?.data !== undefined) error.data = opts.data
  return new Response(JSON.stringify({ jsonrpc: '2.0', id, error }), {
    status: opts?.status ?? 200,
    headers: withHeaders({}),
  })
}

/** An HTTP 202 Accepted with no body — how a Streamable HTTP server acknowledges a
 *  JSON-RPC notification it accepted (e.g. legacy `notifications/initialized`). */
export function notificationAccepted(): Response {
  return new Response(null, { status: 202 })
}

/** Escape hatch for anything that isn't a JSON-RPC success/error: redirects, raw HTTP
 *  error pages, empty bodies — the shapes several negative fixtures specifically need. */
export function rawResponse(status: number, headers: Record<string, string>, body: string | null): Response {
  return new Response(body, { status, headers })
}

const SUMMARY_HEADER_ALLOWLIST = ['content-type', 'location', 'mcp-session-id', 'www-authenticate', 'mcp-protocol-version', 'retry-after']

/** Extracts a deterministic summary of a Response: status, an explicit allowlist of
 *  protocol-meaningful headers (never a wall-clock Date or anything else the runtime
 *  might be tempted to add), and the body text. Two calls against byte-identical
 *  responses must produce byte-identical summaries — this is what the determinism
 *  tests compare via canonicalBytes. */
export async function summarizeResponse(response: Response): Promise<ResponseSummary> {
  const headers: Record<string, string> = {}
  for (const name of SUMMARY_HEADER_ALLOWLIST) {
    const value = response.headers.get(name)
    if (value !== null) headers[name] = value
  }
  return {
    status: response.status,
    headers,
    bodyText: await response.text(),
  }
}
