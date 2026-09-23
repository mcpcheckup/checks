// FROZEN: packages/checks/src/error-taxonomy.ts at suite 0.6.0 (a05097e), verbatim except that
// FROZEN: imports of files outside this directory go through ../../ instead of ./ .
// FROZEN: Test-only baseline for probe-tool-name-differential.test.ts, which checks
// FROZEN: its git blob id. DO NOT edit or "update" it; it is the 0.6.0 behaviour.
import { isSseContentType, jsonRpcCandidates, parseJsonRpcBody } from './protocol.ts'
import type { ParsedJsonRpc, ProbeCallResult } from './protocol.ts'

type Reason = { key: string; params?: Record<string, string | number> } | null

export type ErrorTaxonomyVerdict = { status: 'VERIFIED' } | { status: 'OBSERVED_RISK'; reason: Reason }

/** Judges error_taxonomy from the tools/call(unknown tool) response — the same
 *  response auth_metadata reads. A 401/403 is an HTTP-layer auth rejection that
 *  happens before JSON-RPC dispatch even runs; it says nothing about whether the
 *  server's *protocol-level* error shape is conformant, so it doesn't count
 *  against this check either way (see no-credentials-unverifiable-auth in
 *  @mcpcheckup/fixtures). Anything else must be a well-formed JSON-RPC error.
 *
 *  T73: the verdict itself is unchanged. Only the OBSERVED_RISK branch now
 *  records WHAT came back, as a bounded classification in the signed reason
 *  ref (see classifyUnknownToolResponse). */
export function judgeErrorTaxonomy(callResult: ProbeCallResult): ErrorTaxonomyVerdict {
  if (callResult.status === 401 || callResult.status === 403) {
    return { status: 'VERIFIED' }
  }
  const contentType = callResult.headers.get('content-type')
  const parsed = parseJsonRpcBody(callResult.bodyText, contentType)
  if (parsed.isJsonRpc && parsed.error) {
    return { status: 'VERIFIED' }
  }
  return { status: 'OBSERVED_RISK', reason: classifyUnknownToolResponse(callResult, contentType, parsed) }
}

/** The one scenario error_taxonomy triggers today (probe.ts's PROBE_TOOL_NAME
 *  call). Recorded so a future second scenario cannot be confused with it. */
const SCENARIO = 'tools_call_unknown_tool'

/** Media types recorded verbatim; every other Content-Type becomes 'other'
 *  and an absent/empty one 'none', so the recorded value is always one of six
 *  constants and never server-chosen text. */
const RECORDED_MEDIA_TYPES: ReadonlySet<string> = new Set(['application/json', 'text/event-stream', 'text/html', 'text/plain'])

type UnknownToolResponseClass =
  | 'empty_body'
  | 'event_stream_no_data'
  | 'result_is_error'
  | 'result_ok'
  | 'jsonrpc_malformed'
  | 'not_jsonrpc'
  | 'not_json'

export type ErrorTaxonomyReasonKey = `error_taxonomy_${UnknownToolResponseClass}`

function mediaTypeParam(contentType: string | null): string {
  if (contentType === null || contentType.trim() === '') return 'none'
  const essence = contentType.split(';', 1)[0]!.trim().toLowerCase()
  return RECORDED_MEDIA_TYPES.has(essence) ? essence : 'other'
}

type JsonParse = { ok: true; value: unknown } | { ok: false }
function parseJson(text: string): JsonParse {
  try {
    return { ok: true, value: JSON.parse(text) }
  } catch {
    return { ok: false }
  }
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Why the unknown-tool response is OBSERVED_RISK, as one of seven bounded
 * classes. Spec basis — MCP server/tools "Error Handling" (2025-06-18,
 * 2025-11-25 and 2026-07-28 all agree): "Unknown tool" is a Protocol Error,
 * answered as a JSON-RPC error (example code -32602); `result.isError: true` is
 * for Tool Execution Errors only.
 * https://modelcontextprotocol.io/specification/2026-07-28/server/tools#error-handling
 *
 * Classified over exactly the candidates the verdict parsed
 * (protocol.ts jsonRpcCandidates), first matching rule wins:
 *   1. empty_body           bodyText is zero-length (raw, before SSE handling;
 *                           whitespace-only is NOT empty)
 *   2. event_stream_no_data SSE Content-Type (the verdict's own
 *                           isSseContentType) and zero `data:` payloads
 *   3. result_is_error /    the first candidate the verdict accepted as
 *      result_ok            JSON-RPC carries `result`; result_is_error iff it
 *                           is a non-null object whose isError === true
 *   4. jsonrpc_malformed    some candidate is a JSON object with
 *                           jsonrpc === '2.0' (no result, no well-formed error)
 *   5. not_jsonrpc          some candidate parses as JSON at all
 *   6. not_json             anything else
 *
 * PARAMS ARE EVIDENCE AND GO INTO THE SIGNED RECORD, so every value is bounded
 * and none is third-party text: `scenario` (constant), `status` (the HTTP
 * status integer), `media_type` (one of six constants), and — only for
 * jsonrpc_malformed, only when the first jsonrpc-2.0 candidate's error.code is
 * a safe integer — `jsonrpc_error_code`. Never the body, never a message.
 */
function classifyUnknownToolResponse(
  callResult: ProbeCallResult,
  contentType: string | null,
  parsed: ParsedJsonRpc,
): { key: ErrorTaxonomyReasonKey; params: Record<string, string | number> } {
  const params: Record<string, string | number> = {
    scenario: SCENARIO,
    status: callResult.status,
    media_type: mediaTypeParam(contentType),
  }
  const reason = (cls: UnknownToolResponseClass) => ({ key: `error_taxonomy_${cls}` as const, params })

  // Rule 1.
  if (callResult.bodyText === '') return reason('empty_body')

  const candidates = jsonRpcCandidates(callResult.bodyText, contentType)

  // Rule 2: an event stream that carried no data events at all.
  if (isSseContentType(contentType) && candidates.length === 0) return reason('event_stream_no_data')

  // Rule 3. `parsed` is the verdict's own first-accepted candidate; on this
  // (OBSERVED_RISK) path an accepted candidate can only be a `result` one —
  // an accepted error would already have returned VERIFIED above.
  if (parsed.isJsonRpc) {
    const result = parsed.result
    return reason(typeof result === 'object' && result !== null && (result as Record<string, unknown>).isError === true ? 'result_is_error' : 'result_ok')
  }

  const values = candidates.map(parseJson)

  // Rule 4.
  const selfDeclared = values.find(
    (v): v is { ok: true; value: Record<string, unknown> } => v.ok && isJsonObject(v.value) && v.value.jsonrpc === '2.0',
  )
  if (selfDeclared !== undefined) {
    const error = selfDeclared.value.error
    const code = isJsonObject(error) ? error.code : undefined
    // `code === 0 ? 0 : code` folds -0 into 0: the canonicalizer already
    // signs -0 as "0", so the in-memory value must say the same thing.
    if (Number.isSafeInteger(code)) params.jsonrpc_error_code = (code as number) === 0 ? 0 : (code as number)
    return reason('jsonrpc_malformed')
  }

  // Rule 5 / 6.
  return reason(values.some((v) => v.ok) ? 'not_jsonrpc' : 'not_json')
}
