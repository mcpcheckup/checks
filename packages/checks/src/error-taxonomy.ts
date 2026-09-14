import { parseJsonRpcBody } from './protocol.ts'
import type { ProbeCallResult } from './protocol.ts'

type Reason = { key: string; params?: Record<string, string | number> } | null

export type ErrorTaxonomyVerdict = { status: 'VERIFIED' } | { status: 'OBSERVED_RISK'; reason: Reason }

/** Judges error_taxonomy from the tools/call(unknown tool) response — the same
 *  response auth_metadata reads. A 401/403 is an HTTP-layer auth rejection that
 *  happens before JSON-RPC dispatch even runs; it says nothing about whether the
 *  server's *protocol-level* error shape is conformant, so it doesn't count
 *  against this check either way (see no-credentials-unverifiable-auth in
 *  @mcpcheckup/fixtures). Anything else must be a well-formed JSON-RPC error. */
export function judgeErrorTaxonomy(callResult: ProbeCallResult): ErrorTaxonomyVerdict {
  if (callResult.status === 401 || callResult.status === 403) {
    return { status: 'VERIFIED' }
  }
  const parsed = parseJsonRpcBody(callResult.bodyText, callResult.headers.get('content-type'))
  if (parsed.isJsonRpc && parsed.error) {
    return { status: 'VERIFIED' }
  }
  return { status: 'OBSERVED_RISK', reason: { key: 'error_taxonomy_risk' } }
}
