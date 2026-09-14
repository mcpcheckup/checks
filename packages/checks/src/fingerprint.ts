import { digest, projectToolset, projectSchemas } from '@mcpcheckup/canonicalizer'
import type { ToolSnapshot, ToolSnapshotEntry } from './types.ts'

export type FingerprintVerdict = { status: 'VERIFIED'; fingerprint: string } | { status: 'FAILED'; reason: string }

/** toolset_fingerprint / schema_fingerprint only judge "can we compute a
 *  canonical fingerprint at all" (checks.json: "算得出就是 VERIFIED") — a thrown
 *  error from canonicalizer (a tool missing its "name", or projectSchemas
 *  producing an `inputSchema: undefined` that canonicalize() can't represent) is
 *  itself the determinate FAILED fact, not something to paper over. */
export async function computeToolsetFingerprint(tools: unknown[]): Promise<FingerprintVerdict> {
  try {
    return { status: 'VERIFIED', fingerprint: await digest(projectToolset(tools)) }
  } catch (e) {
    return { status: 'FAILED', reason: e instanceof Error ? e.message : String(e) }
  }
}

export async function computeSchemaFingerprint(tools: unknown[]): Promise<FingerprintVerdict> {
  try {
    return { status: 'VERIFIED', fingerprint: await digest(projectSchemas(tools)) }
  } catch (e) {
    return { status: 'FAILED', reason: e instanceof Error ? e.message : String(e) }
  }
}

function toolName(tool: unknown): string | null {
  if (typeof tool === 'object' && tool !== null && typeof (tool as { name?: unknown }).name === 'string') {
    return (tool as { name: string }).name
  }
  return null
}

/** PRD §5.12.3's retention snapshot. Each tool's own hash is computed
 *  independently (catching a per-tool failure without losing the rest of the
 *  snapshot) — a richer, more diagnostic record than the two aggregate
 *  fingerprints alone, which only say "computable at all," not "which tool". */
export async function buildToolSnapshot(tools: unknown[], observedAt: string): Promise<ToolSnapshot> {
  const toolsetResult = await computeToolsetFingerprint(tools)
  const schemaResult = await computeSchemaFingerprint(tools)

  const entries: ToolSnapshotEntry[] = []
  for (const tool of tools) {
    const name = toolName(tool)
    const description = typeof (tool as { description?: unknown })?.description === 'string' ? (tool as { description: string }).description : null
    const inputSchema = (tool as { inputSchema?: unknown })?.inputSchema
    let hash: string | null = null
    if (name !== null) {
      try {
        hash = await digest({ name, inputSchema })
      } catch {
        hash = null
      }
    }
    entries.push({ name: name ?? '', description, inputSchema, hash })
  }

  return {
    observed_at: observedAt,
    toolset_fingerprint: toolsetResult.status === 'VERIFIED' ? toolsetResult.fingerprint : null,
    schema_fingerprint: schemaResult.status === 'VERIFIED' ? schemaResult.fingerprint : null,
    tools: entries,
  }
}
