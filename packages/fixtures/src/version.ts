import { canonicalize } from '@mcpcheckup/canonicalizer'
import type { Fixture } from './types.ts'

/**
 * Bump this whenever a fixture's expectedAssertions change in a way that would change
 * what a correct detector must produce for it — not for prose-only edits (description,
 * guardsAgainst) that don't change the spec itself. See README.
 */
export const FIXTURE_CORPUS_VERSION = 'v20'

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * A digest of the corpus's normative content only (id + protocolRevision + kind +
 * expectedAssertions) — not the handler implementations or prose. Order-independent:
 * fixtures are sorted by id before hashing, so reordering the corpus array doesn't
 * change the digest. Intended use: an attestation can record "this conclusion was
 * produced by a detector verified against fixture corpus vX @ <digest>", so a future
 * change to what the fixtures expect is visible even if FIXTURE_CORPUS_VERSION itself
 * isn't bumped for some reason.
 */
export async function corpusDigest(corpus: Fixture[]): Promise<string> {
  const normative = corpus
    .map((f) => ({
      id: f.id,
      protocolRevision: f.protocolRevision,
      kind: f.kind,
      expectedAssertions: f.expectedAssertions,
    }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  const bytes = new TextEncoder().encode(canonicalize({ version: FIXTURE_CORPUS_VERSION, fixtures: normative }))
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
  return 'sha256:' + toHex(hashBuffer)
}
