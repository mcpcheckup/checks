import { RateLimited } from './errors.ts'

/**
 * The axes a caller might rate-limit on. This package does not implement any of them —
 * actual limits, storage (Durable Objects, KV, ...), and thresholds are deployment
 * config (see CLAUDE.md's packages/ boundary). What lives here is the *shape* of the
 * decision guardedFetch requires before it will touch the network at all: IP validation
 * alone does not stop abuse (a valid public target can still be hammered or used to
 * amplify traffic), rate limiting is what actually bounds that — see README.
 */
export type RateLimitScope = 'caller_ip' | 'target_host' | 'global_concurrency'

export interface RateLimitDecision {
  allowed: boolean
  /** Which axes were evaluated to produce this decision — for audit records, not enforcement. */
  scope: RateLimitScope[]
  reason?: string
}

/**
 * Fails closed: guardedFetch must be handed an already-computed decision — it does not
 * calculate one itself — and if that decision is missing, malformed, or says no, this
 * throws. There is no path where "the caller forgot to rate-limit" quietly becomes
 * "request allowed".
 */
export function assertRateLimitAllowed(decision: RateLimitDecision | null | undefined): void {
  if (!decision || decision.allowed !== true) {
    throw new RateLimited(
      'RATE_LIMITED',
      decision?.reason ?? 'no allowing rate-limit decision was supplied (default is deny)',
    )
  }
}
