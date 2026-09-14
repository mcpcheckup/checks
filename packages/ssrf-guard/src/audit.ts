import type { ResolvedAddress } from './resolve.ts'

export type ProbeOutcome = 'success' | 'blocked' | 'budget_exceeded' | 'rate_limited' | 'network_error'

export interface ProbeHopRecord {
  hostname: string
  /** Empty for an IP-literal target — nothing was resolved because there was nothing to resolve. */
  resolvedAddresses: ResolvedAddress[]
  status: number | null
}

/**
 * What to record for every probe an unauthenticated caller triggers — the home page's
 * instant-try is the one unauthenticated fan-out point in the whole product (see
 * CLAUDE.md), so every attempt needs a trail, not just the ones that succeed. This
 * package only defines the shape; persistence is the caller's job (see README).
 */
export interface ProbeAuditRecord {
  triggeredAt: string
  callerIdentifier: string
  targetHost: string
  hops: ProbeHopRecord[]
  hopCount: number
  outcome: ProbeOutcome
  blockedReason: string | null
  /** See README "Detecting a DNS answer that changed mid-probe" — true means at least one
   *  hop's post-fetch re-resolution didn't match what we validated before fetching. The
   *  caller must not let a run with this set to true feed the publish pipeline. */
  dnsAnswerChangedDuringProbe: boolean
  /** See README "Non-GET does not follow redirects" — true when a non-GET request's
   *  final response was itself a cross-host redirect guardedFetch declined to follow,
   *  or when a GET redirect chain crossed hosts at least once. */
  redirectCrossHostObserved: boolean
}
