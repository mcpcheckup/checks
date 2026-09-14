export interface ProbeBudget {
  /** Max redirect hops to follow before giving up (0 = the initial request only, no redirects). */
  maxRedirects: number
  /** Wall-clock budget for the whole guardedFetch call, including redirects, in ms. */
  maxDurationMs: number
  /** Max response body bytes read per hop before aborting. */
  maxBodyBytes: number
  /** Max outbound HTTP requests to the target across the whole call (does not count our
   *  own DoH lookups, which go to a fixed trusted resolver, not the target). */
  maxRequests: number
}

export const DEFAULT_PROBE_BUDGET: ProbeBudget = {
  maxRedirects: 3,
  maxDurationMs: 10_000,
  maxBodyBytes: 2_097_152,
  maxRequests: 8,
}

/** Both tiers get DEFAULT_PROBE_BUDGET unchanged. The halving that unclaimed
 *  targets used to get (4 requests) was withdrawn by the user's 2026-09-09
 *  ruling: a legacy-protocol round costs 5 requests at minimum
 *  (server/discover -> initialize -> notifications/initialized -> tools/list ->
 *  tools/call), so 4 could never finish one, and what it actually produced was
 *  UNVERIFIED rather than the intended courtesy. The claimed/unclaimed
 *  difference lives in probe frequency and signing, not in how completely a
 *  target gets probed.
 *
 *  `_opts` is kept in the signature — deliberately unread today — so the two
 *  tiers can diverge again without touching a single call site.
 *
 *  These numbers are this suite's PUBLISHED contract, not a private deployment
 *  threshold: checks.json's own `budget` field states the same values, and the
 *  reachability check's reader copy quotes them. (CLAUDE.md's packages/
 *  boundary rule keeps *allowlists and deployment configuration* out of this
 *  package; it has never applied to the budget, which every report page and
 *  every attestation consumer has to be able to read.) */
export function createProbeBudget(_opts: { claimed: boolean }): ProbeBudget {
  return { ...DEFAULT_PROBE_BUDGET }
}
