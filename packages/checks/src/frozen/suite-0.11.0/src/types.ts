import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import type { ChecksRegistry } from './registry.ts'

export type { ProbeBudget }

/** Signals about the underlying transport that must never travel through the
 *  target's own Response — the target fully controls its response (status,
 *  headers, body), so anything read off it cannot be trusted as a security
 *  signal about the target. Reported instead via the onGuardSignal callback
 *  fetchImpl receives, which the target has no way to reach or influence. */
export interface GuardSignals {
  /** True when @mcpcheckup/ssrf-guard's guardedFetch() re-resolved the target
   *  hostname after fetching and got a different DNS answer than the one it
   *  validated before the request (its dnsAnswerChangedDuringProbe). Computed
   *  entirely from the adapter's own resolver calls. */
  dnsAnswerChanged?: boolean
}

/** What sendRequest (wire.ts) tells every call it makes (TODO 458). */
export interface FetchCallOptions {
  /** The time left in the run's aggregate duration budget when this call was
   *  made, in ms: always > 0 and ≤ budget.maxDurationMs. sendRequest's own
   *  timer, set to that deadline, ends the call if it is still running when
   *  the timer fires, whatever the implementation does; nothing the call
   *  produces after that is read. An implementation
   *  that also enforces it should give up no EARLIER than that (the production
   *  adapter gives guardedFetch timeoutMs plus a grace): a failure of its own
   *  that beats sendRequest's timer is reported as that failure, not as the
   *  budget running out. */
  timeoutMs: number
}

/** The sole outbound-network seam this package uses. Almost structurally
 *  identical to the fetch API itself (and to @mcpcheckup/fixtures' FetchHandler)
 *  so a fixture's createHandler() drops in for tests with zero adapter code —
 *  fixtures ignore the third and fourth parameters and TypeScript accepts that
 *  (a function with fewer declared parameters is assignable to a type
 *  expecting more). A wrapper around another FetchLike must forward all four. In
 *  production the caller is expected to supply an adapter over
 *  @mcpcheckup/ssrf-guard's guardedFetch() that reconstructs a plain Response —
 *  this package never calls guardedFetch itself (see the source-scan test in
 *  no-direct-fetch.test.ts and the dependency note in README.md). That adapter
 *  reports guardedFetch's out-of-band GuardSignals (e.g.
 *  dnsAnswerChangedDuringProbe) by calling onGuardSignal directly — never by
 *  encoding them into the Response it returns, since the target controls that
 *  Response completely. */
export type FetchLike = (
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  onGuardSignal: (signals: GuardSignals) => void,
  options?: FetchCallOptions,
) => Promise<Response>

export type EvidenceProvenance = 'INDEPENDENTLY_OBSERVED' | 'SELF_ATTESTED' | 'STATICALLY_ANALYZED'

export interface RemoteProbeTarget {
  slug: string
  transport: 'remote'
  endpointUrl: string
  packageRef?: undefined
}

export interface StdioProbeTarget {
  slug: string
  transport: 'stdio'
  endpointUrl?: undefined
  packageRef: string
}

export type ProbeTarget = RemoteProbeTarget | StdioProbeTarget

/** The minimum needed to judge drift against a prior, human-approved publication.
 *  Anything richer (who approved it, when) is the caller's storage concern. */
export interface ApprovedBaseline {
  toolset_fingerprint: string
  schema_fingerprint: string
}

export interface ProbeInput {
  target: ProbeTarget
  fetchImpl: FetchLike
  budget: ProbeBudget
  /** Injected clock — every timestamp this package emits comes from here, never
   *  from a bare `new Date()`, so a fixture + fixed clock reproduces byte-identical
   *  output. Must return RFC3339 UTC, millisecond precision, literal 'Z' offset
   *  (exactly what Date.prototype.toISOString() produces) to match
   *  attestation-schema's Timestamp format. */
  now: () => string
  /** Injected id generator — same determinism reasoning as `now`. */
  newId: () => string
  /** Absent => comparison checks (toolset_unchanged_vs_approved /
   *  schema_unchanged_vs_approved) are UNVERIFIED, not FAILED. */
  approvedBaseline?: ApprovedBaseline
  provenance: EvidenceProvenance
  registry: ChecksRegistry
}

export interface ToolSnapshotEntry {
  name: string
  description: string | null
  inputSchema: unknown
  /** digest() of this one tool's {name, inputSchema} — null when this individual
   *  tool's schema can't be canonicalized (e.g. a missing inputSchema key), which
   *  is recorded without failing the whole snapshot. */
  hash: string | null
}

/** PRD §5.12.3's retention requirement: recorded on every run, claimed or not,
 *  because it cannot be captured retroactively. */
export interface ToolSnapshot {
  observed_at: string
  toolset_fingerprint: string | null
  schema_fingerprint: string | null
  tools: ToolSnapshotEntry[]
}

export interface DriftEvent {
  check_id: 'toolset_unchanged_vs_approved' | 'schema_unchanged_vs_approved'
  previous_fingerprint: string
  current_fingerprint: string
  detected_at: string
}

export interface ProbeResult {
  assertions: Assertion[]
  toolSnapshot?: ToolSnapshot
  driftEvents: DriftEvent[]
  /** Present only when this run must not enter the publication flow (e.g. a
   *  DNS-rebind observed mid-probe) — recorded as risk evidence only. No more
   *  nested `.reason`; the object itself IS the key+params reason ref (same
   *  shape as an Assertion's `reason`/`unverified_reason`), resolved against
   *  REASON_MESSAGES by the reader, never rendered as prose here. */
  disqualifiedFromPublication?: { key: string; params?: Record<string, string | number> }
  /** Whether this run's outbound requests observed the target hostname's DNS
   *  answer change mid-probe — a condition of this run, not a judgment about
   *  the target (many healthy endpoints legitimately return different DNS
   *  answers across requests: round-robin, CDN edge selection, failover), so
   *  it is deliberately not a check_id and never affects any assertion's
   *  assertion_status. Maps to @mcpcheckup/attestation-schema's
   *  AttestationPayload.probe_dns_answer_changed — kept as its own field so a
   *  caller never has to infer this specific network condition from
   *  disqualifiedFromPublication, whose reasons may broaden later. null for
   *  a `stdio` target (no DNS resolution to observe); a real boolean for
   *  `remote`, always present once a run reaches that path (regardless of
   *  whether the run later aborts). */
  dnsAnswerChangedObserved: boolean | null
  /** The protocol revision string the target actually declared during handshake
   *  (e.g. '2026-07-28'), independent of whether it matched checks.json's
   *  revision_matrix — that judgment is protocol_revision's assertion_status,
   *  this is the raw observed value a caller needs to build a signed record of
   *  what was actually seen. null when no handshake ever produced a declared
   *  version: stdio transport, or a remote run that errored before the
   *  handshake step. */
  protocolRevisionDeclared: string | null
  /** Present ONLY when this run stopped because the target told us to come back
   *  later — HTTP 429, or 503 carrying a Retry-After (see wire.ts's
   *  rateLimitAbort for why 503 without Retry-After is deliberately excluded).
   *  Its presence is the entire signal; there is no "false" value to check.
   *
   *  This is a narrow, typed control channel on purpose. The same run also
   *  produces a reachability assertion whose reason.params happens to carry the
   *  same numbers, but reason.params is the localized-copy rendering channel —
   *  a caller that read the retry delay back out of it would let a copy edit
   *  silently change probe cadence. Callers that schedule repeated runs read
   *  this field; callers that only run a single ad-hoc probe ignore it.
   *
   *  retryAfterSeconds is null when the target named no delay we could use: a
   *  429 with no Retry-After at all, or a Retry-After we refused to parse (an
   *  HTTP-date, or a value outside the safe-integer range — see
   *  wire.ts's parseRetryAfterSeconds). Null means "come back later, unspecified
   *  when", never "come back immediately". */
  rateLimited?: { retryAfterSeconds: number | null }
}
