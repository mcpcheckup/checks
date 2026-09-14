/**
 * The four-state model (see CLAUDE.md): execution_status and assertion_status are
 * independent axes, never merged into one boolean. A fixture declares both explicitly
 * for every assertion a correct detector run against it must produce.
 */
export type ExecutionStatus = 'COMPLETED' | 'ERROR' | 'SKIPPED' | 'BLOCKED'
export type AssertionStatus = 'VERIFIED' | 'FAILED' | 'OBSERVED_RISK' | 'UNVERIFIED'

export interface Reason {
  key: string
  params: Record<string, string | number>
}

export interface ExpectedAssertion {
  /** Must exist in packages/checks/checks.json — enforced by a cross-consistency test. */
  check_id: string
  execution_status: ExecutionStatus
  assertion_status: AssertionStatus
  /** Required, and enforced by a test, whenever assertion_status is UNVERIFIED. */
  reason?: Reason
}

export type FetchHandler = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export interface ResponseSummary {
  status: number
  /** Only headers meaningful to protocol/security checks — anything with real-clock
   *  timestamps, random boundary strings, etc. is deliberately excluded so two runs of
   *  the same fixture produce byte-identical summaries. */
  headers: Record<string, string>
  bodyText: string
}

export interface Fixture {
  id: string
  /** One sentence: what this simulates. */
  description: string
  /** The protocol revision this fixture simulates, or null when the fixture is
   *  deliberately about a server whose revision can't be identified at all. */
  protocolRevision: string | null
  kind: 'positive' | 'negative'
  /** Which misjudgment this fixture exists to catch. Required for every fixture, not
   *  just negative ones — a positive fixture also guards against a specific false
   *  failure, and that reasoning belongs here, not left implicit. */
  guardsAgainst: string
  expectedAssertions: ExpectedAssertion[]
  /** The raw tool objects this fixture's `tools/list` returns, when it has one — used
   *  by cross-checks that recompute toolset_fingerprint / schema_fingerprint /
   *  tool_description_hygiene with the real production logic (projectToolset,
   *  projectSchemas, runHygieneCheck) and confirm the result actually matches what
   *  expectedAssertions declares, rather than trusting a hand-typed assertion status. */
  tools?: unknown[]
  /** Returns a fresh handler with its own isolated internal state (e.g. session
   *  tracking for a legacy handshake). Never share a handler instance across two
   *  separate "runs" of a fixture — that would make the second run see state left
   *  over from the first and break the determinism guarantee. */
  createHandler: () => FetchHandler
  /** Drives a fresh handler through this fixture's natural request sequence and
   *  returns each response's deterministic summary, in order. Used to (a) prove the
   *  fixture itself is deterministic — run it twice, compare canonical bytes — and
   *  (b) as a runnable, self-documenting example of the exact traffic this fixture
   *  expects. */
  sampleRun: (handler: FetchHandler) => Promise<ResponseSummary[]>
}
