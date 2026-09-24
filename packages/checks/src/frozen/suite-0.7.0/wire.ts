// FROZEN: packages/checks/src/wire.ts at suite 0.7.0 (c76de46), verbatim except that
// FROZEN: imports of files outside this directory go through ../../ instead of ./ .
// FROZEN: Test-only baseline for wire-budget-differential.test.ts, which checks
// FROZEN: its git blob id. DO NOT edit or "update" it; it is the 0.7.0 behaviour.
import type { FetchLike, GuardSignals, ProbeBudget } from '../../types.ts'

export type ProbeAbortedCode = 'MAX_REQUESTS' | 'MAX_DURATION' | 'MAX_BODY_BYTES' | 'MAX_REDIRECTS' | 'RATE_LIMITED'

/** Thrown by anything in this package that hits the run's global budget, or by
 *  the rate-limit stop below. Caught exactly once, at the top of probe.ts's
 *  orchestrator — see its module comment for what an abort does and does not
 *  revise (in particular, since T6.9-F it cannot revise a `reachability` the
 *  handshake had already settled).
 *
 *  ProbeAbortedCode is a closed union on purpose: probe.ts indexes an object
 *  literal by `e.code` to pick the reason key, so adding a member here fails to
 *  typecheck until that table is completed. Deny-by-default — never widen that
 *  lookup with a `?? fallback`. */
export class ProbeAborted extends Error {
  code: ProbeAbortedCode
  details: Record<string, number>
  /** Only ever set for code === 'RATE_LIMITED', and only when the target sent a
   *  parseable delay-seconds Retry-After. A typed field rather than a lookup in
   *  `details`: the scheduler acts on this value (it defers next_run_at), and a
   *  control signal must not be reachable only through the same stringly-keyed
   *  bag that feeds reader copy — the same reasoning that keeps it out of an
   *  assertion's reason.params (see probe.ts's params-channel comment). */
  retryAfterSeconds?: number
  constructor(code: ProbeAbortedCode, message: string, details: Record<string, number>, retryAfterSeconds?: number) {
    super(message)
    this.name = 'ProbeAborted'
    this.code = code
    this.details = details
    // exactOptionalPropertyTypes: assign only when there is a real value, so
    // the property is absent rather than present-with-undefined.
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds
  }
}

export interface ProbeContext {
  requestCount: number
  startedAtMs: number
  redirectCrossHostObserved: boolean
  dnsAnswerChangedObserved: boolean
}

/** startedAtMs is passed in by the caller rather than read here via a bare
 *  Date.now() — wire.ts stays a pure function of its inputs. Deliberately NOT
 *  derived from ProbeInput.now(): that clock exists to make OUTPUT timestamps
 *  reproducible (tests fix it to a constant string), while startedAtMs feeds
 *  the *real* wall-clock budget checks below (`Date.now() - ctx.startedAtMs`),
 *  which must track actual elapsed time regardless of what now() returns —
 *  conflating the two would make a fixed test clock either spuriously trip
 *  MAX_DURATION (if it's stale relative to real time) or make the duration
 *  budget silently unenforceable (if every check used the same frozen value).
 *  startedAtMs itself never appears in any output, so this doesn't affect the
 *  byte-determinism guarantee tied to now()/newId(). */
export function createProbeContext(startedAtMs: number): ProbeContext {
  return { requestCount: 0, startedAtMs, redirectCrossHostObserved: false, dnsAnswerChangedObserved: false }
}

export interface WireResponse {
  status: number
  headers: Headers
  bodyText: string
  finalUrl: string
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

/** Retry-After is `delay-seconds` (a non-negative integer) OR an HTTP-date
 *  (RFC 9110 §10.2.3 — the one place in this repo that clause number is
 *  written out). Only the delay-seconds form is parsed, and only when it is a
 *  non-negative safe integer: this value is entirely third-party-controlled and
 *  it flows both into a signed reason.params and into the scheduler's
 *  next_run_at arithmetic, so an unbounded, non-decimal or non-finite value is
 *  refused outright rather than coerced into something that merely looks
 *  parsed. `Number()` alone is not enough — it accepts '0x10', '1e3' and
 *  ' 3600 ' — hence the explicit digits-only token test; a 310-digit run of
 *  digits passes that test but becomes Infinity, which the safe-integer check
 *  then rejects.
 *
 *  Returning undefined never weakens the decision to stop: presence of the
 *  header (not its parseability) is what makes a 503 a rate-limit signal, and
 *  429 stops unconditionally. An unparseable value costs the caller only the
 *  "how long" hint, which the scheduler then treats as "no hint given". */
export function parseRetryAfterSeconds(raw: string | null): number | undefined {
  if (raw === null) return undefined
  const token = raw.trim()
  if (!/^[0-9]+$/.test(token)) return undefined
  const seconds = Number(token)
  return Number.isSafeInteger(seconds) ? seconds : undefined
}

/** The target has told us to come back later. 429 is unconditional — a server
 *  that just said "you are asking too often" must not be asked again in the
 *  same round, and in particular must never be followed by protocol.ts's legacy
 *  `initialize` fallback. 503 is deliberately NOT unconditional: Service
 *  Unavailable with no Retry-After is far more often a transient fault than an
 *  expression of rate-limiting intent, so it keeps its existing path entirely
 *  (normal judgment, normal interval, normal registration). A 503 that DOES
 *  carry Retry-After has named a time to come back and is treated exactly like
 *  429. Presence of the header is the 503 trigger, not whether we could parse
 *  it — a server that says "come back later, at <unparseable>" has still said
 *  "come back later".
 *
 *  Returns the abort instead of throwing it so the decision and the throw sit
 *  in the caller's loop, next to the other budget checks. */
function rateLimitAbort(response: Response): ProbeAborted | undefined {
  const retryAfterRaw = response.headers.get('retry-after')
  const isRateLimited = response.status === 429 || (response.status === 503 && retryAfterRaw !== null)
  if (!isRateLimited) return undefined
  const retryAfterSeconds = parseRetryAfterSeconds(retryAfterRaw)
  return new ProbeAborted(
    'RATE_LIMITED',
    `目标返回 HTTP ${response.status}，要求我们稍后再来；本轮停止对该目标的一切后续请求`,
    { status: response.status, ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}) },
    retryAfterSeconds,
  )
}

async function readBodyWithBudget(response: Response, maxBodyBytes: number): Promise<string> {
  const declared = response.headers.get('content-length')
  if (declared !== null) {
    const declaredBytes = Number(declared)
    if (declaredBytes > maxBodyBytes) {
      // declaredBytes is parsed from a third-party-controlled header — an
      // extreme digit string (e.g. 310 nines, or "1e400") parses to Infinity,
      // which packages/canonicalizer rejects (NON_FINITE_NUMBER) once this
      // reaches an assertion's reason.params and gets canonicalized for
      // signing. Only include it when finite — maxBodyBytes alone is always
      // sufficient for reason-messages.ts's renderer, so omitting a
      // non-finite declaredBytes costs the reader no information, only an
      // occasionally-untrustworthy diagnostic extra.
      throw new ProbeAborted(
        'MAX_BODY_BYTES',
        `响应体 Content-Length (${declared}) 超过 ${maxBodyBytes} 字节的预算`,
        { ...(Number.isFinite(declaredBytes) ? { declaredBytes } : {}), maxBodyBytes },
      )
    }
  }
  const text = await response.text()
  const actualBytes = new TextEncoder().encode(text).length
  if (actualBytes > maxBodyBytes) {
    throw new ProbeAborted('MAX_BODY_BYTES', `响应体实际大小 (${actualBytes} 字节) 超过 ${maxBodyBytes} 字节的预算`, { actualBytes, maxBodyBytes })
  }
  return text
}

/** Sends one logical request, following same- or cross-host redirects (recording
 *  cross-host ones) up to budget.maxRedirects, enforcing the run's request-count /
 *  wall-clock / body-size budget at every hop, and collecting GuardSignals fetchImpl
 *  reports out-of-band on every call along the way. Every dimension of the global
 *  probe budget (packages/checks/checks.json's `budget`) is enforced here, in one
 *  place, so no individual check has to reimplement budget accounting.
 *
 *  Redirect-following only ever applies to GET. Every real wire call this package
 *  makes is POST (see protocol.ts) — a POST that gets 3xx'd is never re-issued
 *  against the Location target; that response becomes this call's terminal result
 *  instead (same as any non-redirect status), with redirectCrossHostObserved still
 *  set when the Location crosses hosts, so the observation isn't silently lost. This
 *  is the same rule @mcpcheckup/ssrf-guard's guardedFetch enforces independently one
 *  layer below (see that package's README, "Non-GET does not follow redirects") —
 *  re-derived here rather than centralized into one shared signal between the two
 *  packages, on purpose: two layers each independently refusing to replay a POST's
 *  method/headers/body (including `authorization`) cross-host is depth-of-defense;
 *  a single shared decision point just moves the "what if this layer forgets" risk
 *  to one place instead of removing it. This duplication was prompted by an
 *  internally-tracked credential-replay finding; the reasoning for not
 *  centralizing it is stated above. */
export async function sendRequest(
  fetchImpl: FetchLike,
  url: string,
  init: RequestInit,
  budget: ProbeBudget,
  ctx: ProbeContext,
): Promise<WireResponse> {
  const originalHostname = new URL(url).hostname
  const method = (init.method ?? 'GET').toUpperCase()
  let currentUrl = url
  let hop = 0

  const onGuardSignal = (signals: GuardSignals) => {
    if (signals.dnsAnswerChanged) ctx.dnsAnswerChangedObserved = true
  }

  for (;;) {
    if (Date.now() - ctx.startedAtMs > budget.maxDurationMs) {
      throw new ProbeAborted('MAX_DURATION', `探测已超过 ${budget.maxDurationMs}ms 的总预算`, { maxDurationMs: budget.maxDurationMs })
    }
    if (ctx.requestCount >= budget.maxRequests) {
      throw new ProbeAborted('MAX_REQUESTS', `探测已达到 ${budget.maxRequests} 次请求的总预算`, { maxRequests: budget.maxRequests })
    }
    ctx.requestCount++
    const response = await fetchImpl(currentUrl, init, onGuardSignal)

    // Checked before anything else this response could lead to — before the
    // redirect hop, before the body is even read. Throwing here is what makes
    // "zero further requests to this target this round" structural rather than
    // a promise each caller has to keep: fetchImpl is the package's only
    // outbound seam (enforced by no-direct-fetch.test.ts) and sendRequest is
    // the only place it is called, so an abort raised here propagates past
    // every remaining wire call to probe.ts's single catch.
    const rateLimited = rateLimitAbort(response)
    if (rateLimited) throw rateLimited

    if (REDIRECT_STATUSES.has(response.status)) {
      const location = response.headers.get('location')
      if (location && method === 'GET') {
        hop++
        if (hop > budget.maxRedirects) {
          throw new ProbeAborted('MAX_REDIRECTS', `重定向跳数超过 ${budget.maxRedirects} 的预算`, { maxRedirects: budget.maxRedirects })
        }
        const nextUrl = new URL(location, currentUrl)
        if (nextUrl.hostname !== originalHostname) ctx.redirectCrossHostObserved = true
        currentUrl = nextUrl.href
        continue
      }
      if (location && method !== 'GET') {
        const nextUrl = new URL(location, currentUrl)
        if (nextUrl.hostname !== originalHostname) ctx.redirectCrossHostObserved = true
      }
    }

    const bodyText = await readBodyWithBudget(response, budget.maxBodyBytes)
    return { status: response.status, headers: response.headers, bodyText, finalUrl: currentUrl }
  }
}
