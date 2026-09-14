import { parseGuardedTarget } from './url-target.ts'
import { classifyIp } from './ip-policy.ts'
import { resolveAndValidateHost, resolveHost, type ResolvedAddress } from './resolve.ts'
import { assertRateLimitAllowed, type RateLimitDecision } from './rate-limit.ts'
import type { ProbeBudget } from './budget.ts'
import { createSafeResponseHandle, type SafeResponseHandle } from './response-view.ts'
import { SsrfBlocked, BudgetExceeded, RateLimited } from './errors.ts'
import type { ProbeAuditRecord, ProbeHopRecord, ProbeOutcome } from './audit.ts'

export interface GuardedFetchOptions<T> {
  callerIdentifier: string
  parseResponse: (handle: SafeResponseHandle) => T | Promise<T>
  onAudit?: (record: ProbeAuditRecord) => void
  fetchImpl?: typeof fetch
  resolveAndValidateHostImpl?: (hostname: string) => Promise<ResolvedAddress[]>
  resolveHostImpl?: (hostname: string) => Promise<ResolvedAddress[]>
  /** Defaults to GET. Only GET and POST are accepted — the prober never needs
   *  anything else — anything else throws SsrfBlocked('METHOD_NOT_ALLOWED', ...). */
  method?: 'GET' | 'POST'
  /** Checked against a fixed allowlist (see ALLOWED_HEADERS below), case-insensitively,
   *  before any network access. An allowlist, not a blocklist, because a blocklist can
   *  always miss a header; an allowlist that's missing one only needs a line added. */
  headers?: Record<string, string>
  /** Only allowed when method is 'POST' — throws SsrfBlocked('BODY_REQUIRES_POST', ...)
   *  otherwise. Its byte length is checked against budget.maxBodyBytes before any
   *  network access — the same budget dimension response bodies are checked against
   *  (see response-view.ts), not a separate one. */
  body?: string | Uint8Array
}

export interface GuardedFetchResult<T> {
  result: T
  status: number
  finalUrl: string
  hops: ProbeHopRecord[]
  dnsAnswerChangedDuringProbe: boolean
  /** See "Non-GET does not follow redirects" in the README. True when a non-GET
   *  request's final response is itself a redirect (3xx + Location) whose Location
   *  points at a different host than the request that produced it — meaning
   *  guardedFetch deliberately stopped rather than replaying the method/headers/body
   *  at a host that never agreed to receive them. Also true (independently) whenever
   *  a GET redirect chain crosses hosts, since that's the same fact the "strip
   *  authorization across hosts" rule below reacts to. Always false when the whole
   *  call never crossed a host boundary. */
  redirectCrossHostObserved: boolean
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

/**
 * Only headers the prober actually sends, verified against every real call site in
 * @mcpcheckup/checks (src/protocol.ts, src/auth.ts) — not just the 5 this task's brief
 * suggested. `mcp-method` and `mcp-name` are the modern (2026-07-28) handshake's own
 * routing headers (see protocol.ts's modernHeaders()); omitting them from the allowlist
 * would make guardedFetch reject the modern discover/tools-list/tools-call requests this
 * whole task exists to unblock. `authorization` has no real call site yet — it's here for
 * future authenticated probing, per the brief. Deliberately an allowlist, not a
 * blocklist: a blocklist can always miss a header we didn't think of; an allowlist
 * that's missing one the prober later needs only costs adding a line.
 *
 * `user-agent` added for L2b (the probing-etiquette step of that round's plan):
 * production probing now identifies itself as `MCPCheckup-Probe/1.0
 * (+https://mcpcheckup.com/probe)` so a target operator can look up why
 * they're receiving requests. This is a T1-level security-boundary change
 * (widening what a caller may send through the SSRF guard), hence its own
 * commit — see that commit's message. Being in this allowlist only means
 * guardedFetch permits the header through; it says nothing about WHAT value
 * gets sent — the calling prober's own wire-adapter layer is what fixes the
 * value to that one constant and overrides anything a caller tries to pass,
 * so the actual UA string sent over the wire can never be target- or
 * config-driven even though this allowlist entry exists.
 */
const ALLOWED_HEADERS = new Set([
  'accept',
  'authorization',
  'content-type',
  'mcp-method',
  'mcp-name',
  'mcp-protocol-version',
  'mcp-session-id',
  'user-agent',
])

function validateAndNormalizeHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!headers) return out
  for (const [rawKey, value] of Object.entries(headers)) {
    const key = rawKey.toLowerCase()
    if (!ALLOWED_HEADERS.has(key)) {
      throw new SsrfBlocked(
        'HEADER_NOT_ALLOWED',
        `header ${JSON.stringify(rawKey)} is not in the allowlist (${[...ALLOWED_HEADERS].sort().join(', ')})`,
      )
    }
    out[key] = value
  }
  return out
}

/** `authorization` must never survive a hop that crosses hosts — see "authorization
 *  never crosses a host" in the README. Every other allowlisted header is unaffected;
 *  this is a narrow, named strip, not a general "clear headers on redirect" policy. */
function stripAuthorization(headers: Record<string, string>): Record<string, string> {
  if (!('authorization' in headers)) return headers
  const { authorization: _drop, ...rest } = headers
  return rest
}

/** Never throws — an unparseable Location on a redirect we're declining to follow
 *  doesn't block anything (we're not going there), but per this package's "fail toward
 *  flagging it as evidence" rule (see checkDnsAnswerChanged below), an unparseable
 *  target counts as cross-host rather than silently reporting false. */
function isCrossHostRedirect(location: string, base: URL, currentHostname: string): boolean {
  try {
    return new URL(location, base).hostname !== currentHostname
  } catch {
    return true
  }
}

function addressSetKey(addresses: ResolvedAddress[]): string {
  return addresses
    .map((a) => `${a.family}:${a.ip}`)
    .sort()
    .join(',')
}

/** Re-resolves hostname after the real fetch and compares to what we validated before
 *  it. Never throws — a re-resolution failure counts as "changed" (fail toward flagging
 *  it as evidence, not toward silently assuming nothing happened). Does not use the
 *  validating resolver: a post-fetch answer that is itself now bad is exactly the kind
 *  of change we want to surface, not have swallowed by a policy rejection. */
async function checkDnsAnswerChanged(
  hostname: string,
  preAddresses: ResolvedAddress[],
  resolveHostImpl: (hostname: string) => Promise<ResolvedAddress[]>,
): Promise<boolean> {
  try {
    const postAddresses = await resolveHostImpl(hostname)
    return addressSetKey(postAddresses) !== addressSetKey(preAddresses)
  } catch {
    return true
  }
}

function classifyOutcome(error: unknown): ProbeOutcome {
  if (error instanceof SsrfBlocked) return 'blocked'
  if (error instanceof BudgetExceeded) return 'budget_exceeded'
  if (error instanceof RateLimited) return 'rate_limited'
  return 'network_error'
}

/**
 * The single entry point for fetching an unauthenticated caller's target URL. See
 * README for the full threat model and what is/isn't covered. In short: validates
 * scheme/credentials/port, resolves and validates every hop's DNS answer against the
 * private/reserved-range policy before fetching it, never exposes a raw Response to the
 * caller (only what `parseResponse` extracts), and re-resolves after every fetch to
 * detect (not prevent) a DNS answer that changed mid-probe. Method defaults to GET;
 * POST additionally requires an allowlisted header set and does not follow its own
 * redirects — see "Non-GET does not follow redirects" and "authorization never crosses
 * a host" in the README for why.
 */
export async function guardedFetch<T>(
  url: string,
  budget: ProbeBudget,
  rateLimitDecision: RateLimitDecision | null | undefined,
  opts: GuardedFetchOptions<T>,
): Promise<GuardedFetchResult<T>> {
  const fetchImpl = opts.fetchImpl ?? fetch
  const resolveAndValidateHostImpl = opts.resolveAndValidateHostImpl ?? resolveAndValidateHost
  const resolveHostImpl = opts.resolveHostImpl ?? resolveHost

  const deadline = Date.now() + budget.maxDurationMs
  const hops: ProbeHopRecord[] = []
  let dnsAnswerChanged = false
  let redirectCrossHostObserved = false
  let targetHost = ''

  const record: ProbeAuditRecord = {
    triggeredAt: new Date().toISOString(),
    callerIdentifier: opts.callerIdentifier,
    targetHost: '',
    hops: [],
    hopCount: 0,
    outcome: 'success',
    blockedReason: null,
    dnsAnswerChangedDuringProbe: false,
    redirectCrossHostObserved: false,
  }

  try {
    assertRateLimitAllowed(rateLimitDecision)

    const method = opts.method ?? 'GET'
    if (method !== 'GET' && method !== 'POST') {
      throw new SsrfBlocked('METHOD_NOT_ALLOWED', `method must be "GET" or "POST", got ${JSON.stringify(opts.method)}`)
    }
    if (opts.body !== undefined && method !== 'POST') {
      throw new SsrfBlocked('BODY_REQUIRES_POST', 'a request body is only allowed when method is "POST"')
    }
    if (opts.body !== undefined) {
      const bodyByteLength = typeof opts.body === 'string' ? new TextEncoder().encode(opts.body).length : opts.body.length
      if (bodyByteLength > budget.maxBodyBytes) {
        throw new BudgetExceeded('MAX_BODY_BYTES', `request body (${bodyByteLength} bytes) exceeded the ${budget.maxBodyBytes}-byte budget`)
      }
    }
    let currentHeaders = validateAndNormalizeHeaders(opts.headers)

    let currentUrl = url
    let redirectsFollowed = 0
    let requestsUsed = 0

    for (;;) {
      if (Date.now() > deadline) {
        throw new BudgetExceeded('MAX_DURATION', `probe exceeded its ${budget.maxDurationMs}ms wall-clock budget`)
      }
      if (requestsUsed >= budget.maxRequests) {
        throw new BudgetExceeded('MAX_REQUESTS', `probe exceeded its ${budget.maxRequests}-request budget`)
      }

      const target = parseGuardedTarget(currentUrl)
      if (targetHost === '') targetHost = target.hostname

      let preAddresses: ResolvedAddress[] = []
      if (target.isIpLiteral) {
        const verdict = classifyIp(target.hostname, target.ipFamily === 6 ? 6 : 4)
        if (verdict.blocked) throw new SsrfBlocked(verdict.code, `${target.hostname} is ${verdict.description}`)
      } else {
        preAddresses = await resolveAndValidateHostImpl(target.hostname)
      }

      requestsUsed++
      const remainingMs = Math.max(0, deadline - Date.now())
      let response: Response
      try {
        response = await fetchImpl(target.url, {
          method,
          headers: currentHeaders,
          redirect: 'manual',
          signal: AbortSignal.timeout(remainingMs),
          // Cast: a known @types/node + lib.dom.d.ts friction point, not a real type
          // hazard — Uint8Array is a wholly valid BodyInit at runtime (same friction
          // point already documented in the calling prober's own wire-adapter layer).
          ...(method === 'POST' && opts.body !== undefined ? { body: opts.body as BodyInit } : {}),
        })
      } catch (cause) {
        const name = (cause as { name?: string } | undefined)?.name
        if (name === 'TimeoutError' || name === 'AbortError') {
          throw new BudgetExceeded('MAX_DURATION', `probe exceeded its ${budget.maxDurationMs}ms wall-clock budget`)
        }
        throw cause
      }

      hops.push({ hostname: target.hostname, resolvedAddresses: preAddresses, status: response.status })

      if (!target.isIpLiteral) {
        const changed = await checkDnsAnswerChanged(target.hostname, preAddresses, resolveHostImpl)
        if (changed) dnsAnswerChanged = true
      }

      const isRedirect = REDIRECT_STATUSES.has(response.status) && response.headers.has('location')

      // Non-GET never follows its own redirect — see README "Non-GET does not follow
      // redirects": replaying a POST body + headers at a host the caller never named is
      // the classic credential-leak redirect pattern. The redirect becomes the terminal
      // result instead (still a normal, successful return — this is data, not a guard
      // rejection), with redirectCrossHostObserved recording whether it pointed cross-host.
      if (isRedirect && method !== 'GET') {
        const location = response.headers.get('location')!
        redirectCrossHostObserved = isCrossHostRedirect(location, target.url, target.hostname)

        const handle = createSafeResponseHandle(response, budget.maxBodyBytes)
        const parsed = await opts.parseResponse(handle)

        record.targetHost = targetHost
        record.hops = hops
        record.hopCount = hops.length
        record.outcome = 'success'
        record.blockedReason = null
        record.dnsAnswerChangedDuringProbe = dnsAnswerChanged
        record.redirectCrossHostObserved = redirectCrossHostObserved
        opts.onAudit?.(record)

        return {
          result: parsed,
          status: response.status,
          finalUrl: target.url.href,
          hops,
          dnsAnswerChangedDuringProbe: dnsAnswerChanged,
          redirectCrossHostObserved,
        }
      }

      if (isRedirect) {
        if (redirectsFollowed >= budget.maxRedirects) {
          throw new BudgetExceeded('MAX_REDIRECTS', `probe exceeded its ${budget.maxRedirects}-redirect budget`)
        }
        redirectsFollowed++
        const location = response.headers.get('location')!
        if (isCrossHostRedirect(location, target.url, target.hostname)) {
          redirectCrossHostObserved = true
          // authorization never crosses a host — see README. The rest of the
          // allowlisted headers travel on to the next hop unchanged.
          currentHeaders = stripAuthorization(currentHeaders)
        }
        currentUrl = new URL(location, target.url).href
        continue
      }

      const handle = createSafeResponseHandle(response, budget.maxBodyBytes)
      const parsed = await opts.parseResponse(handle)

      record.targetHost = targetHost
      record.hops = hops
      record.hopCount = hops.length
      record.outcome = 'success'
      record.blockedReason = null
      record.dnsAnswerChangedDuringProbe = dnsAnswerChanged
      record.redirectCrossHostObserved = redirectCrossHostObserved
      opts.onAudit?.(record)

      return {
        result: parsed,
        status: response.status,
        finalUrl: target.url.href,
        hops,
        dnsAnswerChangedDuringProbe: dnsAnswerChanged,
        redirectCrossHostObserved,
      }
    }
  } catch (error) {
    record.targetHost = targetHost
    record.hops = hops
    record.hopCount = hops.length
    record.outcome = classifyOutcome(error)
    record.blockedReason = error instanceof Error ? error.message : String(error)
    record.dnsAnswerChangedDuringProbe = dnsAnswerChanged
    record.redirectCrossHostObserved = redirectCrossHostObserved
    opts.onAudit?.(record)
    throw error
  }
}
