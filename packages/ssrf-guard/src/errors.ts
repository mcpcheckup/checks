export class SsrfGuardError extends Error {
  code: string
  /** Set by guardedFetch on the way out: redirects followed before this request (0 = the URL it was given). */
  hop?: number

  constructor(code: string, message: string) {
    super(message)
    this.name = new.target.name
    this.code = code
  }
}

/**
 * The target itself was rejected — its scheme, credentials, port, or a resolved IP
 * failed policy. `detail` is always built from data we already control (the URL we were
 * given, or an IP a trusted DoH resolver returned) — never from bytes the target sent
 * back, so this is safe to surface in logs and error messages verbatim.
 */
export class SsrfBlocked extends SsrfGuardError {
  detail: string

  constructor(code: string, detail: string) {
    super(code, `blocked (${code}): ${detail}`)
    this.detail = detail
  }
}

/** A probe-level resource limit (redirects, wall-clock time, response bytes, request count) was hit. */
export class BudgetExceeded extends SsrfGuardError {}

/** The caller-supplied rate-limit decision said no — or no valid decision was supplied at all, which fails closed to the same thing. */
export class RateLimited extends SsrfGuardError {}

/**
 * The request to the target itself failed: the runtime's fetch() rejected, or
 * reading the response body rejected, for a reason other than a timeout / abort
 * (those become BudgetExceeded('MAX_DURATION')). Only those two sites wrap into
 * it (guarded-fetch.ts's fetch call, response-view.ts's body reader), so an
 * error thrown by our own code before or around them never becomes one.
 * Deliberately NOT an SsrfGuardError: nothing was refused by policy. The message
 * is fixed; the runtime's own error, whose text is not ours, stays on `cause`.
 */
export class UpstreamFetchFailed extends Error {
  /** As on SsrfGuardError. */
  hop?: number
  constructor(cause: unknown) {
    super('the request to the target failed before a complete response arrived', { cause })
    this.name = new.target.name
  }
}
