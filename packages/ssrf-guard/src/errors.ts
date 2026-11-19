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
 * failed policy. `detail` is built from the URL being requested, the caller's options,
 * and what our own DoH resolver returned or failed with. One bounded exception: when
 * guardedFetch follows a redirect, the URL of a later hop (`hop` > 0) is the target's
 * `Location`, so a host name, scheme or port that `detail` names there is the target's,
 * as the URL parser read it (url-target.ts's scheme, port and host-name rules,
 * guarded-fetch.ts's IP-literal check, resolve.ts's "no A or AAAA records"). It never
 * carries raw header or body bytes. The only other exception in this package is
 * UpstreamFetchFailed's `cause`.
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
 * (those become BudgetExceeded('MAX_DURATION')), or the target answered a
 * followed GET with a redirect whose Location does not parse. Only those three
 * sites wrap into it (guarded-fetch.ts's fetch call and its parse of a followed
 * redirect's Location, response-view.ts's body reader), so an error thrown by
 * our own code before or around them never becomes one.
 * Deliberately NOT an SsrfGuardError: nothing was refused by policy. The message
 * is fixed. The runtime's own error stays on `cause`: its text is not ours and may
 * quote what the target sent, such as a `Location` that did not parse. No other
 * error this package throws carries a runtime `cause`.
 */
export class UpstreamFetchFailed extends Error {
  /** As on SsrfGuardError. */
  hop?: number
  constructor(cause: unknown) {
    super('the request to the target failed, or the target\'s response could not be read or followed', { cause })
    this.name = new.target.name
  }
}
