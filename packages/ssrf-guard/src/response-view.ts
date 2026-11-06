import { BudgetExceeded, UpstreamFetchFailed } from './errors.ts'

/**
 * Deliberately NOT a Response, and deliberately does not expose the raw ReadableStream
 * body. This is the "blind SSRF" mitigation described in the README: guardedFetch never
 * hands the caller a Response object to read from at will. Instead the caller must
 * supply a parser function up front, and that function receives only this restricted
 * handle. This does not stop a caller from writing a parser that echoes the raw body
 * straight through — nothing can stop that, since real assertions need real body access
 * — but it makes doing so a deliberate, visible line in the parser you write, not the
 * path of least resistance the way "just read response.text() from what fetch gave you"
 * would be.
 */
export interface SafeResponseHandle {
  status: number
  headers: Headers
  text(): Promise<string>
  json(): Promise<unknown>
  arrayBuffer(): Promise<ArrayBuffer>
  bytes(): Promise<Uint8Array>
}

function bodyDurationExceeded(): BudgetExceeded {
  return new BudgetExceeded('MAX_DURATION', 'the response body did not arrive within the probe\'s wall-clock budget')
}

/** A rejection from reading the body, the same split guarded-fetch.ts makes for the
 *  fetch call itself: the caller's signal having been aborted (whatever its reason), or
 *  the request's timeout signal firing mid-body (TimeoutError / AbortError, by name), is
 *  the wall-clock budget; anything else is UpstreamFetchFailed. */
function bodyReadFailure(cause: unknown, signal: AbortSignal | undefined): Error {
  if (signal?.aborted === true) return bodyDurationExceeded()
  const name = (cause as { name?: string } | undefined)?.name
  if (name === 'TimeoutError' || name === 'AbortError') return bodyDurationExceeded()
  return new UpstreamFetchFailed(cause)
}

/** `signal` is guardedFetch's GuardedFetchOptions.signal (internal; not exported from
 *  the package): once it is aborted no further read starts, a pending read is
 *  cancelled, and a body read still in progress ends in BudgetExceeded('MAX_DURATION'). */
export function createSafeResponseHandle(response: Response, maxBodyBytes: number, signal?: AbortSignal): SafeResponseHandle {
  let cached: Promise<Uint8Array> | null = null

  function readBytes(): Promise<Uint8Array> {
    if (cached) return cached
    cached = (async () => {
      const reader = response.body?.getReader()
      if (!reader) return new Uint8Array(0)
      // Settles a read that would otherwise hang: a cancelled reader's pending read
      // resolves with done: true, which the check after the read turns into MAX_DURATION.
      // A function, not a property read: TypeScript would otherwise keep the narrowing
      // from the check before an await across that await.
      const aborted = (): boolean => signal?.aborted === true
      const onAbort = (): void => { reader.cancel().catch(() => {}) }
      signal?.addEventListener('abort', onAbort, { once: true })
      try {
        const chunks: Uint8Array[] = []
        let total = 0
        for (;;) {
          if (aborted()) {
            reader.cancel().catch(() => {})
            throw bodyDurationExceeded()
          }
          // Only the read itself is wrapped — not getReader() above, nor the checks
          // around it, which are ours.
          let chunk: ReadableStreamReadResult<Uint8Array>
          try {
            chunk = await reader.read()
          } catch (cause) {
            throw bodyReadFailure(cause, signal)
          }
          // Load-bearing: after an abort, done: true means "cancelled", never "complete" —
          // a body cut short must not come back as a shorter success.
          if (aborted()) throw bodyDurationExceeded()
          const { done, value } = chunk
          if (done) break
          total += value.length
          if (total > maxBodyBytes) {
            await reader.cancel().catch(() => {})
            // Deliberately does not include any of the bytes we've read so far — this
            // message must never carry target-supplied content (see README "never echo").
            throw new BudgetExceeded('MAX_BODY_BYTES', `response body exceeded the ${maxBodyBytes}-byte budget`)
          }
          chunks.push(value)
        }
        const out = new Uint8Array(total)
        let offset = 0
        for (const chunk of chunks) {
          out.set(chunk, offset)
          offset += chunk.length
        }
        return out
      } finally {
        signal?.removeEventListener('abort', onAbort)
      }
    })()
    return cached
  }

  return {
    status: response.status,
    headers: response.headers,
    bytes: () => readBytes(),
    arrayBuffer: async () => {
      const b = await readBytes()
      return b.buffer as ArrayBuffer
    },
    text: async () => new TextDecoder().decode(await readBytes()),
    json: async () => JSON.parse(new TextDecoder().decode(await readBytes())),
  }
}
