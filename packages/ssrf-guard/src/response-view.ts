import { BudgetExceeded } from './errors.ts'

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

export function createSafeResponseHandle(response: Response, maxBodyBytes: number): SafeResponseHandle {
  let cached: Promise<Uint8Array> | null = null

  function readBytes(): Promise<Uint8Array> {
    if (cached) return cached
    cached = (async () => {
      const reader = response.body?.getReader()
      if (!reader) return new Uint8Array(0)
      const chunks: Uint8Array[] = []
      let total = 0
      for (;;) {
        const { done, value } = await reader.read()
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
