import { credentialShapes } from '@mcpcheckup/attestation-schema'
import type { AuthObservation } from '@mcpcheckup/attestation-schema'
import { firstChallengeParamNames, parseBearerChallenge } from './auth.ts'
import type { CredentialChallenge } from './protocol.ts'
import type { FetchLike } from './types.ts'

/** Suite 0.14.0: what an 'auth_gated' attestation payload records about the
 *  credential gate that stopped a run (ProbeResult.authObservation). Every rule
 *  below is the one the attestation schema's auth_observation descriptions
 *  state; a value that breaks a rule is left out and flagged, never trimmed. */

const PARAM_NAME = /^[a-z0-9_-]{1,32}$/
const MAX_PARAM_NAMES = 16
const MAX_URL_LENGTH = 512
/** https, a host of [a-z0-9._-] (WHATWG has already lowercased it) and at most a
 *  port, then a path of RFC 3986 pchar and '/', with well-formed escapes only. No
 *  '@' before the path (no userinfo), no '?' (no query), no '#' (no fragment).
 *  Narrower than the schema's pattern and format:"uri" together, so a recorded
 *  URL always passes both. */
const RECORDABLE_URL = /^https:\/\/[a-z0-9._-]+(?::[0-9]+)?(?:\/(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})*)*$/

const isCredentialShaped = (s: string) => credentialShapes(s).length > 0

/** The run's FetchLike, forwarding every call and all four arguments unchanged,
 *  that also keeps the body bytes of the last response it passed back when that
 *  response was an HTTP 200. runProbe hands it to judgeAuthMetadataFromGate only,
 *  which sends at most one request (sendRequest, following GET redirects one hop
 *  per call), so the last response is the one auth_metadata judged.
 *
 *  The bytes are copied as the caller's own read pulls them through (the 200 is
 *  passed back with the same status and headers and its body piped through a
 *  copy), so nothing is read here beyond what sendRequest reads under the run's
 *  deadline and body budget, and nothing is read after it. lastOkBody() answers
 *  only once that read has reached the end of the body, and null otherwise. */
export function keepLastOkBody(fetchImpl: FetchLike): { fetchImpl: FetchLike; lastOkBody: () => Uint8Array | null } {
  let last: { chunks: Uint8Array[]; complete: boolean } | null = null
  return {
    fetchImpl: async (input, init, onGuardSignal, options) => {
      const response = await fetchImpl(input, init, onGuardSignal, options)
      if (response.status !== 200) {
        last = null
        return response
      }
      const seen: { chunks: Uint8Array[]; complete: boolean } = { chunks: [], complete: response.body === null }
      last = seen
      if (response.body === null) return response
      const copy = new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          seen.chunks.push(chunk.slice())
          controller.enqueue(chunk)
        },
        flush() {
          seen.complete = true
        },
      })
      return new Response(response.body.pipeThrough(copy), { status: response.status, statusText: response.statusText, headers: response.headers })
    },
    lastOkBody: () => {
      if (last === null || !last.complete) return null
      const bytes = new Uint8Array(last.chunks.reduce((n, c) => n + c.length, 0))
      let at = 0
      for (const chunk of last.chunks) {
        bytes.set(chunk, at)
        at += chunk.length
      }
      return bytes
    },
  }
}

/** The challenge reduced to auth_observation, or null when its scheme is
 *  credential-shaped, as the header carries it or lowercased: the scheme cannot
 *  be left out (it is required, and the run's credential_required reasons carry
 *  it too), so such a run is not recorded as auth_gated at all. A parameter
 *  name is checked in both forms too: lowercasing can hide a shape (a JWT, a
 *  mixed-case token) that the name as sent shows. `metadataBody`: the bytes of the 200 answer to
 *  the RFC 9728 document request, as keepLastOkBody returned them; null when no
 *  200 came back or nothing was requested. */
export async function authObservationOf(challenge: CredentialChallenge, metadataBody: Uint8Array | null): Promise<AuthObservation | null> {
  // classifyCredentialChallenge's scheme is the header's first token lowercased, so of the same length.
  if (isCredentialShaped(challenge.wwwAuthenticate.slice(0, challenge.scheme.length)) || isCredentialShaped(challenge.scheme)) return null
  const names = firstChallengeParamNames(challenge.wwwAuthenticate)
  const recordable = (name: string) => PARAM_NAME.test(name.toLowerCase()) && !isCredentialShaped(name) && !isCredentialShaped(name.toLowerCase())
  const listed = [...new Set(names.filter(recordable).map((name) => name.toLowerCase()))].sort()
  const url = recordableUrl(parseBearerChallenge(challenge.wwwAuthenticate).resourceMetadataUrl)
  return {
    scheme: challenge.scheme,
    param_names: listed.slice(0, MAX_PARAM_NAMES),
    param_names_truncated: listed.length > MAX_PARAM_NAMES || !names.every(recordable),
    resource_metadata_url: url.url,
    resource_metadata_url_withheld: url.withheld,
    resource_metadata_body_digest: metadataBody === null ? null : await sha256Ref(metadataBody),
  }
}

/** The same URL judgeAuthChallenge requested (parseBearerChallenge's, where an
 *  empty value means none), as WHATWG serializes it, when every rule holds:
 *  credentialShapes() is run on that form and on the value as the header gave it. */
function recordableUrl(raw: string | null): { url: string | null; withheld: boolean } {
  if (!raw) return { url: null, withheld: false }
  let href: string
  try {
    href = new URL(raw).href
  } catch {
    return { url: null, withheld: true }
  }
  // Both forms, as for the scheme: serialization lowercases the host, which can hide a shape.
  const ok = href.length <= MAX_URL_LENGTH && RECORDABLE_URL.test(href) && !isCredentialShaped(href) && !isCredentialShaped(raw)
  return ok ? { url: href, withheld: false } : { url: null, withheld: true }
}

async function sha256Ref(bytes: Uint8Array): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>))
  return 'sha256:' + Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('')
}
