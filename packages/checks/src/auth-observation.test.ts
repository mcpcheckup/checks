// Suite 0.14.0: auth-observation.ts, the credential gate reduced to what an
// 'auth_gated' attestation payload records. Each rule the schema's
// auth_observation descriptions state is driven here from a WWW-Authenticate
// value, through classifyCredentialChallenge as runProbe reaches it.
//
// No credential-shaped text appears in this file: every such value is assembled
// at run time from obviously synthetic parts.
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { ATTESTATION_SCHEMA, credentialShapes } from '@mcpcheckup/attestation-schema'
import { authObservationOf, keepLastOkBody } from './auth-observation.ts'
import { classifyCredentialChallenge, firstChallengeParamNames, MAX_SCHEME_LEN } from './auth.ts'
import type { CredentialChallenge } from './protocol.ts'
import type { FetchLike } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

/** The challenge runProbe would carry for a 401 with this header, or a test failure when it is not one. */
function gate(wwwAuthenticate: string): CredentialChallenge {
  const accepted = classifyCredentialChallenge(401, new Headers({ 'www-authenticate': wwwAuthenticate }))
  assert.ok(accepted, `not a credential challenge: ${wwwAuthenticate}`)
  return { scheme: accepted.scheme, status: 401, wwwAuthenticate }
}
const observe = (wwwAuthenticate: string, body: Uint8Array | null = null) => authObservationOf(gate(wwwAuthenticate), body)
const sha256Ref = (bytes: Uint8Array) => 'sha256:' + createHash('sha256').update(bytes).digest('hex')

const ORIGIN = 'https://notes-mcp.example.com'
const META = `${ORIGIN}/.well-known/oauth-protected-resource/mcp`

// Synthetic credential shapes, assembled at run time.
const VENDOR_SHAPED = ['sk', 'test', 'x'.repeat(16)].join('_')
const HEX_RUN = '0123456789abcdef'.repeat(2)
const MIXED_ENTROPY = 'Synthetic0Value1'.repeat(2)
const percentEncodedEach = (s: string) => Array.from(s, (c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')

console.log('auth_observation：scheme 与 param_names')

await t('scheme lowercased; names lowercased, de-duplicated, sorted; a repeated name is not counted as left out', async () => {
  const o = await observe(`Bearer Realm="mcp", scope="x", error="invalid_token", REALM="again", resource_metadata="${META}"`)
  assert.ok(o)
  assert.equal(o.scheme, 'bearer')
  assert.deepStrictEqual(o.param_names, ['error', 'realm', 'resource_metadata', 'scope'])
  assert.equal(o.param_names_truncated, false)
})

await t('a challenge with no auth-params (shape 1) and a token68 one (shape 2) record no names, and nothing is left out', async () => {
  for (const header of ['Bearer', 'Bearer, Basic realm="x"', 'Bearer c3ludGhldGlj==']) {
    const o = await observe(header)
    assert.ok(o, header)
    assert.deepStrictEqual(o.param_names, [], header)
    assert.equal(o.param_names_truncated, false, header)
  }
})

await t('selection rule: with several challenges, scheme and param_names describe the first one only; the URL is the last resource_metadata in the whole value', async () => {
  const o = await observe(`Basic realm="first", charset="UTF-8", Bearer resource_metadata="${META}", scope="later"`)
  assert.ok(o)
  assert.equal(o.scheme, 'basic')
  assert.deepStrictEqual(o.param_names, ['charset', 'realm'])
  assert.equal(o.param_names_truncated, false)
  assert.equal(o.resource_metadata_url, META)
  // firstChallengeParamNames stops at the second challenge's scheme.
  assert.deepStrictEqual(firstChallengeParamNames('Basic realm="a", Bearer scope="b"'), ['realm'])
})

await t('a name that is not 1-32 of [a-z0-9_-] once lowercased is left out, and param_names_truncated says so', async () => {
  for (const bad of ['n'.repeat(33), 'a.b', "it's", 'x+y']) {
    const o = await observe(`Bearer realm="mcp", ${bad}="v"`)
    assert.ok(o, bad)
    assert.deepStrictEqual(o.param_names, ['realm'], bad)
    assert.equal(o.param_names_truncated, true, bad)
  }
  const exactly32 = await observe(`Bearer ${'n'.repeat(32)}="v"`)
  assert.deepStrictEqual(exactly32?.param_names, ['n'.repeat(32)])
  assert.equal(exactly32?.param_names_truncated, false)
})

await t('a name credentialShapes() flags is left out (as written and percent-encoded the scanner would decode it), and param_names_truncated says so', async () => {
  for (const bad of [VENDOR_SHAPED, HEX_RUN]) {
    const o = await observe(`Bearer realm="mcp", ${bad}="v"`)
    assert.ok(o, bad)
    assert.deepStrictEqual(o.param_names, ['realm'], bad)
    assert.equal(o.param_names_truncated, true, bad)
    assert.deepStrictEqual(credentialShapes(o), [], bad)
  }
})

await t('at most 16 names, the first 16 in ascending code-point order; the 17th sets param_names_truncated', async () => {
  const names = Array.from({ length: 17 }, (_, i) => `p${String(i).padStart(2, '0')}`)
  const header = `Bearer ${[...names].reverse().map((n) => `${n}="v"`).join(', ')}`
  const o = await observe(header)
  assert.ok(o)
  assert.deepStrictEqual(o.param_names, names.slice(0, 16))
  assert.equal(o.param_names_truncated, true)
  const sixteen = await observe(`Bearer ${names.slice(0, 16).map((n) => `${n}="v"`).join(', ')}`)
  assert.equal(sixteen?.param_names.length, 16)
  assert.equal(sixteen?.param_names_truncated, false)
})

await t('a credential-shaped scheme is never recorded: no observation at all', async () => {
  const shaped = 'ghp_' + 'x'.repeat(20)
  assert.equal((await observe(`${shaped} realm="mcp"`)), null)
})

await t('shapes lowercasing would hide are checked as sent: a mixed-case scheme or name, and a mixed-case URL host', async () => {
  // Lowercased, MIXED_ENTROPY is no longer a shape; as sent it is.
  assert.deepStrictEqual(credentialShapes(MIXED_ENTROPY.toLowerCase()), [])
  assert.notDeepStrictEqual(credentialShapes(MIXED_ENTROPY), [])
  assert.equal(await observe(`${MIXED_ENTROPY} realm="mcp"`), null)
  const name = await observe(`Bearer realm="mcp", ${MIXED_ENTROPY}="v"`)
  assert.deepStrictEqual(name?.param_names, ['realm'])
  assert.equal(name?.param_names_truncated, true)
  const host = await observe(`Bearer resource_metadata="https://${MIXED_ENTROPY}.example/meta"`)
  assert.equal(host?.resource_metadata_url, null)
  assert.equal(host?.resource_metadata_url_withheld, true)
})

await t('MAX_SCHEME_LEN is the schema\'s scheme bound: the producer accepts exactly what auth_observation.scheme admits (64 yes, 65 no)', async () => {
  const pattern = new RegExp((ATTESTATION_SCHEMA as unknown as { $defs: { authObservation: { properties: { scheme: { pattern: string } } } } }).$defs.authObservation.properties.scheme.pattern)
  // 'z', not a hex digit: 64 hex digits are a credential shape of their own.
  const at = 'z'.repeat(MAX_SCHEME_LEN), over = 'z'.repeat(MAX_SCHEME_LEN + 1)
  assert.equal(MAX_SCHEME_LEN, 64)
  assert.equal(pattern.test(at), true)
  assert.equal(pattern.test(over), false)
  assert.equal((await observe(`${at} realm="mcp"`))?.scheme, at)
  assert.equal(classifyCredentialChallenge(401, new Headers({ 'www-authenticate': `${over} realm="mcp"` })), null)
})

console.log('\nauth_observation：resource_metadata_url')

await t('none named, or an empty value: null and not withheld', async () => {
  for (const header of ['Bearer realm="mcp"', 'Bearer resource_metadata=""']) {
    const o = await observe(header)
    assert.equal(o?.resource_metadata_url, null, header)
    assert.equal(o?.resource_metadata_url_withheld, false, header)
  }
})

await t('recorded as WHATWG serializes it: host lowercased and IDNA-encoded, default port dropped, dot segments resolved, a bare origin gets its "/"', async () => {
  const cases: [string, string][] = [
    ['https://Notes-MCP.Example.COM/.well-known/x', 'https://notes-mcp.example.com/.well-known/x'],
    ['https://notes-mcp.example.com:443/a/../b', 'https://notes-mcp.example.com/b'],
    ['https://notes-mcp.example.com', 'https://notes-mcp.example.com/'],
    ['https://notes-mcp.example.com:8443/m%2Fx', 'https://notes-mcp.example.com:8443/m%2Fx'],
    ['https://ünotes.example.com/meta', 'https://xn--notes-jva.example.com/meta'],
  ]
  for (const [named, recorded] of cases) {
    const o = await observe(`Bearer resource_metadata="${named}"`)
    assert.equal(o?.resource_metadata_url, recorded, named)
    assert.equal(o?.resource_metadata_url_withheld, false, named)
  }
})

await t('withheld (null, withheld true): not https, userinfo, query, fragment, longer than 512, not a URL, an IP-literal host, a credential-shaped path as written or percent-encoded', async () => {
  // 'z', not a hex digit, so that length alone is what decides these two.
  const long = `${ORIGIN}/${'z'.repeat(512 - ORIGIN.length)}`
  assert.equal(long.length, 513)
  const cases = [
    'http://notes-mcp.example.com/meta',
    'https://' + ['user', 'notes-mcp.example.com'].join('@') + '/meta',
    'https://notes-mcp.example.com/meta?x=1',
    'https://notes-mcp.example.com/meta?',
    'https://notes-mcp.example.com/meta#f',
    long,
    'not a url',
    '/relative/meta',
    'https://[::1]/meta',
    `${ORIGIN}/${VENDOR_SHAPED}`,
    `${ORIGIN}/${percentEncodedEach(VENDOR_SHAPED)}`,
    `${ORIGIN}/a/${MIXED_ENTROPY}`,
  ]
  for (const named of cases) {
    const o = await observe(`Bearer resource_metadata="${named}"`)
    assert.ok(o, named)
    assert.equal(o.resource_metadata_url, null, named)
    assert.equal(o.resource_metadata_url_withheld, true, named)
    assert.deepStrictEqual(credentialShapes(o), [], named)
  }
  const at512 = `${ORIGIN}/${'z'.repeat(511 - ORIGIN.length)}`
  assert.equal(at512.length, 512)
  assert.equal((await observe(`Bearer resource_metadata="${at512}"`))?.resource_metadata_url, at512)
})

await t('every recorded URL matches the schema\'s resource_metadata_url pattern', async () => {
  const node = (ATTESTATION_SCHEMA as unknown as { $defs: { authObservation: { properties: { resource_metadata_url: { oneOf?: { pattern?: string }[]; pattern?: string } } } } }).$defs.authObservation.properties.resource_metadata_url
  const pattern = new RegExp(node.pattern ?? node.oneOf!.find((b) => b.pattern)!.pattern!)
  for (const named of [META, 'https://notes-mcp.example.com', "https://a.example.com/p;q=1/!$&'()*+,=:@~"]) {
    const url = (await observe(`Bearer resource_metadata="${named}"`))?.resource_metadata_url
    assert.ok(url, named)
    assert.ok(pattern.test(url), url)
  }
})

console.log('\nauth_observation：resource_metadata_body_digest')

await t('sha256 of the exact bytes, never of decoded text: a BOM and invalid UTF-8 change the digest', async () => {
  const bytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d, 0xff, 0xfe, 0x0a])
  const o = await observe(`Bearer resource_metadata="${META}"`, bytes)
  assert.equal(o?.resource_metadata_body_digest, sha256Ref(bytes))
  const decodedThenEncoded = new TextEncoder().encode(new TextDecoder().decode(bytes))
  assert.notEqual(o?.resource_metadata_body_digest, sha256Ref(decodedThenEncoded))
})

await t('present also when the URL is withheld; null when no body was received', async () => {
  const body = new TextEncoder().encode('{}')
  const withheld = await observe('Bearer resource_metadata="https://notes-mcp.example.com/meta?x=1"', body)
  assert.equal(withheld?.resource_metadata_url_withheld, true)
  assert.equal(withheld?.resource_metadata_body_digest, sha256Ref(body))
  assert.equal((await observe(`Bearer resource_metadata="${META}"`, null))?.resource_metadata_body_digest, null)
})

console.log('\nkeepLastOkBody：转发不变；只留调用方自己读到底的最后一个 200 的字节，此外一字节不读')

await t('forwards all four arguments unchanged; a 200 comes back with the same status, headers and body bytes, and those bytes are kept once the caller has read them', async () => {
  const seen: unknown[][] = []
  const bytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d, 0xff])
  const response = new Response(bytes, { status: 200, statusText: 'OK', headers: { 'content-type': 'application/json', 'x-kept': '1' } })
  const inner: FetchLike = async (...args) => { seen.push(args); return response }
  const kept = keepLastOkBody(inner)
  const init = { method: 'GET' }, onGuardSignal = () => {}, options = { timeoutMs: 5 }
  const got = await kept.fetchImpl(META, init, onGuardSignal, options)
  assert.equal(seen.length, 1)
  assert.equal(seen[0]![0], META)
  assert.equal(seen[0]![1], init)
  assert.equal(seen[0]![2], onGuardSignal)
  assert.equal(seen[0]![3], options)
  assert.equal(got.status, 200)
  assert.equal(got.statusText, 'OK')
  assert.equal(got.headers.get('x-kept'), '1')
  assert.equal(kept.lastOkBody(), null, 'nothing is kept before the caller reads the body')
  assert.deepStrictEqual(new Uint8Array(await got.arrayBuffer()), bytes)
  assert.deepStrictEqual(kept.lastOkBody(), bytes)
})

await t('non-200 answers are passed back untouched, the very object', async () => {
  const response = new Response('gone', { status: 404 })
  const kept = keepLastOkBody(async () => response)
  assert.equal(await kept.fetchImpl(META, undefined, () => {}), response)
  assert.equal(kept.lastOkBody(), null)
})

await t('only the last response counts: 302 then 200 keeps the 200; 200 then 404 keeps nothing; nothing sent keeps nothing; an empty 200 keeps zero bytes', async () => {
  const answers = [new Response('', { status: 302, headers: { location: META } }), new Response('ok', { status: 200 }), new Response('gone', { status: 404 }), new Response(null, { status: 200 })]
  const kept = keepLastOkBody(async () => answers.shift()!)
  assert.equal(kept.lastOkBody(), null)
  await kept.fetchImpl(META, undefined, () => {})
  assert.equal(kept.lastOkBody(), null)
  await (await kept.fetchImpl(META, undefined, () => {})).text()
  assert.deepStrictEqual(kept.lastOkBody(), new TextEncoder().encode('ok'))
  await kept.fetchImpl(META, undefined, () => {})
  assert.equal(kept.lastOkBody(), null)
  await (await kept.fetchImpl(META, undefined, () => {})).text()
  assert.deepStrictEqual(kept.lastOkBody(), new Uint8Array())
})

await t('a body the caller stops reading (a stalled stream) is never read here and keeps nothing: lastOkBody() answers at once, null', async () => {
  let pulls = 0
  const stalled = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++
      if (pulls === 1) controller.enqueue(new TextEncoder().encode('{"partial":'))
      // then never again: no more chunks, never closed
      return new Promise(() => {})
    },
  })
  const kept = keepLastOkBody(async () => new Response(stalled, { status: 200 }))
  const got = await kept.fetchImpl(META, undefined, () => {})
  const reader = got.body!.getReader()
  await reader.read()
  const pullsSeen = pulls
  assert.equal(kept.lastOkBody(), null)
  assert.equal(pulls, pullsSeen, 'lastOkBody() pulled from the source')
  void reader.cancel().catch(() => {})
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
