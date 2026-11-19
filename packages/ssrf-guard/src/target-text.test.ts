/**
 * Where text the target chose can end up in what this package throws (README
 * "never echo", errors.ts). The target controls the Location of every redirect it
 * answers and the body of every response, so each case below starts at a public
 * host, follows a redirect to a Location that carries a marker (or reads a body
 * that does), and checks where that marker goes:
 *
 *   - an SsrfBlocked from a later hop (hop > 0) may name the Location's host,
 *     scheme or port, as the URL parser read them: the one bounded exception for
 *     message and detail;
 *   - every other class guardedFetch can throw on a followed hop carries none of
 *     it, in its message, its detail (if it has one) or the audit record's
 *     blockedReason;
 *   - only UpstreamFetchFailed carries a runtime `cause` (whose text is not ours).
 *
 * RateLimited is not exercised: assertRateLimitAllowed runs once, before the hop
 * loop (guarded-fetch.ts:313), so it can never be thrown on a hop > 0.
 */
import assert from 'node:assert'
import { guardedFetch } from './guarded-fetch.ts'
import { DEFAULT_PROBE_BUDGET, type ProbeBudget } from './budget.ts'
import { SsrfGuardError, SsrfBlocked, BudgetExceeded, UpstreamFetchFailed } from './errors.ts'
import { resolveAndValidateHost, type ResolvedAddress } from './resolve.ts'
import { createSafeResponseHandle, type SafeResponseHandle } from './response-view.ts'
import type { ProbeAuditRecord } from './audit.ts'
import type { RateLimitDecision } from './rate-limit.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ALLOW: RateLimitDecision = { allowed: true, scope: [] }
/** Lower case: the URL parser lower-cases a host name. */
const MARK = 'zqmark7'
const START = 'https://start.example.com/mcp'
const MARK_HOST = `https://${MARK}.example.com/`
/** A private-use address (10.0.0.0/8): a block-code input, never contacted. */
const PRIVATE_IP = '10.77.77.77'
/** One DNS label of 67 bytes, over the 63-byte limit, carrying the marker. */
const LONG_LABEL = MARK + 'a'.repeat(60)
const UPSTREAM_MESSAGE = 'the request to the target failed, or the target\'s response could not be read or followed'
const JSON_MESSAGE = 'the response body is not valid JSON'

const PUBLIC: Record<string, ResolvedAddress[]> = {
  'start.example.com': [{ ip: '93.184.216.34', family: 4 }],
  [`${MARK}.example.com`]: [{ ip: '93.184.216.35', family: 4 }],
}

/** Our own DoH resolver, answered here and never on the network: the query echoed back
 *  as a response (QR set), so NOERROR with no records. */
const noRecordsDoh = (async (_input: unknown, init?: RequestInit) => {
  const answer = new Uint8Array(init!.body as Uint8Array)
  answer[2] = answer[2]! | 0x80
  return new Response(answer, { status: 200 })
}) as typeof fetch

/** A known public host resolves locally; any other name goes through the real
 *  resolveAndValidateHost (dns-wire's query encoder included) against noRecordsDoh. */
const resolveValidating = (hostname: string) =>
  PUBLIC[hostname] !== undefined ? Promise.resolve(PUBLIC[hostname]!) : resolveAndValidateHost(hostname, { fetchImpl: noRecordsDoh })
const resolvePlain = async (hostname: string) => PUBLIC[hostname] ?? []

type Route = () => Response | Promise<Response>
const redirectTo = (location: string): Route => () => new Response(null, { status: 302, headers: { location } })

interface Outcome { error: unknown; audit: ProbeAuditRecord | undefined; fetched: string[] }

/** One guardedFetch call over `routes` (href -> answer); resolves to what it threw. */
async function run(
  routes: Record<string, Route>,
  opts: { budget?: Partial<ProbeBudget>; parse?: (h: SafeResponseHandle) => unknown } = {},
): Promise<Outcome> {
  let audit: ProbeAuditRecord | undefined
  const fetched: string[] = []
  try {
    await guardedFetch(START, { ...DEFAULT_PROBE_BUDGET, ...opts.budget }, ALLOW, {
      callerIdentifier: 'target-text.test',
      fetchImpl: (async (input: URL | RequestInfo) => {
        const href = input instanceof URL ? input.href : String(input)
        fetched.push(href)
        const route = routes[href]
        if (route === undefined) throw new Error(`test bug: unexpected fetch of ${href}`)
        return route()
      }) as typeof fetch,
      resolveAndValidateHostImpl: resolveValidating,
      resolveHostImpl: resolvePlain,
      parseResponse: opts.parse ?? ((h) => h.bytes()),
      onAudit: (r) => { audit = r },
    })
  } catch (error) {
    return { error, audit, fetched }
  }
  throw new Error('expected guardedFetch to reject')
}

/** Every string the error and its audit record expose to a reader, cause excluded. */
function exposed(error: unknown, audit: ProbeAuditRecord | undefined): string[] {
  const e = error as { message?: unknown; detail?: unknown }
  return [String(e.message), ...('detail' in (error as object) ? [String(e.detail)] : []), String(audit?.blockedReason)]
}

/** Only UpstreamFetchFailed carries a runtime cause. */
function assertCauseRule(error: unknown): void {
  if (error instanceof UpstreamFetchFailed) assert.ok(error.cause instanceof Error, `UpstreamFetchFailed must keep the runtime error on cause, got ${String(error.cause)}`)
  else assert.equal(Object.hasOwn(error as object, 'cause'), false, `${(error as Error).name} must not carry a cause`)
}

console.log('the one exception: an SsrfBlocked from a later hop names the Location\'s host, scheme or port')

for (const [label, location, code, marker] of [
  ['a special-use host', `https://${MARK}.localhost/`, 'SPECIAL_USE_HOSTNAME', MARK],
  ['an empty-label host', `https://${MARK}..example.com/`, 'MALFORMED_HOSTNAME', MARK],
  ['a single-label host', `https://${MARK}/`, 'SINGLE_LABEL_HOSTNAME', MARK],
  ['a blocked IP literal', `https://${PRIVATE_IP}/`, 'PRIVATE_USE', PRIVATE_IP],
  ['a host with no A or AAAA records', `https://${MARK}-none.example.com/`, 'RESOLUTION_FAILED', MARK],
  ['a non-https scheme', `${MARK}://x.example.com/`, 'NON_HTTPS_SCHEME', MARK],
  ['a non-default port', `https://${MARK}.example.com:47123/`, 'NON_STANDARD_PORT', '47123'],
] as const) {
  await t(`Location to ${label}: SsrfBlocked ${code} at hop 1, the marker in its detail and message only, no cause`, async () => {
    const { error, audit, fetched } = await run({ [START]: redirectTo(location) })
    assert.ok(error instanceof SsrfBlocked, String(error))
    assert.equal(error.code, code)
    assert.equal(error.hop, 1)
    assert.ok(error.detail.includes(marker), error.detail)
    assert.ok(error.message.includes(marker), error.message)
    assert.equal(audit?.blockedReason, error.message)
    assert.deepEqual(fetched, [START], 'the blocked hop is never fetched')
    assertCauseRule(error)
  })
}

console.log('\nevery other class on a followed hop: no target-derived text in message, detail or blockedReason')

const twice = (location: string): Record<string, Route> => ({ [START]: redirectTo(MARK_HOST), [MARK_HOST]: redirectTo(location) })
const atMarkHost = (route: Route): Record<string, Route> => ({ [START]: redirectTo(MARK_HOST), [MARK_HOST]: route })
const failingStream = (error: unknown) => new ReadableStream({ pull(c) { c.error(error) } })

const others: [string, () => Promise<Outcome>, (e: unknown) => boolean, number | undefined][] = [
  ['BudgetExceeded MAX_REDIRECTS', () => run(twice(`https://${MARK}.example.com/next?${MARK}`), { budget: { maxRedirects: 1 } }),
    (e) => e instanceof BudgetExceeded && e.code === 'MAX_REDIRECTS', 1],
  ['BudgetExceeded MAX_REQUESTS', () => run({ [START]: redirectTo(`${MARK_HOST}?${MARK}`) }, { budget: { maxRequests: 1 } }),
    (e) => e instanceof BudgetExceeded && e.code === 'MAX_REQUESTS', 1],
  ['BudgetExceeded MAX_DURATION (the hop\'s fetch times out)', () => run(atMarkHost(() => { throw new DOMException(`${MARK} timed out`, 'TimeoutError') })),
    (e) => e instanceof BudgetExceeded && e.code === 'MAX_DURATION', 1],
  ['BudgetExceeded MAX_BODY_BYTES (the hop\'s body)', () => run(atMarkHost(() => new Response(MARK.repeat(8), { status: 200 })), { budget: { maxBodyBytes: 16 }, parse: (h) => h.text() }),
    (e) => e instanceof BudgetExceeded && e.code === 'MAX_BODY_BYTES', 1],
  ['UpstreamFetchFailed (the hop\'s fetch rejects)', () => run(atMarkHost(() => { throw new TypeError(`${MARK} connection reset`) })),
    (e) => e instanceof UpstreamFetchFailed, 1],
  ['UpstreamFetchFailed (the hop\'s body read rejects)', () => run(atMarkHost(() => new Response(failingStream(new TypeError(MARK)), { status: 200 }))),
    (e) => e instanceof UpstreamFetchFailed, 1],
  ['UpstreamFetchFailed (the hop answers with a Location that does not parse)', () => run(twice(`https://[${MARK}/`)),
    (e) => e instanceof UpstreamFetchFailed && e.cause instanceof TypeError, 1],
  ['a plain Error from the DNS query encoder (a label over 63 bytes)', () => run({ [START]: redirectTo(`https://${LONG_LABEL}.example.com/`) }),
    (e) => e instanceof Error && e.constructor === Error && e.message === 'DNS label too long (max 63 bytes)', undefined],
  ['a SyntaxError from json() (the hop\'s body is not JSON)', () => run(atMarkHost(() => new Response(`${MARK} not json`, { status: 200 })), { parse: (h) => h.json() }),
    (e) => e instanceof SyntaxError && e.message === JSON_MESSAGE, undefined],
]

for (const [label, call, isExpected, hop] of others) {
  await t(`${label}: ${hop === undefined ? 'no hop field' : `hop ${hop}`}, the marker nowhere, a cause only on UpstreamFetchFailed`, async () => {
    const { error, audit, fetched } = await call()
    assert.ok(isExpected(error), `unexpected error: ${(error as Error)?.name} ${(error as Error)?.message}`)
    assert.ok(!(error instanceof SsrfBlocked))
    assert.equal((error as SsrfGuardError).hop, hop)
    assert.equal(fetched[0], START)
    assert.ok(fetched.slice(1).every((href) => href.includes(MARK)), JSON.stringify(fetched))
    assert.ok((audit?.hopCount ?? 0) >= 1, 'the call got past its first request before this was thrown')
    for (const text of exposed(error, audit)) assert.ok(!text.includes(MARK), `target-derived text in ${JSON.stringify(text)}`)
    if (error instanceof UpstreamFetchFailed) assert.equal(error.message, UPSTREAM_MESSAGE)
    assertCauseRule(error)
  })
}

console.log('\njson(): a body that is not JSON gives a fixed message; what reading the body throws passes through')

for (const [label, routes] of [
  ['hop 0', { [START]: () => new Response(`${MARK} {not json`, { status: 200 }) }],
  ['a followed hop', atMarkHost(() => new Response(`${MARK} {not json`, { status: 200 }))],
] as const) {
  await t(`json() on ${label}: SyntaxError with exactly "${JSON_MESSAGE}", no cause, the body in neither message nor blockedReason`, async () => {
    const { error, audit } = await run(routes, { parse: (h) => h.json() })
    assert.ok(error instanceof SyntaxError, String(error))
    assert.equal(error.constructor, SyntaxError)
    assert.equal(error.message, JSON_MESSAGE)
    assert.equal(Object.hasOwn(error, 'cause'), false)
    assert.equal(audit?.outcome, 'network_error')
    assert.equal(audit?.blockedReason, JSON_MESSAGE)
    assert.ok(!String(audit?.blockedReason).includes(MARK))
  })
}

await t('json() passes readBytes\'s own errors through unchanged: UpstreamFetchFailed from a failing body read, BudgetExceeded MAX_BODY_BYTES', async () => {
  const original = new TypeError(`${MARK} stream broke`)
  const viaJson = await createSafeResponseHandle(new Response(failingStream(original)), 1000).json().then(() => undefined, (e: unknown) => e)
  const viaText = await createSafeResponseHandle(new Response(failingStream(original)), 1000).text().then(() => undefined, (e: unknown) => e)
  assert.ok(viaJson instanceof UpstreamFetchFailed, String(viaJson))
  assert.equal(viaJson.cause, original)
  assert.equal(viaJson.message, UPSTREAM_MESSAGE)
  assert.ok(viaText instanceof UpstreamFetchFailed)
  assert.equal(viaJson.message, viaText.message)

  const tooBig = await createSafeResponseHandle(new Response('{"a":"' + MARK.repeat(4) + '"}'), 8).json().then(() => undefined, (e: unknown) => e)
  assert.ok(tooBig instanceof BudgetExceeded, String(tooBig))
  assert.equal(tooBig.code, 'MAX_BODY_BYTES')
  assert.equal(tooBig.message, 'response body exceeded the 8-byte budget')
})

await t('sanity: json() still parses a JSON body', async () => {
  assert.deepEqual(await createSafeResponseHandle(new Response('{"a":[1,"x"]}'), 1000).json(), { a: [1, 'x'] })
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
