/**
 * suite-0130-remap.ts is the oracle half of every live-vs-frozen differential
 * in this package for what suite 0.13.0 (TODO 217) changes on every run — the
 * legacy initialize offer and the recorded probeOfferedRevision — so it is
 * tested on its own: offerAsLive hands over the live request only where the
 * two differ by exactly the old offer, and passes every other difference
 * through for the differential to report; suite0130Remap inserts one key in
 * one place and touches nothing else. suite-0130-differential.test.ts then
 * proves the live probe agrees with it on the whole fixture corpus.
 */
import assert from 'node:assert'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import { runProbe as frozen0120RunProbe } from './frozen/suite-0.12.0/src/probe.ts'
import { runProbe } from './probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { LEGACY_OFFER_0130, LEGACY_OFFER_BEFORE_0130, MODERN_OFFER, offerAsLive, offeredRevisionOf, offerSubstitutionProblem, recordRequest, suite0130Remap } from './suite-0130-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ENDPOINT = 'https://notes-mcp.example.com/mcp'

const initialize = (protocolVersion: string, id = 1) => JSON.stringify({ jsonrpc: '2.0', id, method: 'initialize', params: { protocolVersion, capabilities: {}, clientInfo: { name: 'mcpcheckup-probe', version: '0' } } })
const post = (body: string, headers: Record<string, string> = { 'content-type': 'application/json' }): RequestInit => ({ method: 'POST', headers, body })

/** Sends `old` through offerAsLive guided by `live`; returns what the target received and the counts. */
async function through(old: RequestInit, live: RequestInit | undefined, url = ENDPOINT, liveUrl = ENDPOINT) {
  const received: string[] = []
  const inner: FetchLike = async (input, init) => { received.push(recordRequest(input, init)); return new Response('{}') }
  const offer = offerAsLive(inner, live === undefined ? undefined : [recordRequest(liveUrl, live)])
  await offer.fetchImpl(url, old, () => {})
  return { received: received[0]!, substituted: offer.substituted() }
}

await t('an initialize that differs only by the old offer goes out as the live one, byte for byte (protocolVersion keeps its place among the keys), and is counted as a body substitution', async () => {
  const live = post(initialize(LEGACY_OFFER_0130))
  const r = await through(post(initialize(LEGACY_OFFER_BEFORE_0130)), live)
  assert.equal(r.received, recordRequest(ENDPOINT, live))
  assert.deepStrictEqual(r.substituted, { body: 1, header: 0 })
})

await t('a legacy follow-up whose mcp-protocol-version header is the old offer goes out with the new one, counted as a header substitution', async () => {
  const body = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
  const live = post(body, { 'content-type': 'application/json', 'mcp-protocol-version': LEGACY_OFFER_0130 })
  const r = await through(post(body, { 'content-type': 'application/json', 'mcp-protocol-version': LEGACY_OFFER_BEFORE_0130 }), live)
  assert.equal(r.received, recordRequest(ENDPOINT, live))
  assert.deepStrictEqual(r.substituted, { body: 0, header: 1 })
})

await t('any other difference is passed through untouched, for the differential to report: URL, method, another body field, another offer, another header, a non-initialize body', async () => {
  const cases: [string, RequestInit, RequestInit, string?][] = [
    ['another URL', post(initialize(LEGACY_OFFER_BEFORE_0130)), post(initialize(LEGACY_OFFER_0130)), 'https://other.example.com/mcp'],
    ['another method', { ...post(initialize(LEGACY_OFFER_BEFORE_0130)), method: 'PUT' }, post(initialize(LEGACY_OFFER_0130))],
    ['another JSON-RPC id as well', post(initialize(LEGACY_OFFER_BEFORE_0130, 7)), post(initialize(LEGACY_OFFER_0130, 1))],
    ['an offer other than the old one', post(initialize('2024-11-05')), post(initialize(LEGACY_OFFER_0130))],
    ['the new offer where the live run has the old one', post(initialize(LEGACY_OFFER_0130)), post(initialize(LEGACY_OFFER_BEFORE_0130))],
    ['another header besides the offer', post(initialize(LEGACY_OFFER_BEFORE_0130), { 'content-type': 'text/plain' }), post(initialize(LEGACY_OFFER_0130))],
    ['another header value', post('{}', { 'content-type': 'application/json', 'mcp-protocol-version': '2024-11-05' }), post('{}', { 'content-type': 'application/json', 'mcp-protocol-version': LEGACY_OFFER_0130 })],
    ['a non-initialize body carrying the old revision', post(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { protocolVersion: LEGACY_OFFER_BEFORE_0130 } })), post(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { protocolVersion: LEGACY_OFFER_0130 } }))],
  ]
  for (const [label, old, live, url] of cases) {
    const r = await through(old, live, url ?? ENDPOINT)
    assert.equal(r.received, recordRequest(url ?? ENDPOINT, old), `${label}: the old request must go out as it was`)
    assert.deepStrictEqual(r.substituted, { body: 0, header: 0 }, label)
  }
})

await t('no live sequence (the implementation\'s own run), an identical request, or a request past the end of the live sequence: nothing is replaced', async () => {
  const old = post(initialize(LEGACY_OFFER_BEFORE_0130))
  for (const live of [undefined, old]) {
    const r = await through(old, live)
    assert.equal(r.received, recordRequest(ENDPOINT, old))
    assert.deepStrictEqual(r.substituted, { body: 0, header: 0 })
  }
  const received: string[] = []
  const offer = offerAsLive(async (input, init) => { received.push(recordRequest(input, init)); return new Response('{}') }, [])
  await offer.fetchImpl(ENDPOINT, old, () => {})
  assert.deepStrictEqual(received, [recordRequest(ENDPOINT, old)])
  assert.deepStrictEqual(offer.substituted(), { body: 0, header: 0 })
})

const base = (declared: string | null, reachability: ['COMPLETED' | 'ERROR', 'VERIFIED' | 'UNVERIFIED']): ProbeResult => ({
  assertions: [{ check_id: 'reachability', execution_status: reachability[0], assertion_status: reachability[1] }],
  protocolRevisionDeclared: declared,
  trailing: 'kept',
} as unknown as ProbeResult)
const req = (body: string | null) => JSON.stringify(['POST', ENDPOINT, [], body])

await t('offerSubstitutionProblem: a replaced header is a problem exactly when the server declared a version', () => {
  assert.equal(offerSubstitutionProblem(base(null, ['COMPLETED', 'VERIFIED']), { header: 3 }), null)
  assert.equal(offerSubstitutionProblem(base('2025-06-18', ['COMPLETED', 'VERIFIED']), { header: 0 }), null)
  assert.match(offerSubstitutionProblem(base('2025-06-18', ['COMPLETED', 'VERIFIED']), { header: 1 }) ?? '', /declared 2025-06-18/)
})

await t('offeredRevisionOf: null unless reachability is COMPLETED/VERIFIED; then the legacy offer if an initialize was sent, else the modern one', () => {
  const sentInitialize = [req(JSON.stringify({ method: 'server/discover' })), req(initialize(LEGACY_OFFER_0130))]
  const discoverOnly = [req(JSON.stringify({ method: 'server/discover' })), req(JSON.stringify({ method: 'tools/list' })), req(null)]
  assert.equal(offeredRevisionOf(base(null, ['ERROR', 'UNVERIFIED']), sentInitialize), null)
  assert.equal(offeredRevisionOf(base(null, ['COMPLETED', 'UNVERIFIED']), sentInitialize), null)
  assert.equal(offeredRevisionOf(base(null, ['COMPLETED', 'VERIFIED']), sentInitialize), LEGACY_OFFER_0130)
  assert.equal(offeredRevisionOf(base('2026-07-28', ['COMPLETED', 'VERIFIED']), discoverOnly), MODERN_OFFER)
})

await t('suite0130Remap: probeOfferedRevision lands right after protocolRevisionDeclared, every other key keeps its place and value, the input is not mutated', () => {
  const old = base('2025-06-18', ['COMPLETED', 'VERIFIED'])
  const before = JSON.stringify(old)
  const out = suite0130Remap(old, [req(initialize(LEGACY_OFFER_0130))])
  assert.deepStrictEqual(Object.keys(out), ['assertions', 'protocolRevisionDeclared', 'probeOfferedRevision', 'trailing'])
  assert.equal(out.probeOfferedRevision, LEGACY_OFFER_0130)
  assert.deepStrictEqual({ ...out, probeOfferedRevision: undefined }, { ...old, probeOfferedRevision: undefined })
  assert.equal(JSON.stringify(old), before)
})

await t('suite0130Remap refuses a result with no protocolRevisionDeclared, or one that already carries probeOfferedRevision', () => {
  assert.throws(() => suite0130Remap({ assertions: [] } as unknown as ProbeResult, []), /no protocolRevisionDeclared/)
  assert.throws(() => suite0130Remap({ ...base(null, ['COMPLETED', 'VERIFIED']), probeOfferedRevision: null }, []), /already carries/)
})

await t('on a real run of a legacy server: frozen 0.12.0 offers 2025-06-18 and the implementation 2025-11-25; guided by the implementation\'s requests, the frozen run sends exactly them', async () => {
  const run = async (probe: typeof runProbe, createHandler: () => (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>, live?: readonly string[]) => {
    const handler = createHandler()
    const requests: string[] = []
    const offer = offerAsLive(async (input, init) => { requests.push(recordRequest(input, init)); return handler(input, init) }, live)
    let seq = 0
    const result = await probe({
      target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
      fetchImpl: offer.fetchImpl,
      budget: DEFAULT_PROBE_BUDGET,
      now: () => '2026-10-14T00:00:00.000Z',
      newId: () => `probe-${++seq}`,
      provenance: 'INDEPENDENTLY_OBSERVED',
      registry: CHECKS_REGISTRY,
    })
    return { result, requests, substituted: offer.substituted() }
  }
  const offers = (requests: string[]) => requests.map((r) => (JSON.parse(r) as unknown[])[3]).filter((b): b is string => typeof b === 'string').map((b) => JSON.parse(b) as { method?: string; params?: { protocolVersion?: string } }).filter((b) => b.method === 'initialize').map((b) => b.params?.protocolVersion)
  let legacy = 0
  for (const fixture of FIXTURE_CORPUS) {
    const now = await run(runProbe, fixture.createHandler)
    if (offers(now.requests).length === 0 || now.result.protocolRevisionDeclared === null) continue
    legacy++
    const unguided = await run(frozen0120RunProbe, fixture.createHandler)
    assert.deepStrictEqual(offers(now.requests), [LEGACY_OFFER_0130], `${fixture.id}: the implementation offers ${LEGACY_OFFER_0130} once`)
    assert.deepStrictEqual(offers(unguided.requests), [LEGACY_OFFER_BEFORE_0130], `${fixture.id}: frozen 0.12.0 offered ${LEGACY_OFFER_BEFORE_0130}`)
    const guided = await run(frozen0120RunProbe, fixture.createHandler, now.requests)
    assert.deepStrictEqual(guided.requests, now.requests, `${fixture.id}: guided, the frozen run sends the implementation's requests`)
    assert.equal(guided.substituted.body, 1, fixture.id)
    assert.equal(now.result.probeOfferedRevision, LEGACY_OFFER_0130, fixture.id)
  }
  assert.ok(legacy >= 3, `only ${legacy} legacy fixtures that declared a version`)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
