/**
 * suite-0120-remap.ts is the oracle half of every live-vs-frozen differential
 * in this package (what suite 0.12.0 changes for every run), so it is tested on
 * its own: the rule table, what it leaves alone, that it never mutates its
 * input, and that recordToolsCallStatus sees exactly the reserved-name
 * tools/call and nothing else. The differentials then prove the live probe
 * agrees with it on the whole fixture corpus.
 */
import assert from 'node:assert'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import { runProbe as frozen0110RunProbe } from './frozen/suite-0.11.0/src/probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { recordToolsCallStatus, suite0120Remap } from './suite-0120-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ENDPOINT = 'https://notes-mcp.example.com/mcp'

/** What suite 0.11.0 stored for the clean modern server, and the status its tools/call was answered with. */
async function frozenRun(fixtureId: string): Promise<{ result: ProbeResult; status: number | null }> {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === fixtureId)
  assert.ok(fixture, `fixture ${fixtureId} is not in the corpus`)
  const handler = fixture.createHandler()
  const recorder = recordToolsCallStatus(async (input, init) => handler(input, init))
  let seq = 0
  const result = await frozen0110RunProbe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: recorder.fetchImpl,
    budget: DEFAULT_PROBE_BUDGET,
    now: () => '2026-10-13T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  })
  return { result, status: recorder.toolsCallStatus() }
}

const row = (r: ProbeResult, id: string) => r.assertions.find((a) => a.check_id === id)!
const state = (r: ProbeResult, id: string) => {
  const a = row(r, id)
  return [a.execution_status, a.assertion_status, a.reason?.key ?? null, a.unverified_reason?.key ?? null]
}

const clean = await frozenRun('modern-baseline-clean')

await t('premise: suite 0.11.0 recorded latency_profile, auth_metadata and error_taxonomy COMPLETED/VERIFIED for a server whose tools/call was answered with an ordinary error', () => {
  assert.equal(clean.status, 200)
  for (const id of ['latency_profile', 'auth_metadata', 'error_taxonomy']) assert.deepStrictEqual(state(clean.result, id).slice(0, 2), ['COMPLETED', 'VERIFIED'], id)
})

await t('a tools/call answered 200: latency_profile and auth_metadata are rewritten, error_taxonomy (a real protocol error came back) is not', () => {
  const out = suite0120Remap(clean.result, 200)
  assert.deepStrictEqual(state(out, 'latency_profile'), ['SKIPPED', 'UNVERIFIED', 'latency_not_recorded', 'latency_not_recorded'])
  assert.deepStrictEqual(state(out, 'auth_metadata'), ['SKIPPED', 'UNVERIFIED', 'auth_no_challenge_observed', 'auth_no_challenge_observed'])
  assert.deepStrictEqual(state(out, 'error_taxonomy').slice(0, 2), ['COMPLETED', 'VERIFIED'])
})

await t('the reason is exactly { key }, with no params member, in both reason and unverified_reason', () => {
  const out = suite0120Remap(clean.result, 200)
  for (const id of ['latency_profile', 'auth_metadata']) {
    assert.deepStrictEqual(row(out, id).reason, { key: id === 'latency_profile' ? 'latency_not_recorded' : 'auth_no_challenge_observed' })
    assert.deepStrictEqual(row(out, id).unverified_reason, row(out, id).reason)
  }
})

await t('rule table over the tools/call status: auth_metadata is rewritten unless the answer was a 401 or there was none; error_taxonomy only for a 401 or 403', () => {
  const cases: [number | null, boolean, boolean][] = [
    // [status, auth_metadata rewritten, error_taxonomy rewritten]
    [null, false, false],
    [200, true, false],
    [201, true, false],
    [400, true, false],
    [401, false, true],
    [403, true, true],
    [404, true, false],
    [500, true, false],
  ]
  for (const [status, auth, taxonomy] of cases) {
    const out = suite0120Remap(clean.result, status)
    assert.equal(row(out, 'auth_metadata').assertion_status === 'UNVERIFIED', auth, `auth_metadata at ${status}`)
    assert.equal(row(out, 'error_taxonomy').assertion_status === 'UNVERIFIED', taxonomy, `error_taxonomy at ${status}`)
    if (auth) assert.deepStrictEqual(state(out, 'auth_metadata'), ['SKIPPED', 'UNVERIFIED', 'auth_no_challenge_observed', 'auth_no_challenge_observed'], `auth_metadata at ${status}`)
    if (taxonomy) assert.deepStrictEqual(state(out, 'error_taxonomy'), ['SKIPPED', 'UNVERIFIED', 'error_shape_not_observed', 'error_shape_not_observed'], `error_taxonomy at ${status}`)
  }
})

await t('latency_profile is rewritten whatever the frozen suite wrote there, including a cascade reason', () => {
  const cascaded = structuredClone(clean.result)
  Object.assign(row(cascaded, 'latency_profile'), { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'probe_cascade_incomplete' }, unverified_reason: { key: 'probe_cascade_incomplete' } })
  for (const status of [null, 200, 401]) {
    assert.deepStrictEqual(state(suite0120Remap(cascaded, status), 'latency_profile'), ['SKIPPED', 'UNVERIFIED', 'latency_not_recorded', 'latency_not_recorded'], `at ${status}`)
  }
})

await t('only a COMPLETED/VERIFIED auth_metadata or error_taxonomy is rewritten: a row 0.11.0 already had something else to say about is left alone', () => {
  const other = structuredClone(clean.result)
  Object.assign(row(other, 'auth_metadata'), { assertion_status: 'OBSERVED_RISK', reason: { key: 'auth_metadata_http_error', params: { status: 500 } } })
  Object.assign(row(other, 'error_taxonomy'), { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'probe_tool_name_collision' }, unverified_reason: { key: 'probe_tool_name_collision' } })
  const out = suite0120Remap(other, 403)
  assert.deepStrictEqual(row(out, 'auth_metadata'), row(other, 'auth_metadata'))
  assert.deepStrictEqual(row(out, 'error_taxonomy'), row(other, 'error_taxonomy'))
})

await t('every other row, and every other field of the result, is returned as it was, with own keys in the same order', () => {
  const out = suite0120Remap(clean.result, 401)
  const rewritten = new Set(['latency_profile', 'error_taxonomy'])
  assert.deepStrictEqual(out.assertions.map((a) => a.check_id), clean.result.assertions.map((a) => a.check_id))
  for (const a of clean.result.assertions) {
    if (rewritten.has(a.check_id)) continue
    assert.deepStrictEqual(row(out, a.check_id), a, a.check_id)
    assert.deepStrictEqual(Object.keys(row(out, a.check_id)), Object.keys(a), `${a.check_id}: key order`)
  }
  assert.deepStrictEqual({ ...out, assertions: [] }, { ...clean.result, assertions: [] })
})

await t('the input is not mutated', () => {
  const before = structuredClone(clean.result)
  suite0120Remap(clean.result, 403)
  assert.deepStrictEqual(clean.result, before)
})

await t('recordToolsCallStatus: remembers the status of the answer to the tools/call, ignores every other method, and is null when none was sent', async () => {
  const answers = new Map<string, number>([['initialize', 200], ['tools/list', 202], ['tools/call', 403]])
  const inner: FetchLike = async (_input, init) => {
    const method = (JSON.parse(String(init?.body)) as { method: string }).method
    return new Response('{}', { status: answers.get(method) ?? 500 })
  }
  const send = (recorded: ReturnType<typeof recordToolsCallStatus>, method: string) =>
    recorded.fetchImpl(ENDPOINT, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method }) }, () => undefined)
  const recorded = recordToolsCallStatus(inner)
  assert.equal(recorded.toolsCallStatus(), null)
  await send(recorded, 'initialize')
  await send(recorded, 'tools/list')
  assert.equal(recorded.toolsCallStatus(), null, 'a method other than tools/call is not the call')
  await send(recorded, 'tools/call')
  assert.equal(recorded.toolsCallStatus(), 403)
  const get = recordToolsCallStatus(inner)
  await get.fetchImpl(ENDPOINT, { method: 'GET' }, () => undefined).catch(() => undefined)
  assert.equal(get.toolsCallStatus(), null, 'a GET has no body and is not the call')
})

await t('recordToolsCallStatus on a real run: a server that answers the call 401 is seen as 401, one that answers a JSON-RPC error as 200, a run that never sends the call as null', async () => {
  const seen = new Set<number | null>()
  for (const f of FIXTURE_CORPUS) seen.add((await frozenRun(f.id)).status)
  for (const wanted of [200, 401, null]) assert.ok(seen.has(wanted), `no fixture in the corpus has a tools/call status of ${wanted}`)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
