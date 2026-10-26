// Suite 0.16.0: latency_profile is measured (docs_version v0.3.0).
//
// The time comes from the FetchLike (in production the probe Worker's
// guarded-fetch-adapter.ts, which times the request from just before it is sent
// until its response headers arrive) through GuardSignals.responseHeadersMs.
// wire.ts's sendRequest keeps one time per POST to the endpoint, ignores one
// reported after the call was abandoned at the run's deadline, and never
// counts the auth metadata GET. probe.ts turns the times into one row:
//   - samples, not credential-gated: COMPLETED/VERIFIED latency_measured
//     { p50_ms, p95_ms, n, timed_to: 'response_headers' } (nearest rank);
//   - samples on a credential-gated run: SKIPPED/UNVERIFIED latency_not_signed_auth_gated;
//   - responses but no time reported (a FetchLike that does not time):
//     SKIPPED/UNVERIFIED latency_not_recorded, as in suites 0.12.0 to 0.15.0;
//   - no response at all: SKIPPED/UNVERIFIED latency_no_samples.
// Timing adds no request: with and without a timing FetchLike every corpus
// fixture sends the same requests, and every other part of the result is the same.
import assert from 'node:assert'
import { BudgetExceeded, DEFAULT_PROBE_BUDGET, UpstreamFetchFailed } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { canonicalize } from '@mcpcheckup/canonicalizer'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { createProbeContext, ProbeAborted, sendRequest } from './wire.ts'
import { isLatencySampleMs, judgeLatency, LATENCY_TIMED_TO, nearestRank } from './latency.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { FetchLike, ProbeInput, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ENDPOINT = 'https://notes-mcp.example.com/mcp'

function input(fetchImpl: FetchLike, budget: ProbeBudget = DEFAULT_PROBE_BUDGET): ProbeInput {
  let seq = 0
  return {
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget,
    now: () => '2026-10-25T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  }
}

const handlerOf = (id: string): FetchLike => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === id)
  assert.ok(fixture, `no fixture ${id}`)
  return fixture.createHandler()
}

interface Transcript { methods: string[] }

/** Records each call as `METHOD jsonrpc-method` (or `GET <url>`). */
function recording(inner: FetchLike): { fetchImpl: FetchLike; transcript: Transcript } {
  const transcript: Transcript = { methods: [] }
  const fetchImpl: FetchLike = async (req, init, onGuardSignal, options) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    if (typeof init?.body === 'string') {
      let rpc = '?'
      try { rpc = String((JSON.parse(init.body) as { method?: unknown }).method) } catch { /* not JSON */ }
      transcript.methods.push(`${method} ${rpc}`)
    } else {
      transcript.methods.push(`${method} ${typeof req === 'string' ? req : req instanceof URL ? req.href : req.url}`)
    }
    return inner(req, init, onGuardSignal, options)
  }
  return { fetchImpl, transcript }
}

/** What the production adapter does, for a test: after the inner call has
 *  its response (headers), report a time for it; `ms(i)` gives the i-th call's. */
function timing(inner: FetchLike, ms: (i: number) => unknown = (i) => 10 * (i + 1)): FetchLike {
  let i = 0
  return async (req, init, onGuardSignal, options) => {
    const response = await inner(req, init, onGuardSignal, options)
    onGuardSignal({ responseHeadersMs: ms(i++) as number })
    return response
  }
}

const latencyRows = (r: ProbeResult) => r.assertions.filter((a) => a.check_id === 'latency_profile')
function latency(r: ProbeResult): Assertion {
  const rows = latencyRows(r)
  assert.equal(rows.length, 1, 'exactly one latency_profile row')
  return rows[0]!
}
const state = (a: Assertion) => [a.execution_status, a.assertion_status, a.reason, a.unverified_reason]
const notRecorded = { key: 'latency_not_recorded' }
const noSamples = { key: 'latency_no_samples' }
const gatedKey = { key: 'latency_not_signed_auth_gated' }
const measured = (p50_ms: number, p95_ms: number, n: number) => ({ key: 'latency_measured', params: { p50_ms, p95_ms, n, timed_to: 'response_headers' } })
const posts = (tr: Transcript) => tr.methods.filter((m) => m.startsWith('POST ')).length

console.log('suite 0.16.0: latency_profile is measured from the existing requests (time to response headers)')

await t('nearestRank: the value at rank ceil(p/100 × n), always one of the samples; p95 is the largest for n ≤ 19', () => {
  assert.deepStrictEqual([nearestRank([7], 50), nearestRank([7], 95)], [7, 7])
  assert.deepStrictEqual([nearestRank([10, 20], 50), nearestRank([10, 20], 95)], [10, 20])
  assert.deepStrictEqual([nearestRank([10, 20, 30], 50), nearestRank([10, 20, 30], 95)], [20, 30])
  const twenty = Array.from({ length: 20 }, (_, i) => i + 1)
  assert.deepStrictEqual([nearestRank(twenty, 50), nearestRank(twenty, 95)], [10, 19])
  const hundred = Array.from({ length: 100 }, (_, i) => i + 1)
  assert.deepStrictEqual([nearestRank(hundred, 50), nearestRank(hundred, 95)], [50, 95])
  for (let n = 1; n <= 19; n++) {
    const s = Array.from({ length: n }, (_, i) => i)
    assert.equal(nearestRank(s, 95), n - 1, `n=${n}: p95 is the largest`)
  }
  assert.throws(() => nearestRank([], 50), RangeError)
  for (const p of [0, 101, 49.5, Number.NaN]) assert.throws(() => nearestRank([1], p), RangeError, String(p))
})

await t('judgeLatency: p50 and p95 always come with n; samples are sorted first; the four outcomes', () => {
  assert.deepStrictEqual(judgeLatency({ samplesMs: [30, 10, 20], untimedResponses: 0 }, false), { execution_status: 'COMPLETED', assertion_status: 'VERIFIED', reason: measured(20, 30, 3) })
  assert.deepStrictEqual(judgeLatency({ samplesMs: [30, 10, 20], untimedResponses: 2 }, false).reason, measured(20, 30, 3), 'untimed responses do not change n')
  assert.deepStrictEqual(judgeLatency({ samplesMs: [5], untimedResponses: 0 }, true), { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: gatedKey })
  assert.deepStrictEqual(judgeLatency({ samplesMs: [], untimedResponses: 1 }, false), { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: notRecorded })
  assert.deepStrictEqual(judgeLatency({ samplesMs: [], untimedResponses: 1 }, true), { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: notRecorded })
  assert.deepStrictEqual(judgeLatency({ samplesMs: [], untimedResponses: 0 }, false), { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: noSamples })
  assert.deepStrictEqual(judgeLatency(undefined, false), { execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: notRecorded })
  assert.equal(LATENCY_TIMED_TO, 'response_headers')
  const input = [3, 1, 2]
  judgeLatency({ samplesMs: input, untimedResponses: 0 }, false)
  assert.deepStrictEqual(input, [3, 1, 2], 'the observations are not sorted in place')
})

await t('isLatencySampleMs: whole non-negative safe integers only', () => {
  for (const ok of [0, 1, 250, 9_999]) assert.equal(isLatencySampleMs(ok), true, String(ok))
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, '12', null, undefined]) assert.equal(isLatencySampleMs(bad), false, String(bad))
})

await t('modern server, timed 30 / 10 / 20 ms: COMPLETED/VERIFIED latency_measured { p50_ms 20, p95_ms 30, n 3, timed_to }, no unverified_reason', async () => {
  const rec = recording(handlerOf('modern-baseline-clean'))
  const values = [30, 10, 20]
  const result = await runProbe(input(timing(rec.fetchImpl, (i) => values[i])))
  assert.deepStrictEqual(rec.transcript.methods, ['POST server/discover', 'POST tools/list', 'POST tools/call'])
  assert.deepStrictEqual(state(latency(result)), ['COMPLETED', 'VERIFIED', measured(20, 30, 3), null])
  assert.equal(latency(result).docs_version, 'v0.3.0')
  assert.doesNotThrow(() => canonicalize(result.assertions), 'the params are canonicalizable (whole numbers and a string)')
})

await t('every corpus fixture: timing adds no request, and nothing but the latency_profile row differs between a timed and an untimed run', async () => {
  let measuredCount = 0
  for (const fixture of FIXTURE_CORPUS) {
    const plain = recording(fixture.createHandler())
    const timed = recording(fixture.createHandler())
    const a = await runProbe(input(plain.fetchImpl))
    const b = await runProbe(input(timing(timed.fetchImpl)))
    assert.deepStrictEqual(timed.transcript.methods, plain.transcript.methods, `${fixture.id}: the same requests, in the same order`)
    const withoutLatency = (r: ProbeResult) => ({ ...r, assertions: r.assertions.filter((x) => x.check_id !== 'latency_profile') })
    assert.deepStrictEqual(withoutLatency(b), withoutLatency(a), `${fixture.id}: every other part of the result is the same`)
    assert.equal(latencyRows(a).length, 1, fixture.id)
    assert.equal(latencyRows(b).length, 1, fixture.id)
    const row = latency(b)
    if (row.assertion_status === 'VERIFIED') {
      measuredCount++
      assert.equal(row.execution_status, 'COMPLETED', fixture.id)
      const p = row.reason!.params!
      assert.equal(p.n, posts(timed.transcript), `${fixture.id}: n is the number of POSTs to the endpoint`)
      assert.deepStrictEqual(Object.keys(p).sort(), ['n', 'p50_ms', 'p95_ms', 'timed_to'], `${fixture.id}: p50 and p95 never without n`)
    } else {
      assert.equal(row.execution_status, 'SKIPPED', fixture.id)
      assert.ok(['latency_not_signed_auth_gated', 'latency_no_samples'].includes(row.reason!.key), `${fixture.id}: ${row.reason!.key}`)
    }
    assert.deepStrictEqual(state(latency(a)).slice(0, 2), ['SKIPPED', 'UNVERIFIED'], `${fixture.id}: untimed is never VERIFIED`)
    assert.ok(['latency_not_recorded', 'latency_no_samples'].includes(latency(a).reason!.key), `${fixture.id}: untimed ${latency(a).reason!.key}`)
  }
  assert.ok(measuredCount >= 40, `only ${measuredCount} fixtures measured`)
})

await t('a FetchLike that times nothing (the corpus handlers as they are): latency_not_recorded, the 0.15.0 row', async () => {
  assert.deepStrictEqual(state(latency(await runProbe(input(handlerOf('modern-baseline-clean'))))), ['SKIPPED', 'UNVERIFIED', notRecorded, notRecorded])
})

await t('legacy server with an auth challenge on tools/call: every POST is timed, the metadata GET is not', async () => {
  const rec = recording(handlerOf('legacy-tools-call-credential-gated'))
  const result = await runProbe(input(timing(rec.fetchImpl, () => 40)))
  assert.ok(rec.transcript.methods.some((m) => m.startsWith('GET ')), 'the metadata GET was sent (and timed by the FetchLike)')
  assert.equal(posts(rec.transcript) + 1, rec.transcript.methods.length)
  assert.deepStrictEqual(state(latency(result)), ['COMPLETED', 'VERIFIED', measured(40, 40, posts(rec.transcript)), null])
})

await t('credential gate on the handshake (the run an auth_gated payload signs), timed: SKIPPED/UNVERIFIED latency_not_signed_auth_gated; untimed: latency_not_recorded', async () => {
  const id = 'credential-gated-handshake'
  const result = await runProbe(input(timing(handlerOf(id))))
  assert.equal(result.assertions.find((a) => a.check_id === 'discovery_handshake')!.unverified_reason?.key, 'credential_required', 'precondition: the handshake itself is gated')
  assert.deepStrictEqual(state(latency(result)), ['SKIPPED', 'UNVERIFIED', gatedKey, gatedKey], id)
  assert.deepStrictEqual(state(latency(await runProbe(input(handlerOf(id))))), ['SKIPPED', 'UNVERIFIED', notRecorded, notRecorded], `${id} untimed`)
})

await t('credential gate on tools/list only (the handshake verified, so no auth_gated payload can sign it): the times are measured like any other run', async () => {
  const id = 'credential-gated-tools-list'
  const result = await runProbe(input(timing(handlerOf(id))))
  assert.equal(result.assertions.find((a) => a.check_id === 'discovery_handshake')!.assertion_status, 'VERIFIED', 'precondition: the handshake verified')
  assert.equal(result.assertions.find((a) => a.check_id === 'tools_list')!.unverified_reason?.key, 'credential_required', 'precondition: tools/list is gated')
  const row = latency(result)
  assert.deepStrictEqual([row.execution_status, row.assertion_status, row.reason?.key, row.unverified_reason], ['COMPLETED', 'VERIFIED', 'latency_measured', null], id)
  const n = (row.reason!.params as { n: number }).n
  assert.ok(n >= 2, `discover and tools/list are both timed (n ${n})`)
  assert.deepStrictEqual(row.reason, measured(10 * Math.ceil(n / 2), 10 * n, n))
  assert.deepStrictEqual(state(latency(await runProbe(input(handlerOf(id))))), ['SKIPPED', 'UNVERIFIED', notRecorded, notRecorded], `${id} untimed`)
})

await t('no response at all — the first request fails, or never answers inside the budget: SKIPPED/UNVERIFIED latency_no_samples', async () => {
  const failing: FetchLike = async () => { throw Object.assign(new UpstreamFetchFailed(new TypeError('lost')), { hop: 0 }) }
  assert.deepStrictEqual(state(latency(await runProbe(input(timing(failing))))), ['SKIPPED', 'UNVERIFIED', noSamples, noSamples])
  const guardTimeout: FetchLike = async () => { throw Object.assign(new BudgetExceeded('MAX_DURATION', 'x'), { hop: 0 }) }
  assert.deepStrictEqual(state(latency(await runProbe(input(timing(guardTimeout))))), ['SKIPPED', 'UNVERIFIED', noSamples, noSamples])
  const silent: FetchLike = () => new Promise<Response>(() => {})
  const result = await runProbe(input(timing(silent), { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 50 }))
  assert.deepStrictEqual(state(latency(result)), ['SKIPPED', 'UNVERIFIED', noSamples, noSamples])
  assert.equal(result.assertions.find((a) => a.check_id === 'reachability')!.reason?.key, 'probe_budget_exhausted_duration')
})

await t('a time reported after the call was abandoned at the deadline is ignored; one reported while it still counted is kept', async () => {
  const late: FetchLike = (_req, _init, onGuardSignal) => new Promise<Response>((resolve) => setTimeout(() => {
    onGuardSignal({ responseHeadersMs: 5 })
    resolve(new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }))
  }, 150))
  const abandoned = await runProbe(input(late, { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 50 }))
  await new Promise((r) => setTimeout(r, 200))
  assert.deepStrictEqual(state(latency(abandoned)), ['SKIPPED', 'UNVERIFIED', noSamples, noSamples])
  // Headers in time, then the body never ends: the headers arrived, so the time counts.
  const stalledBody: FetchLike = async (_req, _init, onGuardSignal) => {
    onGuardSignal({ responseHeadersMs: 7 })
    return new Response(new ReadableStream({ start() {} }), { status: 200, headers: { 'content-type': 'application/json' } })
  }
  const r = await runProbe(input(stalledBody, { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 80 }))
  assert.deepStrictEqual(state(latency(r)), ['COMPLETED', 'VERIFIED', measured(7, 7, 1), null])
  assert.equal(r.assertions.find((a) => a.check_id === 'reachability')!.assertion_status, 'UNVERIFIED')
})

await t('sendRequest itself: a time reported through a call\'s onGuardSignal after that call was abandoned is not kept in the run context, also while the context lives on; one reported before is', async () => {
  let report: ((s: { responseHeadersMs?: number }) => void) | undefined
  const never: FetchLike = (_req, _init, onGuardSignal) => { report = onGuardSignal; return new Promise<Response>(() => {}) }
  const budget = { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 40 }
  const ctx = createProbeContext(Date.now())
  await assert.rejects(() => sendRequest(never, ENDPOINT, { method: 'POST', body: '{}' }, budget, ctx), (e: unknown) => e instanceof ProbeAborted && e.code === 'MAX_DURATION')
  report!({ responseHeadersMs: 5 })
  assert.deepStrictEqual(ctx.latency, { samplesMs: [], untimedResponses: 0 })
  const answered: FetchLike = async (_req, _init, onGuardSignal) => { onGuardSignal({ responseHeadersMs: 9 }); return new Response('{}', { status: 200 }) }
  const ctx2 = createProbeContext(Date.now())
  await sendRequest(answered, ENDPOINT, { method: 'POST', body: '{}' }, DEFAULT_PROBE_BUDGET, ctx2)
  assert.deepStrictEqual(ctx2.latency, { samplesMs: [9], untimedResponses: 0 })
})

await t('any HTTP status counts: a 429 on the first request is one sample (the run still stops there, reachability UNVERIFIED)', async () => {
  const rec = recording(handlerOf('rate-limited-429-retry-after'))
  const result = await runProbe(input(timing(rec.fetchImpl, () => 12)))
  assert.equal(rec.transcript.methods.length, 1)
  assert.deepStrictEqual(state(latency(result)), ['COMPLETED', 'VERIFIED', measured(12, 12, 1), null])
  assert.equal(result.assertions.find((a) => a.check_id === 'reachability')!.reason?.key, 'probe_rate_limited')
})

await t('an abort after some answers (tools/list over the body budget): the answers that came are measured, the cascade is unchanged', async () => {
  const rec = recording(handlerOf('response-exceeds-budget'))
  const timed = await runProbe(input(timing(rec.fetchImpl, (i) => [8, 4][i])))
  assert.deepStrictEqual(state(latency(timed)), ['COMPLETED', 'VERIFIED', measured(4, 8, 2), null])
  assert.equal(posts(rec.transcript), 2)
})

await t('a reported value that is not a whole non-negative number of ms is not a sample (that call counts as untimed); a second report for one call is not a second sample', async () => {
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, '12']) {
    assert.deepStrictEqual(state(latency(await runProbe(input(timing(handlerOf('modern-baseline-clean'), () => bad))))), ['SKIPPED', 'UNVERIFIED', notRecorded, notRecorded], String(bad))
  }
  const mixed = [Number.NaN, 25, -3]
  assert.deepStrictEqual(latency(await runProbe(input(timing(handlerOf('modern-baseline-clean'), (i) => mixed[i])))).reason, measured(25, 25, 1))
  const twice: FetchLike = async (req, init, onGuardSignal, options) => {
    const response = await handlerOf('modern-baseline-clean')(req, init, onGuardSignal, options)
    onGuardSignal({ responseHeadersMs: 10 })
    onGuardSignal({ responseHeadersMs: 99 })
    return response
  }
  assert.deepStrictEqual(latency(await runProbe(input(twice))).reason, measured(10, 10, 3))
})

await t('stdio target: latency_not_recorded (no request is made), one row', async () => {
  const result = await runProbe({ ...input(async () => { throw new Error('stdio never fetches') }), target: { slug: 'example/local-tool', transport: 'stdio', packageRef: 'example-local-tool@1.0.0' } })
  assert.deepStrictEqual(state(latency(result)), ['SKIPPED', 'UNVERIFIED', notRecorded, notRecorded])
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
