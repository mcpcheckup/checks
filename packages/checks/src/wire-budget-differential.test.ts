/**
 * TODO 458 differential — the primary evidence that handing each request only
 * the time left in the run's budget changed nothing about a run that stays
 * inside that budget, and the measured evidence that it bounds one that does
 * not.
 *
 * Two parties, both the REAL orchestrator (./probe.ts, ./protocol.ts,
 * ./auth.ts, …), differing only in the wire.ts they import:
 *
 *   1. The implementation: runProbe with the live ./wire.ts.
 *   2. FROZEN 0.7.0 — the same runProbe module graph loaded a second time with
 *      every `./wire.ts` import redirected to ./frozen/suite-0.7.0/wire.ts,
 *      byte-for-byte the suite 0.7.0 (c76de46) wire.ts apart from a four-line
 *      `// FROZEN:` header and a `../../` import path; the first test below
 *      recomputes its git blob id to prove it. The redirect is a module
 *      resolve hook scoped to a query tag, so nothing else in this process (or
 *      in any other test file — each runs in its own process) sees it, and the
 *      second test proves the two graphs really do run different wire code.
 *
 * Invariant, for every input below (all of them far inside the 10 s duration
 * budget): the two ProbeResults are identical (same own keys in the same order
 * at every level, Object.is on every leaf — stricter than equal JSON bytes),
 * and so is the request sequence the target sees (URL, method, headers, body).
 * Nothing is normalized: ProbeResult carries no suite version. The inputs are
 * the whole fixture corpus, crossed with the other budget dimensions (request
 * count, body size, redirect hops — all still enforced by wire.ts and all able
 * to abort a run), a GuardSignals report on each request position, an
 * approved-baseline mismatch, and GET redirect chains through the loop in
 * sendRequest that now recomputes the remaining time on every hop.
 *
 * The same comparison is repeated for ./frozen/suite-0.6.0/probe.ts, which
 * imports the live wire.ts: it shows the T86 differential
 * (probe-tool-name-differential.test.ts) is judging the same wire behaviour it
 * was written against for every in-budget input here.
 *
 * The out-of-budget half comes first, measured rather than argued: the same
 * slow target run through both graphs; the old one lets its last request run
 * to the end (up to twice the budget), the new one stops at the budget plus
 * timer slack.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import { FIXTURE_CORPUS, modernBaselineClean } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { runProbe as frozen060RunProbe } from './frozen/suite-0.6.0/probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { ApprovedBaseline, FetchLike, GuardSignals, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// The frozen copy is what it says it is.
// ---------------------------------------------------------------------------

/** `git rev-parse c76de46:packages/checks/src/wire.ts` (suite 0.7.0). */
const FROZEN_WIRE_BLOB = '4ad85e3cc63bf55220d4433f92dae7d953e90cec'

await t('the frozen 0.7.0 wire.ts is the c76de46 blob: header dropped, import path restored, git blob id recomputed', () => {
  const raw = readFileSync(new URL('./frozen/suite-0.7.0/wire.ts', import.meta.url), 'utf8').replace(/\r\n/g, '\n')
  const lines = raw.split('\n')
  let header = 0
  while (lines[header]!.startsWith('// FROZEN:')) header++
  assert.equal(header, 4, 'expected the four-line FROZEN header')
  const restored = lines.slice(header).map((l) => (l.startsWith('import ') ? l.replace("from '../../", "from './") : l)).join('\n')
  const bytes = Buffer.from(restored, 'utf8')
  const id = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
  assert.equal(id, FROZEN_WIRE_BLOB, 'frozen/suite-0.7.0/wire.ts is not the 0.7.0 file')
})

// ---------------------------------------------------------------------------
// A second copy of the orchestrator's module graph, wired to the frozen file.
// Any module under this src/ directory imported by a module carrying the tag
// is loaded again under the same tag; ./wire.ts itself becomes the frozen
// file. Packages outside src/ (@mcpcheckup/*, checks.json) stay shared — they
// hold no wire behaviour.
// ---------------------------------------------------------------------------

const TAG = 'wire=frozen-0.7.0'
const SRC_DIR = new URL('./', import.meta.url).href
const LIVE_WIRE = new URL('./wire.ts', import.meta.url).href
const FROZEN_WIRE = new URL('./frozen/suite-0.7.0/wire.ts', import.meta.url).href
let redirectedWireImports = 0

registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context)
    if (!context.parentURL?.includes(`?${TAG}`)) return resolved
    const url = new URL(resolved.url)
    url.search = ''
    if (!url.href.startsWith(SRC_DIR)) return resolved
    if (url.href === LIVE_WIRE) {
      redirectedWireImports++
      return { ...resolved, url: `${FROZEN_WIRE}?${TAG}`, shortCircuit: true }
    }
    return { ...resolved, url: `${url.href}?${TAG}`, shortCircuit: true }
  },
})

// Variable specifiers: tsc must not try to resolve the tagged URLs.
const frozenWireProbePath = `./probe.ts?${TAG}`
const frozen060FrozenWirePath = `./frozen/suite-0.6.0/probe.ts?${TAG}`
const oldRunProbe = ((await import(frozenWireProbePath)) as typeof import('./probe.ts')).runProbe
const oldFrozen060RunProbe = ((await import(frozen060FrozenWirePath)) as typeof import('./frozen/suite-0.6.0/probe.ts')).runProbe

type Probe = typeof runProbe

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

const ENDPOINT = 'https://notes-mcp.example.com/mcp'

interface Variant {
  budget: ProbeBudget
  approvedBaseline?: ApprovedBaseline
  /** 1-based request positions on which the transport reports GuardSignals. */
  signalOn?: { position: number; signals: GuardSignals }[]
  /** Every GET is answered with this many 302s before reaching the fixture. */
  getRedirects?: { hops: number; crossHost: boolean }
}

interface Run { result: ProbeResult; requests: string[]; fourthArgs: unknown[] }

async function runOnce(probe: Probe, createHandler: () => (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>, v: Variant): Promise<Run> {
  const handler = createHandler()
  const requests: string[] = []
  const fourthArgs: unknown[] = []
  let position = 0
  let redirectsServed = 0
  const fetchImpl: FetchLike = async (input, init, onGuardSignal, ...rest) => {
    position++
    fourthArgs.push(rest.length === 0 ? 'absent' : rest[0])
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = init?.method ?? 'GET'
    const headers: string[] = []
    new Headers(init?.headers).forEach((value, key) => { headers.push(`${key}: ${value}`) })
    requests.push(JSON.stringify([method, href, headers, typeof init?.body === 'string' ? init.body : null]))
    for (const s of v.signalOn ?? []) if (s.position === position) onGuardSignal(s.signals)
    if (method === 'GET' && v.getRedirects && redirectsServed < v.getRedirects.hops) {
      redirectsServed++
      const next = new URL(href)
      if (v.getRedirects.crossHost) next.hostname = `hop${redirectsServed}.example.net`
      next.searchParams.set('hop', String(redirectsServed))
      return new Response('', { status: 302, headers: { location: next.href } })
    }
    if (method === 'GET' && v.getRedirects) {
      // Hand the fixture the URL it was originally asked for.
      const original = new URL(href)
      original.searchParams.delete('hop')
      if (v.getRedirects.crossHost) original.hostname = new URL(ENDPOINT).hostname
      return handler(original.href, init)
    }
    return handler(input, init)
  }
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget: v.budget,
    now: () => '2026-09-23T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  return { result, requests, fourthArgs }
}

/** Identical own keys in identical order at every level, Object.is on every
 *  leaf — verbatim from probe-tool-name-differential.test.ts (T86). */
function identical(a: unknown, b: unknown): boolean {
  const stack: [unknown, unknown][] = [[a, b]]
  while (stack.length > 0) {
    const [x, y] = stack.pop()!
    if (x === null || y === null || typeof x !== 'object' || typeof y !== 'object') {
      if (!Object.is(x, y)) return false
      continue
    }
    if (Array.isArray(x) !== Array.isArray(y)) return false
    const kx = Object.keys(x), ky = Object.keys(y)
    if (kx.length !== ky.length || kx.some((k, i) => k !== ky[i])) return false
    for (const k of kx) stack.push([(x as Record<string, unknown>)[k], (y as Record<string, unknown>)[k]])
  }
  return true
}

// ---------------------------------------------------------------------------
// The two graphs really differ.
// ---------------------------------------------------------------------------

await t('the tagged graph runs the frozen wire.ts and the live graph does not: only the live one passes a 4th argument', async () => {
  const live = await runOnce(runProbe, modernBaselineClean.createHandler, { budget: DEFAULT_PROBE_BUDGET })
  const old = await runOnce(oldRunProbe, modernBaselineClean.createHandler, { budget: DEFAULT_PROBE_BUDGET })
  assert.ok(live.fourthArgs.length > 0 && old.fourthArgs.length === live.fourthArgs.length)
  for (const a of old.fourthArgs) assert.equal(a, 'absent', 'the frozen 0.7.0 wire.ts never passes a 4th argument')
  for (const a of live.fourthArgs) {
    const timeoutMs = (a as { timeoutMs?: unknown }).timeoutMs
    assert.ok(typeof timeoutMs === 'number' && timeoutMs > 0 && timeoutMs <= DEFAULT_PROBE_BUDGET.maxDurationMs, `live wire.ts must pass { timeoutMs } in (0, budget], got ${JSON.stringify(a)}`)
  }
  assert.ok(redirectedWireImports >= 3, `expected the tagged probe/protocol/auth to each import the frozen wire.ts, saw ${redirectedWireImports}`)
})

// ---------------------------------------------------------------------------
// Out of budget, measured: a target that takes 450 ms per request against a
// 600 ms budget. The fetchImpl ignores the 4th argument on purpose (as every
// fixture does), so what bounds the new run is sendRequest's own timer. The
// 150 ms between one request and the budget absorbs timer granularity (about
// 15 ms on Windows); each graph gets one unmeasured warm-up run first.
// ---------------------------------------------------------------------------

const SLOW_BUDGET: ProbeBudget = { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 600 }
const REQUEST_MS = 450
/** Timer lateness allowed on top of the budget (event-loop scheduling only). */
const SLACK_MS = 150

async function slowRun(probe: Probe, requestMs: number): Promise<{ result: ProbeResult; elapsedMs: number; requests: number }> {
  const handler = modernBaselineClean.createHandler()
  let requests = 0
  const fetchImpl: FetchLike = async (input, init) => {
    requests++
    await new Promise((r) => setTimeout(r, requestMs))
    return handler(input, init)
  }
  let seq = 0
  const begin = performance.now()
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget: SLOW_BUDGET,
    now: () => '2026-09-23T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  })
  return { result, elapsedMs: performance.now() - begin, requests }
}

const statusOf = (r: ProbeResult) => Object.fromEntries(r.assertions.map((a) => [a.check_id, `${a.execution_status}/${a.assertion_status}${a.reason ? ` ${a.reason.key}` : ''}`]))
const DURATION = `probe_budget_exhausted_duration`

await slowRun(oldRunProbe, 1)
await slowRun(runProbe, 1)

await t(`slow target, two ${REQUEST_MS} ms requests fit the old pre-request check: 0.7.0 lets the second one finish at ≈ ${2 * REQUEST_MS} ms, past the ${SLOW_BUDGET.maxDurationMs} ms budget; the new wire.ts stops at the budget`, async () => {
  const old = await slowRun(oldRunProbe, REQUEST_MS)
  const now = await slowRun(runProbe, REQUEST_MS)
  console.log(`       timings: 0.7.0 ${old.elapsedMs.toFixed(0)} ms (${old.requests} requests), new ${now.elapsedMs.toFixed(0)} ms (${now.requests} requests), budget ${SLOW_BUDGET.maxDurationMs} ms`)
  assert.ok(old.elapsedMs >= 2 * REQUEST_MS - 5, `0.7.0 should have let the second request run to completion (${old.elapsedMs} ms)`)
  assert.ok(now.elapsedMs <= SLOW_BUDGET.maxDurationMs + SLACK_MS, `new wire.ts overran the budget: ${now.elapsedMs} ms`)
  // Same two requests are started by both; only the new one cuts the second.
  assert.equal(now.requests, 2)
  assert.equal(old.requests, 2)

  const o = statusOf(old.result), n = statusOf(now.result)
  // Handshake (one request on this fixture) completed in budget either way.
  for (const id of ['reachability', 'discovery_handshake', 'protocol_revision', 'transport_type', 'latency_profile']) {
    assert.equal(n[id], 'COMPLETED/VERIFIED', id)
    assert.equal(o[id], 'COMPLETED/VERIFIED', id)
  }
  // 0.7.0: tools/list finished at ≈ 2 × REQUEST_MS and was judged; the pre-request
  // check then stopped tools/call.
  for (const id of ['tools_list', 'toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene']) assert.equal(o[id], 'COMPLETED/VERIFIED', `0.7.0 ${id}`)
  for (const id of ['error_taxonomy', 'auth_metadata', 'redirect_policy']) assert.equal(o[id], `SKIPPED/UNVERIFIED ${DURATION}`, `0.7.0 ${id}`)
  // New: tools/list is cut at the deadline, so it and everything after it
  // cascade with the duration key; no response past the deadline is judged.
  const cascaded = ['tools_list', 'toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene', 'toolset_unchanged_vs_approved', 'schema_unchanged_vs_approved', 'error_taxonomy', 'auth_metadata', 'redirect_policy']
  for (const id of cascaded) assert.equal(n[id], `SKIPPED/UNVERIFIED ${DURATION}`, `new ${id}`)
  for (const a of now.result.assertions) {
    if (cascaded.includes(a.check_id)) assert.deepStrictEqual(a.reason, { key: DURATION, params: { maxDurationMs: SLOW_BUDGET.maxDurationMs } })
  }
  assert.equal(now.result.toolSnapshot, undefined, 'a tools/list cut at the deadline yields no snapshot')
})

await t('slow target, the FIRST request outlives the whole budget: the new wire.ts ends it at the budget and reachability becomes ERROR/UNVERIFIED with the duration key (0.7.0 waited it out and called it VERIFIED)', async () => {
  const old = await slowRun(oldRunProbe, 800)
  const now = await slowRun(runProbe, 800)
  console.log(`       timings: 0.7.0 ${old.elapsedMs.toFixed(0)} ms, new ${now.elapsedMs.toFixed(0)} ms, budget ${SLOW_BUDGET.maxDurationMs} ms`)
  assert.ok(old.elapsedMs >= 800 - 5)
  assert.ok(now.elapsedMs <= SLOW_BUDGET.maxDurationMs + SLACK_MS, `new wire.ts overran the budget: ${now.elapsedMs} ms`)
  assert.equal(statusOf(old.result)['reachability'], 'COMPLETED/VERIFIED')
  const n = statusOf(now.result)
  assert.equal(n['reachability'], `ERROR/UNVERIFIED ${DURATION}`)
  for (const [id, s] of Object.entries(n)) {
    if (id === 'reachability') continue
    if (id === 'tls_certificate') assert.equal(s, 'SKIPPED/UNVERIFIED tls_certificate_out_of_scope')
    else assert.equal(s, `SKIPPED/UNVERIFIED ${DURATION}`, id)
  }
})

// ---------------------------------------------------------------------------
// The in-budget invariant.
// ---------------------------------------------------------------------------

function* variants(): Generator<[string, Variant]> {
  yield ['default', { budget: DEFAULT_PROBE_BUDGET }]
  for (let maxRequests = 0; maxRequests < DEFAULT_PROBE_BUDGET.maxRequests; maxRequests++) {
    yield [`maxRequests=${maxRequests}`, { budget: { ...DEFAULT_PROBE_BUDGET, maxRequests } }]
  }
  for (const maxBodyBytes of [0, 16, 200, 1024]) {
    yield [`maxBodyBytes=${maxBodyBytes}`, { budget: { ...DEFAULT_PROBE_BUDGET, maxBodyBytes } }]
  }
  yield ['baseline mismatch', { budget: DEFAULT_PROBE_BUDGET, approvedBaseline: { toolset_fingerprint: 'sha256:0', schema_fingerprint: 'sha256:0' } }]
  for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
    yield [`dns changed on request ${position}`, { budget: DEFAULT_PROBE_BUDGET, signalOn: [{ position, signals: { dnsAnswerChanged: true } }] }]
  }
  yield ['dns unchanged reported on every request', { budget: DEFAULT_PROBE_BUDGET, signalOn: Array.from({ length: 8 }, (_, i) => ({ position: i + 1, signals: { dnsAnswerChanged: false } })) }]
  for (const crossHost of [false, true]) {
    for (let hops = 1; hops <= DEFAULT_PROBE_BUDGET.maxRedirects + 1; hops++) {
      yield [`GET ${hops}×302 ${crossHost ? 'cross' : 'same'}-host`, { budget: DEFAULT_PROBE_BUDGET, getRedirects: { hops, crossHost } }]
      yield [`GET ${hops}×302 ${crossHost ? 'cross' : 'same'}-host, maxRedirects=1`, { budget: { ...DEFAULT_PROBE_BUDGET, maxRedirects: 1 }, getRedirects: { hops, crossHost } }]
    }
  }
}

let total = 0, violations = 0
const failures: string[] = []
const seen = { abortKeys: new Set<string>(), dnsDisqualified: 0, rateLimited: 0, redirectsFollowed: 0, crossHostRisk: 0, drift: 0, snapshots: 0 }
const started = Date.now()

for (const fixture of FIXTURE_CORPUS) {
  for (const [label, v] of variants()) {
    for (const [side, newProbe, oldProbe] of [['current', runProbe, oldRunProbe], ['0.6.0', frozen060RunProbe, oldFrozen060RunProbe]] as const) {
      total++
      const id = `${fixture.id} / ${label} / ${side} orchestrator`
      let now: Run, old: Run
      try {
        now = await runOnce(newProbe, fixture.createHandler, v)
        old = await runOnce(oldProbe, fixture.createHandler, v)
      } catch (e) {
        violations++
        if (failures.length < 200) failures.push(`${id}: threw ${(e as Error).message}`)
        continue
      }
      if (!identical(now.result, old.result)) {
        violations++
        if (failures.length < 200) failures.push(`${id}: ProbeResult differs\n           new ${JSON.stringify(now.result).slice(0, 400)}\n           old ${JSON.stringify(old.result).slice(0, 400)}`)
      }
      if (!identical(now.requests, old.requests)) {
        violations++
        if (failures.length < 200) failures.push(`${id}: request sequence differs\n           new ${now.requests.join(' | ')}\n           old ${old.requests.join(' | ')}`)
      }
      if (side === 'current') {
        for (const a of now.result.assertions) if (a.execution_status === 'SKIPPED' && a.reason?.key.startsWith('probe_')) seen.abortKeys.add(a.reason.key)
        if (now.result.disqualifiedFromPublication) seen.dnsDisqualified++
        if (now.result.rateLimited) seen.rateLimited++
        if (v.getRedirects && now.requests.some((r) => r.includes('hop='))) seen.redirectsFollowed++
        if (now.result.assertions.some((a) => a.check_id === 'redirect_policy' && a.assertion_status === 'OBSERVED_RISK')) seen.crossHostRisk++
        if (now.result.driftEvents.length > 0) seen.drift++
        if (now.result.toolSnapshot) seen.snapshots++
      }
    }
  }
}

console.log(`  inputs: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants × 2 orchestrators = ${total}; ${((Date.now() - started) / 1000).toFixed(1)}s`)
console.log(`  seen: abort keys ${[...seen.abortKeys].sort().join(',')}; dns-disqualified ${seen.dnsDisqualified}; rate-limited ${seen.rateLimited}; GET redirects followed ${seen.redirectsFollowed}; redirect_policy OBSERVED_RISK ${seen.crossHostRisk}; drift ${seen.drift}; snapshots ${seen.snapshots}`)

await t(`in budget, the new wire.ts is indistinguishable from 0.7.0's: all ${total} inputs give identical ProbeResults and request sequences`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: every other budget abort, the rate-limit stop, the DNS disqualification, drift, snapshots and followed GET redirects all occur', () => {
  assert.ok(FIXTURE_CORPUS.length >= 70, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const key of ['probe_budget_exhausted_requests', 'probe_budget_exhausted_body', 'probe_budget_exhausted_redirects', 'probe_rate_limited']) {
    assert.ok(seen.abortKeys.has(key), `${key} never produced`)
  }
  assert.ok(!seen.abortKeys.has('probe_budget_exhausted_duration'), 'no in-budget input may run out of time')
  for (const [what, n] of Object.entries(seen)) if (typeof n === 'number') assert.ok(n > 0, `${what} never seen`)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
