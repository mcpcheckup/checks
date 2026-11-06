/**
 * Suite 0.19.3 differential (TODO 1902): the evidence that handing each call a
 * signal, aborted once sendRequest's timer has put the step down, changes no
 * assertion anywhere, and changes what the target sees in exactly two named
 * scenarios.
 *
 * Two parties, both the REAL orchestrator (./probe.ts, ./protocol.ts,
 * ./auth.ts, …), differing only in the wire.ts they import:
 *
 *   1. NEW: runProbe with the live ./wire.ts.
 *   2. OLD: the same module graph loaded a second time with every `./wire.ts`
 *      import redirected to ./frozen/suite-0.18.0/src/wire.ts. That file is
 *      byte for byte the wire.ts suite 0.19.2 shipped (wire.ts did not change
 *      from suite 0.16.0 to 0.19.2; suite-0190-differential.test.ts pins the
 *      same blob); the first test recomputes its git blob id. The redirect is
 *      the module resolve hook of wire-budget-differential.test.ts, scoped to a
 *      query tag, so nothing else in this process sees it, and the second test
 *      proves the two graphs run different wire code.
 *
 * A + B: suite-0180-differential.test.ts's input sets (the fixture corpus ×
 * budget / GuardSignals / baseline / GET-redirect variants; and the corpus with
 * request p throwing), over an untimed and a timed transport. These transports,
 * like every fixture, ignore the fourth argument.
 * C: wire-budget-differential.test.ts's two out-of-budget runs (a slow target
 * cut at the deadline), with the same kind of transport.
 * G: runs through the REAL guardedFetch (@mcpcheckup/ssrf-guard), stubbed only
 * at its DNS lookups and its transport to the target, behind a FetchLike built
 * like the probe's production one (time left plus a 500 ms grace, no redirect
 * followed, the signal handed on when there is one): one in budget, and the two
 * exceptions below.
 *
 * Invariant, for every input: the assertions are identical one by one
 * (check_id, execution_status, assertion_status, reason, details: same own keys
 * in the same order at every level, Object.is on every leaf), and so is the whole
 * ProbeResult; the requests the orchestrator makes are identical; and what the
 * target sees is identical, EXCEPT in the scenarios EXCEPTIONS names, where it
 * must differ in exactly the way that entry states and nothing else may.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { DEFAULT_PROBE_BUDGET, SsrfBlocked, guardedFetch } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget, RateLimitDecision, ResolvedAddress } from '@mcpcheckup/ssrf-guard'
import { FIXTURE_CORPUS, modernBaselineClean } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { OtherHostDeclined } from './other-host-declined.ts'
import { recordRequest } from './suite-0130-remap.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { ApprovedBaseline, FetchLike, GuardSignals, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// What is being compared, and the version it ships as.
// ---------------------------------------------------------------------------

const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}
const readHere = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8')

/** `git rev-parse 18097f8d:packages/checks/src/wire.ts` — suite 0.19.2's wire.ts. */
const SUITE_0192_WIRE_BLOB = '4eaaee5217f9acc55457191b123bc27127a83505'
/** `git rev-parse 18097f8d:packages/checks/src/latency.ts` — the one module the old wire.ts runs besides itself. */
const SUITE_0192_LATENCY_BLOB = '64947a43c414ded3590e599a7f08569391da6bef'

await t('the old side is suite 0.19.2\'s wire.ts: frozen/suite-0.18.0/src/wire.ts (and the latency.ts it runs) are the 18097f8d blobs, git blob id recomputed; the live wire.ts is not', () => {
  assert.equal(blobId(readHere('./frozen/suite-0.18.0/src/wire.ts')), SUITE_0192_WIRE_BLOB)
  assert.equal(blobId(readHere('./frozen/suite-0.18.0/src/latency.ts')), SUITE_0192_LATENCY_BLOB)
  assert.notEqual(blobId(readHere('./wire.ts')), SUITE_0192_WIRE_BLOB)
})

await t('packages/checks ships this change as suite 0.19.3', () => {
  assert.equal((JSON.parse(readHere('../package.json')) as { version: string }).version, '0.19.3')
})

// ---------------------------------------------------------------------------
// The old module graph.
// ---------------------------------------------------------------------------

const TAG = 'wire=suite-0.19.2'
const SRC_DIR = new URL('./', import.meta.url).href
const LIVE_WIRE = new URL('./wire.ts', import.meta.url).href
const OLD_WIRE = new URL('./frozen/suite-0.18.0/src/wire.ts', import.meta.url).href
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
      return { ...resolved, url: `${OLD_WIRE}?${TAG}`, shortCircuit: true }
    }
    return { ...resolved, url: `${url.href}?${TAG}`, shortCircuit: true }
  },
})

// Variable specifiers: tsc must not try to resolve the tagged URLs.
const oldProbePath = `./probe.ts?${TAG}`
const oldDeclinedPath = `./other-host-declined.ts?${TAG}`
const oldRunProbe = ((await import(oldProbePath)) as typeof import('./probe.ts')).runProbe
const OldOtherHostDeclined = ((await import(oldDeclinedPath)) as typeof import('./other-host-declined.ts')).OtherHostDeclined

type Probe = typeof runProbe
type Handler = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

const ENDPOINT = 'https://notes-mcp.example.com/mcp'

async function probeWith(probe: Probe, fetchImpl: FetchLike, budget: ProbeBudget, approvedBaseline?: ApprovedBaseline): Promise<ProbeResult> {
  let seq = 0
  return probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget,
    now: () => '2026-11-06T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(approvedBaseline ? { approvedBaseline } : {}),
  })
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

await t('the tagged graph runs the old wire.ts and the live graph does not: only the live one hands each call a signal', async () => {
  const seen = { live: [] as unknown[], old: [] as unknown[] }
  const handlerFor = (side: unknown[]): FetchLike => {
    const handler = modernBaselineClean.createHandler()
    return async (input, init, _s, ...rest) => { side.push(rest[0]); return handler(input, init) }
  }
  await probeWith(runProbe, handlerFor(seen.live), DEFAULT_PROBE_BUDGET)
  await probeWith(oldRunProbe, handlerFor(seen.old), DEFAULT_PROBE_BUDGET)
  assert.ok(seen.live.length > 0 && seen.old.length === seen.live.length)
  for (const o of seen.old) assert.deepEqual(Object.keys(o as object), ['timeoutMs'])
  for (const o of seen.live) {
    assert.deepEqual(Object.keys(o as object), ['timeoutMs', 'signal'])
    assert.ok((o as { signal: unknown }).signal instanceof AbortSignal)
  }
  assert.ok(redirectedWireImports >= 3, `expected the tagged probe/protocol/auth to each import the old wire.ts, saw ${redirectedWireImports}`)
})

// ---------------------------------------------------------------------------
// The comparison, and the two exceptions.
// ---------------------------------------------------------------------------

interface Run {
  result: ProbeResult
  /** The calls the orchestrator made to its FetchLike, in order. */
  requests: string[]
  /** What the target saw, in order (for A, B and C: the same calls). */
  traffic: string[]
  threw?: boolean
  /** G only, for the log: how long after the deadline each open request was aborted, in ms. */
  abortedLateMs?: number[]
}

/** The only scenarios in which the target may see something different, each with
 *  exactly what it sees on the old side and on the new. Their assertions must
 *  still be identical. */
const EXCEPTIONS: Record<string, { why: string; old: string[]; new: string[] }> = {
  'G (i) the DoH answer for request 2 arrives after the deadline': {
    why: 'the guard\'s request is never dispatched after the deadline',
    old: ['request 1, sent before the deadline, answered in full', 'request 2, sent after the deadline, answered in full'],
    new: ['request 1, sent before the deadline, answered in full'],
  },
  'G (ii) request 2\'s body sends one chunk and then hangs': {
    why: 'the abandoned step\'s in-flight fetch and body read are aborted at the deadline',
    old: ['request 1, sent before the deadline, answered in full', "request 2, sent before the deadline, aborted by the guard's own timeout, no read after it"],
    new: ['request 1, sent before the deadline, answered in full', "request 2, sent before the deadline, aborted by the step's signal, no read after it"],
  },
}

let total = 0, violations = 0
const failures: string[] = []
const trafficDiffered = new Set<string>()
function violation(id: string, what: string) {
  violations++
  if (failures.length < 200) failures.push(`${id}: ${what}`)
}

/** Every assertion, one by one, then the whole result; then the orchestrator's
 *  requests; then the target's traffic, which may differ only as EXCEPTIONS says. */
function compare(id: string, now: Run, old: Run) {
  total++
  const a = now.result.assertions, b = old.result.assertions
  if (a.length !== b.length) violation(id, `${a.length} assertions vs ${b.length}`)
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (!identical(a[i], b[i])) violation(id, `assertion ${i} differs\n           new ${JSON.stringify(a[i])}\n           old ${JSON.stringify(b[i])}`)
  }
  if (!identical(now.result, old.result)) violation(id, 'ProbeResult differs')
  if (!identical(now.requests, old.requests)) violation(id, `requests differ\n           new ${now.requests.join(' | ')}\n           old ${old.requests.join(' | ')}`)
  if (now.threw !== old.threw) violation(id, 'one side reached the throwing request and the other did not')
  const exception = EXCEPTIONS[id]
  if (!identical(now.traffic, old.traffic)) trafficDiffered.add(id)
  if (exception === undefined) {
    if (trafficDiffered.has(id)) violation(id, `target traffic differs\n           new ${now.traffic.join(' | ')}\n           old ${old.traffic.join(' | ')}`)
  } else if (!identical(old.traffic, exception.old) || !identical(now.traffic, exception.new)) {
    violation(id, `target traffic is not the named exception\n           new ${now.traffic.join(' | ')}\n           old ${old.traffic.join(' | ')}`)
  }
}

const seen = { abortKeys: new Set<string>(), dnsDisqualified: 0, rateLimited: 0, redirectsFollowed: 0, drift: 0, snapshots: 0, threw: 0 }
function note(r: Run) {
  for (const a of r.result.assertions) if (a.reason?.key.startsWith('probe_')) seen.abortKeys.add(a.reason.key)
  if (r.result.disqualifiedFromPublication) seen.dnsDisqualified++
  if (r.result.rateLimited) seen.rateLimited++
  if (r.requests.some((q) => q.includes('hop='))) seen.redirectsFollowed++
  if (r.result.driftEvents.length > 0) seen.drift++
  if (r.result.toolSnapshot) seen.snapshots++
  if (r.threw) seen.threw++
}

// ---------------------------------------------------------------------------
// C: out of budget, as wire-budget-differential.test.ts measures it.
// ---------------------------------------------------------------------------

const SLOW_BUDGET: ProbeBudget = { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 600 }

async function slowRun(probe: Probe, requestMs: number): Promise<Run> {
  const handler = modernBaselineClean.createHandler()
  const requests: string[] = []
  const fetchImpl: FetchLike = async (input, init) => {
    requests.push(recordRequest(input, init))
    await new Promise((r) => setTimeout(r, requestMs))
    return handler(input, init)
  }
  const result = await probeWith(probe, fetchImpl, SLOW_BUDGET)
  return { result, requests, traffic: requests }
}

for (const requestMs of [450, 800]) {
  const id = `C slow target, ${requestMs} ms per request, ${SLOW_BUDGET.maxDurationMs} ms budget`
  const now = await slowRun(runProbe, requestMs)
  const old = await slowRun(oldRunProbe, requestMs)
  compare(id, now, old)
  note(now)
}

// ---------------------------------------------------------------------------
// G: through the real guardedFetch.
// ---------------------------------------------------------------------------

const ALLOW: RateLimitDecision = { allowed: true, scope: [] }
const PUBLIC: ResolvedAddress[] = [{ ip: '93.184.216.34', family: 4 }]
/** The production FetchLike's GUARDED_FETCH_GRACE_MS. */
const GRACE_MS = 500
const G_BUDGET: ProbeBudget = { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 400 }
const sleepUntil = (atMs: number) => new Promise<void>((r) => setTimeout(r, Math.max(0, atMs - Date.now())))

interface GuardScenario {
  /** Before the pre-send lookup of request n (1-based) returns. */
  lookup?: (n: number, deadline: number) => Promise<void>
  /** Request n's response body, if not the fixture's own. */
  body?: (n: number, signal: AbortSignal, onRead: () => void) => ReadableStream<Uint8Array> | undefined
}

async function guardRun(probe: Probe, s: GuardScenario): Promise<Run> {
  const handler = modernBaselineClean.createHandler()
  const requests: string[] = []
  const sent: { request: number; at: number; signal: AbortSignal; done: boolean; abortedAt?: number; abortedBy?: string; readsAtAbort?: number; reads: () => number }[] = []
  const pending: Promise<unknown>[] = []
  let lookups = 0
  // The run's deadline as sendRequest computes it, read off the first call: timeoutMs is the
  // time left, computed just before that call (both wire.ts versions pass it).
  let deadline = Number.POSITIVE_INFINITY
  const target = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = sent.length + 1
    let reads = 0
    const entry = { request, at: Date.now(), signal: init!.signal!, done: false, reads: () => reads } as (typeof sent)[number]
    sent.push(entry)
    // An abort counts only while the exchange is still open: the request's own timeout
    // signal also fires, harmlessly, after a response that was read to the end.
    entry.signal.addEventListener('abort', () => { if (!entry.done) { entry.abortedAt = Date.now(); entry.abortedBy = (entry.signal.reason as { name?: unknown } | undefined)?.name as string; entry.readsAtAbort = reads } }, { once: true })
    const answer = await handler(input, init)
    const body = s.body?.(request, entry.signal, () => { reads++ })
    if (body !== undefined) return new Response(body, { status: answer.status, headers: answer.headers })
    if (answer.body === null) { entry.done = true; return answer }
    const reader = answer.body.getReader()
    const counted = new ReadableStream<Uint8Array>({
      async pull(controller) {
        reads++
        const r = await reader.read()
        if (r.done) { entry.done = true; controller.close() } else controller.enqueue(r.value)
      },
    })
    return new Response(counted, { status: answer.status, headers: answer.headers })
  }
  const fetchImpl: FetchLike = (input, init, onGuardSignal, options) => {
    if (options === undefined) throw new Error('both wire.ts versions pass { timeoutMs }')
    if (deadline === Number.POSITIVE_INFINITY) deadline = Date.now() + options.timeoutMs
    requests.push(recordRequest(input, init))
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const headers: Record<string, string> = { 'user-agent': 'suite-0193-differential' }
    new Headers(init?.headers).forEach((value, key) => { headers[key] = value })
    const body = typeof init?.body === 'string' ? init.body : undefined
    const call = guardedFetch(href, { ...G_BUDGET, maxDurationMs: Math.min(G_BUDGET.maxDurationMs, options.timeoutMs) + GRACE_MS }, ALLOW, {
      callerIdentifier: 'suite-0193-differential',
      method: (init?.method?.toUpperCase() ?? 'GET') as 'GET' | 'POST',
      headers,
      ...(body !== undefined ? { body } : {}),
      followRedirects: false,
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      fetchImpl: target as typeof fetch,
      resolveAndValidateHostImpl: async () => { const n = ++lookups; await s.lookup?.(n, deadline); return PUBLIC },
      resolveHostImpl: async () => PUBLIC,
      parseResponse: async (h) => ({ status: h.status, headers: h.headers, bytes: await h.bytes() }),
      onAudit: (record) => onGuardSignal({ dnsAnswerChanged: record.dnsAnswerChangedDuringProbe }),
    })
    pending.push(call.catch(() => {}))
    return call.then(({ result }) => new Response([204, 205, 304].includes(result.status) ? null : (result.bytes as BodyInit), { status: result.status, headers: result.headers }))
  }
  const result = await probeWith(probe, fetchImpl, G_BUDGET)
  // Let every abandoned call finish (old side: up to the deadline plus the grace).
  await sleepUntil(deadline + GRACE_MS + 150)
  await Promise.all(pending)
  const traffic = sent.map((e) => {
    const when = e.at <= deadline ? 'sent before the deadline' : 'sent after the deadline'
    if (e.abortedAt === undefined) return `request ${e.request}, ${when}, ${e.done ? 'answered in full' : 'still open'}`
    // Classified by WHO aborted, read off the signal's reason, not by when: the request's init.signal is
    // guardedFetch's own AbortSignal.timeout (reason: a TimeoutError) or, when the caller passed a signal,
    // AbortSignal.any of that and the caller's, whose reason is that of whichever fired first. The step's
    // controller is aborted without a reason, i.e. with an AbortError. The only time check left is a sanity
    // bound: the step's signal never fires before the deadline (timer firing up to 2 ms early is allowed,
    // as in wire.test.ts).
    const late = e.abortedAt - deadline
    const aborted = e.abortedBy === 'AbortError'
      ? (late >= -2 ? "aborted by the step's signal" : `aborted by the step's signal ${-late} ms before the deadline`)
      : e.abortedBy === 'TimeoutError' ? "aborted by the guard's own timeout" : `aborted (${String(e.abortedBy)})`
    return `request ${e.request}, ${when}, ${aborted}, ${e.reads() === e.readsAtAbort ? 'no read after it' : 'read after it'}`
  })
  const abortedLateMs = sent.flatMap((e) => (e.abortedAt === undefined ? [] : [e.abortedAt - deadline]))
  return { result, requests, traffic, abortedLateMs }
}

/** One chunk, then a read that waits until the request's signal aborts (the body then errors, as the platform's does). */
const oneChunkThenHang = (signal: AbortSignal, onRead: () => void) => {
  let first = true
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      onRead()
      if (first) { first = false; controller.enqueue(new TextEncoder().encode('{"jsonrpc":')); return }
      return new Promise<void>((resolve) => {
        const end = () => { controller.error(signal.reason); resolve() }
        if (signal.aborted) end(); else signal.addEventListener('abort', end, { once: true })
      })
    },
  })
}

const GUARD_SCENARIOS: [string, GuardScenario][] = [
  ['G in budget, nothing late', {}],
  ['G (i) the DoH answer for request 2 arrives after the deadline', { lookup: async (n, deadline) => { if (n === 2) await sleepUntil(deadline + 100) } }],
  ['G (ii) request 2\'s body sends one chunk and then hangs', { body: (n, signal, onRead) => (n === 2 ? oneChunkThenHang(signal, onRead) : undefined) }],
]

const guardStatus = new Map<string, string>()
for (const [id, s] of GUARD_SCENARIOS) {
  const now = await guardRun(runProbe, s)
  const old = await guardRun(oldRunProbe, s)
  compare(id, now, old)
  note(now)
  const durationRows = now.result.assertions.filter((a) => a.reason?.key === 'probe_budget_exhausted_duration').length
  guardStatus.set(id, `${now.result.assertions.find((a) => a.check_id === 'reachability')!.execution_status}; ${durationRows} rows probe_budget_exhausted_duration; ${now.requests.length} calls; aborted late by new [${now.abortedLateMs!.join(', ')}] ms, old [${old.abortedLateMs!.join(', ')}] ms; traffic new [${now.traffic.join(' | ')}] old [${old.traffic.join(' | ')}]`)
}
for (const [id, line] of guardStatus) console.log(`  ${id}: reachability ${line}`)

// ---------------------------------------------------------------------------
// A + B: the corpus, as suite-0180-differential.test.ts runs it.
// ---------------------------------------------------------------------------

interface Variant {
  budget: ProbeBudget
  approvedBaseline?: ApprovedBaseline
  signalOn?: { position: number; signals: GuardSignals }[]
  getRedirects?: { hops: number; crossHost: boolean }
  throwAt?: { position: number; make: () => unknown }
}

const timeFor = (position: number) => 5 + ((position * 37) % 90)

async function corpusRun(probe: Probe, createHandler: () => Handler, v: Variant, timed: boolean): Promise<Run> {
  const handler = createHandler()
  const requests: string[] = []
  let position = 0
  let redirectsServed = 0
  let threw = false
  const transport: FetchLike = async (input, init, onGuardSignal) => {
    position++
    const at = position
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    requests.push(recordRequest(input, init))
    if (v.throwAt && v.throwAt.position === at) { threw = true; throw v.throwAt.make() }
    for (const s of v.signalOn ?? []) if (s.position === at) onGuardSignal(s.signals)
    let response: Response
    if (method === 'GET' && v.getRedirects && redirectsServed < v.getRedirects.hops) {
      redirectsServed++
      const next = new URL(href)
      if (v.getRedirects.crossHost) next.hostname = `hop${redirectsServed}.example.com`
      next.searchParams.set('hop', String(redirectsServed))
      response = new Response('', { status: 302, headers: { location: next.href } })
    } else if (method === 'GET' && v.getRedirects) {
      const original = new URL(href)
      original.searchParams.delete('hop')
      if (v.getRedirects.crossHost) original.hostname = new URL(ENDPOINT).hostname
      response = await handler(original.href, init)
    } else {
      response = await handler(input, init)
    }
    if (timed) onGuardSignal({ responseHeadersMs: timeFor(at) })
    return response
  }
  const result = await probeWith(probe, transport, v.budget, v.approvedBaseline)
  return { result, requests, traffic: requests, threw }
}

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
      yield [`GET ${hops}×302 ${crossHost ? 'cross' : 'same'}-host, maxRedirects=0`, { budget: { ...DEFAULT_PROBE_BUDGET, maxRedirects: 0 }, getRedirects: { hops, crossHost } }]
    }
  }
}

/** [label, the error as the new graph receives it, the same error as the old graph receives it]. */
const ERRORS: [string, () => unknown, () => unknown][] = [
  ['OtherHostDeclined', () => new OtherHostDeclined(), () => new OldOtherHostDeclined()],
  ['own Error (adapter argument check)', () => new TypeError('guarded-fetch-adapter: unsupported request body type'), () => new TypeError('guarded-fetch-adapter: unsupported request body type')],
  ['guard PRIVATE_USE', () => Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 }), () => Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 })],
]

const started = Date.now()
let totalA = 0, totalB = 0
for (const timed of [false, true]) {
  for (const fixture of FIXTURE_CORPUS) {
    for (const [label, v] of variants()) {
      totalA++
      const id = `A ${timed ? 'timed' : 'untimed'} ${fixture.id} / ${label}`
      try {
        const now = await corpusRun(runProbe, fixture.createHandler, v, timed)
        const old = await corpusRun(oldRunProbe, fixture.createHandler, v, timed)
        compare(id, now, old)
        note(now)
      } catch (e) {
        violation(id, `threw ${(e as Error).message}`)
      }
    }
    for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
      for (const [label, make, makeOld] of ERRORS) {
        totalB++
        const id = `B ${timed ? 'timed' : 'untimed'} ${fixture.id} / ${label} @ request ${position}`
        try {
          const now = await corpusRun(runProbe, fixture.createHandler, { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make } }, timed)
          const old = await corpusRun(oldRunProbe, fixture.createHandler, { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make: makeOld } }, timed)
          compare(id, now, old)
          note(now)
        } catch (e) {
          violation(id, `threw ${(e as Error).message}`)
        }
      }
    }
  }
}
console.log(`  A: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants × 2 transports = ${totalA}; B: ${FIXTURE_CORPUS.length} fixtures × ${DEFAULT_PROBE_BUDGET.maxRequests} positions × ${ERRORS.length} errors × 2 transports = ${totalB}; ${((Date.now() - started) / 1000).toFixed(1)}s`)

// ---------------------------------------------------------------------------
// Verdicts.
// ---------------------------------------------------------------------------

const report = (n: number, list: string[]) => `${n} violation(s)\n         ${list.slice(0, 25).join('\n         ')}${list.length > 25 ? '\n         … and more' : ''}`

await t(`every one of the ${total} inputs (A ${totalA}, B ${totalB}, C 2, G ${GUARD_SCENARIOS.length}): identical assertions one by one and identical ProbeResults; identical requests; identical target traffic outside the ${Object.keys(EXCEPTIONS).length} named exceptions`, () => {
  if (violations > 0) throw new Error(report(violations, failures))
})

await t('the exceptions are exact: each named exception is a scenario that ran and whose target traffic did differ, and no other scenario\'s did', () => {
  const ran = new Set(GUARD_SCENARIOS.map(([id]) => id))
  for (const id of Object.keys(EXCEPTIONS)) assert.ok(ran.has(id), `${id} never ran`)
  assert.deepStrictEqual([...trafficDiffered].sort(), Object.keys(EXCEPTIONS).sort())
  assert.deepStrictEqual(Object.values(EXCEPTIONS).map((e) => e.why), [
    'the guard\'s request is never dispatched after the deadline',
    'the abandoned step\'s in-flight fetch and body read are aborted at the deadline',
  ])
})

await t('the inputs are not vacuous: every budget abort (the duration one included), the rate-limit stop, the DNS disqualification, drift, snapshots, followed GET redirects and thrown requests all occur', () => {
  assert.ok(FIXTURE_CORPUS.length >= 70, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const key of ['probe_budget_exhausted_requests', 'probe_budget_exhausted_body', 'probe_budget_exhausted_redirects', 'probe_budget_exhausted_duration', 'probe_rate_limited']) {
    assert.ok(seen.abortKeys.has(key), `${key} never produced`)
  }
  for (const [what, n] of Object.entries(seen)) if (typeof n === 'number') assert.ok(n > 0, `${what} never seen`)
  // G: the run in budget finishes inside it; both exceptions end at the deadline.
  assert.match(guardStatus.get('G in budget, nothing late')!, /^COMPLETED; 0 rows probe_budget_exhausted_duration;/)
  for (const id of Object.keys(EXCEPTIONS)) assert.match(guardStatus.get(id)!, /^COMPLETED; [1-9]\d* rows probe_budget_exhausted_duration;/, id)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
