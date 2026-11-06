/**
 * TODO 1902 (PR-1): the deadline is checked again after every DoH await and
 * before sending, and guardedFetch takes a `signal` — "the caller has given
 * up". Both only ever end a call sooner, as BudgetExceeded('MAX_DURATION').
 *
 *   (i)   a lookup that returns at/after the deadline, or after the caller
 *         aborted, sends nothing (0 fetchImpl calls);
 *   (ii)  an abort reaches the target fetch (init.signal), stops the body
 *         read (a hung read is cancelled, and the cancelled read's done: true
 *         is never a shorter success), whatever the abort's reason;
 *   (iii) with no signal, the request is built exactly as before.
 */
import assert from 'node:assert'
import { guardedFetch } from './guarded-fetch.ts'
import { createSafeResponseHandle, type SafeResponseHandle } from './response-view.ts'
import { DEFAULT_PROBE_BUDGET, type ProbeBudget } from './budget.ts'
import { BudgetExceeded, UpstreamFetchFailed } from './errors.ts'
import type { ProbeAuditRecord } from './audit.ts'
import type { RateLimitDecision } from './rate-limit.ts'
import type { ResolvedAddress } from './resolve.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ALLOW: RateLimitDecision = { allowed: true, scope: [] }
const PUBLIC: ResolvedAddress[] = [{ ip: '1.1.1.1', family: 4 }]
const resolvePublic = async (): Promise<ResolvedAddress[]> => PUBLIC
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms))
const budget = (maxDurationMs: number): ProbeBudget => ({ ...DEFAULT_PROBE_BUDGET, maxDurationMs })
/** Rejects with a named error if `p` has not settled within 3 s (a ref'd timer, unlike AbortSignal.timeout's). */
function withCap<T>(p: Promise<T>): Promise<T> {
  let cap: ReturnType<typeof setTimeout> | undefined
  const capped = new Promise<never>((_r, reject) => { cap = setTimeout(() => reject(new Error('test cap: did not settle within 3 s')), 3000) })
  return Promise.race([capped, p]).finally(() => clearTimeout(cap))
}

interface Sent { url: string; init: RequestInit }
interface Outcome { value?: unknown; error?: unknown; audit: ProbeAuditRecord | undefined; sent: Sent[]; parseCalls: number; ms: number }

async function call(opts: {
  url?: string
  budget?: ProbeBudget
  respond?: (url: string, init: RequestInit) => Promise<Response>
  validate?: (host: string) => Promise<ResolvedAddress[]>
  recheck?: (host: string) => Promise<ResolvedAddress[]>
  parse?: (h: SafeResponseHandle) => unknown
  signal?: AbortSignal
}): Promise<Outcome> {
  const sent: Sent[] = []
  let audit: ProbeAuditRecord | undefined
  let parseCalls = 0
  const started = Date.now()
  const fetchImpl = async (input: unknown, init?: RequestInit): Promise<Response> => {
    sent.push({ url: String(input), init: init! })
    return (opts.respond ?? (async () => new Response('ok', { status: 200 })))(String(input), init!)
  }
  try {
    // withCap: a call that never settles fails by name instead of the process exiting early.
    const r = await withCap(guardedFetch(opts.url ?? 'https://example.com/mcp', opts.budget ?? DEFAULT_PROBE_BUDGET, ALLOW, {
      callerIdentifier: 'caller-signal.test',
      fetchImpl: fetchImpl as typeof fetch,
      resolveAndValidateHostImpl: opts.validate ?? resolvePublic,
      resolveHostImpl: opts.recheck ?? resolvePublic,
      parseResponse: (h) => { parseCalls++; return (opts.parse ?? ((x) => x.text()))(h) },
      onAudit: (rec) => { audit = rec },
      ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
    }))
    return { value: r.result, audit, sent, parseCalls, ms: Date.now() - started }
  } catch (error) {
    return { error, audit, sent, parseCalls, ms: Date.now() - started }
  }
}

function assertDuration(o: Outcome, hop: number) {
  assert.ok(o.error instanceof BudgetExceeded, `expected BudgetExceeded, got ${String(o.error)} / value ${JSON.stringify(o.value)}`)
  assert.equal((o.error as BudgetExceeded).code, 'MAX_DURATION')
  assert.equal((o.error as BudgetExceeded).hop, hop)
  assert.equal(o.audit?.outcome, 'budget_exceeded')
}

/** A fetch stub that behaves like the runtime's: it settles only when init.signal aborts, rejecting with its reason. */
const hangUntilAborted = (_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
  const s = init.signal!
  if (s.aborted) { reject(s.reason); return }
  s.addEventListener('abort', () => reject(s.reason), { once: true })
})

/** A response whose body reader is ours: counts reads and cancels; read 1 gives a chunk, read 2 hangs until cancel (done: true). */
function hangingBody(onSecondRead?: () => void, secondRead: 'cancel-settles' | 'reject-with-reason' = 'cancel-settles', signalForReason?: () => AbortSignal | undefined) {
  const counts = { reads: 0, cancels: 0 }
  let settlePending: ((r: ReadableStreamReadResult<Uint8Array>) => void) | undefined
  const reader = {
    read(): Promise<ReadableStreamReadResult<Uint8Array>> {
      counts.reads++
      if (counts.reads === 1) return Promise.resolve({ done: false, value: new TextEncoder().encode('partial') })
      return new Promise((resolve, reject) => {
        settlePending = resolve
        if (secondRead === 'reject-with-reason') {
          const s = signalForReason?.()
          s?.addEventListener('abort', () => reject(s.reason), { once: true })
          settlePending = undefined
        }
        onSecondRead?.()
      })
    },
    cancel(): Promise<void> {
      counts.cancels++
      settlePending?.({ done: true, value: undefined })
      settlePending = undefined
      return Promise.resolve()
    },
  }
  const response = {
    status: 200,
    headers: new Headers(),
    body: { getReader: () => reader, cancel: () => reader.cancel() },
  } as unknown as Response
  return { response, counts }
}

console.log('(i) the deadline is checked after every DoH await and before sending')

await t('(i) red proof: budget 20 ms, DoH answers after 40 ms -> MAX_DURATION at hop 0, 0 fetchImpl calls (main: 1)', async () => {
  const o = await call({ budget: budget(20), validate: async () => { await sleep(40); return PUBLIC } })
  assert.equal(o.sent.length, 0)
  assertDuration(o, 0)
})

await t('(i) after one followed redirect: hop 1\'s DoH answers past the deadline -> MAX_DURATION at hop 1, hop 1 never sent', async () => {
  let lookups = 0
  const o = await call({
    budget: budget(150),
    validate: async () => { if (++lookups === 2) await sleep(250); return PUBLIC },
    respond: async () => new Response(null, { status: 302, headers: { location: 'https://example.com/next' } }),
  })
  assertDuration(o, 1)
  assert.deepEqual(o.sent.map((s) => s.url), ['https://example.com/mcp'])
})

await t('(i) the post-fetch DNS re-check of a 302 returning past the deadline: the redirect is not requested — MAX_DURATION at hop 1, one request sent', async () => {
  const o = await call({
    budget: budget(60),
    recheck: async () => { await sleep(120); return PUBLIC },
    respond: async () => new Response(null, { status: 302, headers: { location: 'https://example.com/next' } }),
  })
  assertDuration(o, 1)
  assert.deepEqual(o.sent.map((s) => s.url), ['https://example.com/mcp'])
})

await t('(i) the deadline is not re-checked once a response has arrived: a re-check returning past the deadline still hands that response to parseResponse (no signal involved)', async () => {
  const o = await call({ budget: budget(60), recheck: async () => { await sleep(120); return PUBLIC }, parse: (h) => h.status })
  assert.equal(o.error, undefined)
  assert.equal(o.value, 200)
})

await t('(i) the loop-top check is `<= 0`, not `>`: with the clock frozen and maxDurationMs 0, no DoH lookup and no request', async () => {
  const realNow = Date.now
  const frozen = realNow()
  Date.now = () => frozen
  let lookups = 0
  try {
    const o = await call({ budget: budget(0), validate: async () => { lookups++; return PUBLIC } })
    assertDuration(o, 0)
  } finally {
    Date.now = realNow
  }
  assert.equal(lookups, 0)
})

await t('(i) one clock reading decides both: 1 ms left at the check and the clock ticking before the next read never sends with a 0 ms timeout (5e1563e9: timeout 0)', async () => {
  const realNow = Date.now
  const realTimeout = AbortSignal.timeout
  const start = realNow()
  const budgetMs = 1000
  // Frozen at start until the DoH lookup returns; then the first reading is 1 ms before
  // the deadline and every later one is the deadline itself.
  const after: number[] = [start + budgetMs - 1]
  let ticking = false
  Date.now = () => (ticking ? (after.shift() ?? start + budgetMs) : start)
  const timeoutArgs: number[] = []
  AbortSignal.timeout = (ms: number) => { timeoutArgs.push(ms); return realTimeout.call(AbortSignal, ms) }
  let o: Outcome
  try {
    o = await call({ budget: budget(budgetMs), validate: async () => { ticking = true; return PUBLIC } })
  } finally {
    Date.now = realNow
    AbortSignal.timeout = realTimeout
  }
  assert.deepEqual(timeoutArgs.filter((ms) => ms <= 0), [], 'a request was dispatched with a timeout of 0 ms or less')
  assert.equal(o.sent.length, 1)
  assert.deepEqual(timeoutArgs, [1])
})

console.log('\n(i\') the caller\'s signal is checked after every DoH await')

await t('(i\') aborted while the DoH lookup is in flight -> MAX_DURATION at hop 0, 0 fetchImpl calls', async () => {
  const ac = new AbortController()
  const o = await call({ signal: ac.signal, validate: async () => { ac.abort(); await sleep(5); return PUBLIC } })
  assertDuration(o, 0)
  assert.equal(o.sent.length, 0)
})

await t('(i\') already aborted on entry -> MAX_DURATION at hop 0, no DoH lookup, no request', async () => {
  const ac = new AbortController()
  ac.abort()
  let lookups = 0
  const o = await call({ signal: ac.signal, validate: async () => { lookups++; return PUBLIC } })
  assertDuration(o, 0)
  assert.equal(lookups, 0)
  assert.equal(o.sent.length, 0)
})

await t('(i\') aborted during the post-fetch DNS re-check -> MAX_DURATION, parseResponse never called, body cancelled', async () => {
  const ac = new AbortController()
  let cancelled = 0
  const o = await call({
    signal: ac.signal,
    recheck: async () => { ac.abort(); return PUBLIC },
    respond: async () => new Response(new ReadableStream({ cancel() { cancelled++ } }), { status: 200 }),
    parse: (h) => h.status,
  })
  assertDuration(o, 0)
  assert.equal(o.parseCalls, 0)
  assert.equal(cancelled, 1)
})

console.log('\n(ii) the signal reaches the target fetch and the body read')

await t('(ii) a fetch in flight is aborted through init.signal: settles at the abort (not the 2 s budget), init.signal.aborted, MAX_DURATION', async () => {
  const ac = new AbortController()
  setTimeout(() => ac.abort(), 30)
  const o = await call({ budget: budget(2000), signal: ac.signal, respond: hangUntilAborted })
  assertDuration(o, 0)
  assert.equal(o.sent.length, 1)
  assert.equal(o.sent[0]!.init.signal!.aborted, true)
  assert.ok(o.ms < 1000, `settled after ${o.ms} ms`)
})

await t('(ii) abort(\'x\') — a reason that is not an AbortError — on a fetch in flight -> MAX_DURATION, never UpstreamFetchFailed', async () => {
  const ac = new AbortController()
  setTimeout(() => ac.abort('x'), 30)
  const o = await call({ budget: budget(2000), signal: ac.signal, respond: hangUntilAborted })
  assert.ok(!(o.error instanceof UpstreamFetchFailed), 'mapped to UpstreamFetchFailed')
  assertDuration(o, 0)
  assert.equal(o.sent[0]!.init.signal!.reason, 'x')
})

await t('(ii) aborted mid-body, the second read hanging: init.signal aborted, the hung read is cancelled, no further read, MAX_DURATION, no truncated body returned', async () => {
  const ac = new AbortController()
  const body = hangingBody(() => setTimeout(() => ac.abort(), 20))
  const o = await call({ budget: budget(2000), signal: ac.signal, respond: async () => body.response, parse: (h) => h.text() })
  assertDuration(o, 0)
  assert.equal(o.value, undefined)
  assert.equal(o.sent[0]!.init.signal!.aborted, true)
  assert.equal(body.counts.reads, 2)
  assert.ok(body.counts.cancels >= 1)
  assert.ok(o.ms < 1000, `settled after ${o.ms} ms`)
})

await t('(ii) mid-body abort(\'x\') where the read itself rejects with that reason -> MAX_DURATION, never UpstreamFetchFailed', async () => {
  const ac = new AbortController()
  const body = hangingBody(() => setTimeout(() => ac.abort('x'), 20), 'reject-with-reason', () => ac.signal)
  const o = await call({ budget: budget(2000), signal: ac.signal, respond: async () => body.response, parse: (h) => h.bytes() })
  assert.ok(!(o.error instanceof UpstreamFetchFailed), 'mapped to UpstreamFetchFailed')
  assertDuration(o, 0)
  assert.equal(body.counts.reads, 2)
})

await t('(ii) a real ReadableStream that sends one chunk then hangs: the abort settles it as MAX_DURATION, never as the one-chunk text', async () => {
  const ac = new AbortController()
  const stream = new ReadableStream<Uint8Array>({
    start(c) { c.enqueue(new TextEncoder().encode('first chunk only')) },
    pull() { setTimeout(() => ac.abort(), 20); return new Promise(() => {}) },
  })
  const o = await call({ budget: budget(2000), signal: ac.signal, respond: async () => new Response(stream, { status: 200 }) })
  assertDuration(o, 0)
  assert.equal(o.value, undefined)
})

console.log('\n(ii) createSafeResponseHandle with a signal (internal parameter)')

await t('handle: already aborted -> MAX_DURATION before any read', async () => {
  const ac = new AbortController()
  ac.abort()
  const body = hangingBody()
  const h = createSafeResponseHandle(body.response, 1000, ac.signal)
  await assert.rejects(() => withCap(h.text()), (e) => e instanceof BudgetExceeded && e.code === 'MAX_DURATION')
  assert.equal(body.counts.reads, 0)
})

await t('handle: the abort listener is removed once reading finishes — a later abort cancels nothing', async () => {
  const ac = new AbortController()
  let cancelled = 0
  const response = new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('whole')); c.close() }, cancel() { cancelled++ } }))
  const h = createSafeResponseHandle(response, 1000, ac.signal)
  assert.equal(await h.text(), 'whole')
  ac.abort()
  assert.equal(cancelled, 0)
  assert.equal(await h.text(), 'whole')
})

console.log('\n(iii) no signal given: the request is built exactly as before')

await t('(iii) no signal: init is { method, headers, redirect: manual, signal: AbortSignal.timeout(remaining) }, AbortSignal.any never called, body read in full', async () => {
  const realAny = AbortSignal.any
  const realTimeout = AbortSignal.timeout
  let anyCalls = 0
  const timeouts: AbortSignal[] = []
  const timeoutArgs: number[] = []
  AbortSignal.any = (signals: AbortSignal[]) => { anyCalls++; return realAny.call(AbortSignal, signals) }
  AbortSignal.timeout = (ms: number) => { timeoutArgs.push(ms); const s = realTimeout.call(AbortSignal, ms); timeouts.push(s); return s }
  let o: Outcome
  try {
    o = await call({ budget: budget(5000) })
  } finally {
    AbortSignal.any = realAny
    AbortSignal.timeout = realTimeout
  }
  assert.equal(o.error, undefined)
  assert.equal(o.value, 'ok')
  assert.equal(anyCalls, 0)
  assert.equal(timeoutArgs.length, 1)
  assert.ok(timeoutArgs[0]! > 0 && timeoutArgs[0]! <= 5000)
  const init = o.sent[0]!.init
  assert.deepEqual(Object.keys(init), ['method', 'headers', 'redirect', 'signal'])
  assert.equal(init.method, 'GET')
  assert.equal(init.redirect, 'manual')
  assert.equal(init.signal, timeouts[0])
})

await t('(iii) contrast, with a signal: the fetch init is the combination, AbortSignal.any([timeout, signal]) — not the caller\'s signal alone', async () => {
  const ac = new AbortController()
  const o = await call({ signal: ac.signal })
  assert.equal(o.value, 'ok')
  const s = o.sent[0]!.init.signal!
  assert.notEqual(s, ac.signal)
  assert.equal(s.aborted, false)
  ac.abort()
  assert.equal(s.aborted, true)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
