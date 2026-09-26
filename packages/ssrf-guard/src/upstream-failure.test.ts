/**
 * T85 (R13 ①, R4 b): what ssrf-guard raises when the request to the target
 * fails, and which resolver failures are ours.
 *
 *   - UpstreamFetchFailed wraps exactly two things: the runtime's fetch() call
 *     rejecting, and a body read rejecting. A TimeoutError / AbortError at
 *     either is BudgetExceeded('MAX_DURATION') instead. Nothing our own code
 *     throws becomes one — shown both by behaviour and by where
 *     `new UpstreamFetchFailed` may appear in the source (AST, not text).
 *   - RESOLVER_UNAVAILABLE is raised at exactly six throw sites where our own
 *     DoH resolver could not be asked; since round 2 they also cover queryOne's
 *     answer-body read (the seventh failure point — it joined the decode try,
 *     as resolveTxt's always had). RESOLUTION_FAILED stays at the three where
 *     it answered and the name does not resolve.
 *   - guardedFetch records which request of the call failed as `hop` on the
 *     error (redirects followed before it), so a caller never reads a message.
 */
import assert from 'node:assert'
import { readdirSync, readFileSync } from 'node:fs'
import ts from 'typescript'
import { guardedFetch } from './guarded-fetch.ts'
import { DEFAULT_PROBE_BUDGET } from './budget.ts'
import { SsrfGuardError, SsrfBlocked, BudgetExceeded, UpstreamFetchFailed } from './errors.ts'
import { resolveHost, resolveTxt } from './resolve.ts'
import type { ProbeAuditRecord } from './audit.ts'
import type { RateLimitDecision } from './rate-limit.ts'
import type { SafeResponseHandle } from './response-view.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ALLOW: RateLimitDecision = { allowed: true, scope: [] }
const resolvePublic = async () => [{ ip: '1.1.1.1', family: 4 as const }]

async function run(fetchImpl: () => Promise<Response>, parse: (h: SafeResponseHandle) => unknown = (h) => h.bytes(), extra: Record<string, unknown> = {}): Promise<{ error: unknown; audit: ProbeAuditRecord | undefined }> {
  let audit: ProbeAuditRecord | undefined
  try {
    await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
      callerIdentifier: 'upstream-failure.test',
      fetchImpl: fetchImpl as typeof fetch,
      resolveAndValidateHostImpl: resolvePublic,
      resolveHostImpl: resolvePublic,
      parseResponse: parse,
      onAudit: (r) => { audit = r },
      ...extra,
    })
  } catch (error) {
    return { error, audit }
  }
  throw new Error('expected guardedFetch to reject')
}

/** A 200 whose body stream fails with `error` on the first read. */
const failingBody = (error: unknown) => async () => new Response(new ReadableStream({ pull(c) { c.error(error) } }), { status: 200 })
const timeoutError = () => new DOMException('The operation was aborted due to timeout', 'TimeoutError')
const abortError = () => new DOMException('This operation was aborted', 'AbortError')

console.log('UpstreamFetchFailed: the fetch call')

await t('fetch() rejecting (workerd "Network connection lost.") -> UpstreamFetchFailed carrying the original as cause; not an SsrfGuardError; audit outcome network_error', async () => {
  const original = new TypeError('Network connection lost.')
  const { error, audit } = await run(() => Promise.reject(original))
  assert.ok(error instanceof UpstreamFetchFailed)
  assert.equal((error as Error).cause, original)
  assert.equal(error instanceof SsrfGuardError, false)
  assert.equal(error instanceof SsrfBlocked, false)
  assert.equal(audit?.outcome, 'network_error')
})

await t('the message is fixed: the runtime error\'s own text is only on cause, never in message', async () => {
  const { error } = await run(() => Promise.reject(new Error('internal error; reference = abc123')))
  assert.equal((error as Error).message, 'the request to the target failed before a complete response arrived')
  assert.equal((error as Error).name, 'UpstreamFetchFailed')
})

await t('a non-Error rejection value is wrapped too, as cause', async () => {
  const { error } = await run(() => Promise.reject('reset'))
  assert.ok(error instanceof UpstreamFetchFailed)
  assert.equal((error as Error).cause, 'reset')
})

for (const [label, make] of [['TimeoutError', timeoutError], ['AbortError', abortError]] as const) {
  await t(`fetch() rejecting with ${label} is still BudgetExceeded('MAX_DURATION'), never UpstreamFetchFailed`, async () => {
    const { error } = await run(() => Promise.reject(make()))
    assert.ok(error instanceof BudgetExceeded)
    assert.equal((error as BudgetExceeded).code, 'MAX_DURATION')
  })
}

console.log('\nUpstreamFetchFailed: reading the body')

await t('a body read rejecting -> UpstreamFetchFailed carrying the original as cause', async () => {
  const original = new TypeError('Network connection lost.')
  const { error } = await run(failingBody(original))
  assert.ok(error instanceof UpstreamFetchFailed)
  assert.equal((error as Error).cause, original)
})

for (const [label, make] of [['TimeoutError', timeoutError], ['AbortError', abortError]] as const) {
  await t(`a body read rejecting with ${label} -> BudgetExceeded('MAX_DURATION') (the fetch call's own precedent)`, async () => {
    const { error } = await run(failingBody(make()))
    assert.ok(error instanceof BudgetExceeded)
    assert.equal((error as BudgetExceeded).code, 'MAX_DURATION')
  })
}

for (const reader of ['text', 'json', 'arrayBuffer'] as const) {
  await t(`every body reader goes through the same wrap: handle.${reader}()`, async () => {
    const { error } = await run(failingBody(new TypeError('x')), (h) => h[reader]())
    assert.ok(error instanceof UpstreamFetchFailed)
  })
}

console.log('\nour own errors are never wrapped')

await t('parseResponse throwing its own Error: that same object reaches the caller', async () => {
  const own = new Error('parser says no')
  const { error } = await run(async () => new Response('ok'), () => { throw own })
  assert.equal(error, own)
})

await t('handle.json() on a body that is not JSON: SyntaxError, not UpstreamFetchFailed (the read succeeded)', async () => {
  const { error } = await run(async () => new Response('not json'), (h) => h.json())
  assert.ok(error instanceof SyntaxError)
})

await t('a body over maxBodyBytes: BudgetExceeded MAX_BODY_BYTES, not UpstreamFetchFailed', async () => {
  let error: unknown
  try {
    await guardedFetch('https://example.com/', { ...DEFAULT_PROBE_BUDGET, maxBodyBytes: 2 }, ALLOW, {
      callerIdentifier: 't', fetchImpl: (async () => new Response('abcdef')) as typeof fetch,
      resolveAndValidateHostImpl: resolvePublic, resolveHostImpl: resolvePublic, parseResponse: (h) => h.bytes(),
    })
  } catch (e) { error = e }
  assert.ok(error instanceof BudgetExceeded)
  assert.equal((error as BudgetExceeded).code, 'MAX_BODY_BYTES')
})

await t('the host resolver (ours, injected) throwing a plain Error: unchanged', async () => {
  const own = new Error('resolver wiring broke')
  const { error } = await run(async () => new Response('ok'), undefined, { resolveAndValidateHostImpl: async () => { throw own } })
  assert.equal(error, own)
})

await t('building the request (AbortSignal.timeout on a NaN budget) throws before the fetch call: RangeError, not UpstreamFetchFailed, and fetch never runs', async () => {
  let calls = 0
  let error: unknown
  try {
    await guardedFetch('https://example.com/', { ...DEFAULT_PROBE_BUDGET, maxDurationMs: Number.NaN }, ALLOW, {
      callerIdentifier: 't', fetchImpl: (async () => { calls++; return new Response('ok') }) as typeof fetch,
      resolveAndValidateHostImpl: resolvePublic, resolveHostImpl: resolvePublic, parseResponse: (h) => h.status,
    })
  } catch (e) { error = e }
  assert.ok(error instanceof RangeError)
  assert.equal(calls, 0)
})

console.log('\nhop: which request of the call failed, as a field (redirects followed before it; 0 = the URL guardedFetch was given)')

/** `hops` GET redirects, each to a new host hop<n>.example.com, then `final`. */
function redirecting(hops: number, final: () => Promise<Response>): () => Promise<Response> {
  let n = 0
  return async () => (n++ < hops ? new Response(null, { status: 302, headers: { location: 'https://' + `hop${n}.example.com` + '/' } }) : final())
}
const nxdomainAt = (host: string) => async (h: string) => {
  if (h === host) throw new SsrfBlocked('RESOLUTION_FAILED', `${h} has no A or AAAA records`)
  return resolvePublic()
}
const hopOf = (e: unknown) => (e as { hop?: unknown }).hop

await t('RESOLUTION_FAILED for the URL it was given -> hop 0', async () => {
  const { error } = await run(async () => new Response('ok'), undefined, { resolveAndValidateHostImpl: nxdomainAt('example.com') })
  assert.ok(error instanceof SsrfBlocked && error.code === 'RESOLUTION_FAILED')
  assert.equal(hopOf(error), 0)
})
await t('RESOLUTION_FAILED after following one cross-host GET redirect -> hop 1', async () => {
  const { error } = await run(redirecting(1, async () => new Response('ok')), undefined, { resolveAndValidateHostImpl: nxdomainAt('hop1.example.com') })
  assert.ok(error instanceof SsrfBlocked && error.code === 'RESOLUTION_FAILED')
  assert.equal(hopOf(error), 1)
})
await t('fetch() timing out after one redirect -> BudgetExceeded MAX_DURATION with hop 1', async () => {
  const { error } = await run(redirecting(1, () => Promise.reject(timeoutError())))
  assert.ok(error instanceof BudgetExceeded && error.code === 'MAX_DURATION')
  assert.equal(hopOf(error), 1)
})
await t('fetch() rejecting after two redirects -> UpstreamFetchFailed with hop 2', async () => {
  const { error } = await run(redirecting(2, () => Promise.reject(new TypeError('Network connection lost.'))))
  assert.ok(error instanceof UpstreamFetchFailed)
  assert.equal(hopOf(error), 2)
})
await t('a body read failing at hop 0, and at hop 1', async () => {
  assert.equal(hopOf((await run(failingBody(new TypeError('x')))).error), 0)
  const { error } = await run(redirecting(1, failingBody(timeoutError())))
  assert.ok(error instanceof BudgetExceeded && error.code === 'MAX_DURATION')
  assert.equal(hopOf(error), 1)
})
await t('a POST is never past hop 0: its 302 is returned as the result, not followed', async () => {
  let calls = 0
  const r = await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 't', method: 'POST', body: '{}',
    fetchImpl: (async () => { calls++; return new Response(null, { status: 302, headers: { location: 'https://hop1.example.com/' } }) }) as typeof fetch,
    resolveAndValidateHostImpl: resolvePublic, resolveHostImpl: resolvePublic, parseResponse: (h) => h.status,
  })
  assert.equal(r.result, 302)
  assert.equal(calls, 1)
})
await t('our own errors get no hop; an error that already has one keeps it', async () => {
  const own = new Error('resolver wiring broke')
  assert.equal(hopOf((await run(async () => new Response('ok'), undefined, { resolveAndValidateHostImpl: async () => { throw own } })).error), undefined)
  const inner = Object.assign(new SsrfBlocked('RESOLUTION_FAILED', 'x'), { hop: 5 })
  assert.equal(hopOf((await run(async () => new Response('ok'), () => { throw inner })).error), 5)
})

console.log('\nstructure: where the new class and the resolver codes may appear (TypeScript AST)')

const SRC = new URL('./', import.meta.url)
const sources = readdirSync(SRC).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
  .map((file) => ts.createSourceFile(file, readFileSync(new URL(file, SRC), 'utf8'), ts.ScriptTarget.Latest, true))

function findAll(pred: (n: ts.Node) => boolean): ts.Node[] {
  const out: ts.Node[] = []
  for (const sf of sources) {
    const visit = (n: ts.Node): void => { if (pred(n)) out.push(n); ts.forEachChild(n, visit) }
    visit(sf)
  }
  return out
}
function enclosing<T extends ts.Node>(n: ts.Node, is: (x: ts.Node) => x is T): T | undefined {
  for (let p = n.parent; p !== undefined; p = p.parent) if (is(p)) return p
  return undefined
}
const fnName = (n: ts.Node) => enclosing(n, ts.isFunctionDeclaration)?.name?.text
/** The try statement whose catch clause `n` sits in, if any. */
const tryOf = (n: ts.Node) => { const c = enclosing(n, ts.isCatchClause); return c === undefined ? undefined : c.parent as ts.TryStatement }
/** The one awaited call a try block consists of: `x = await f(…)`. */
function soleAwaitedCall(block: ts.Block): string | undefined {
  if (block.statements.length !== 1) return undefined
  const s = block.statements[0]!
  if (!ts.isExpressionStatement(s) || !ts.isBinaryExpression(s.expression) || !ts.isAwaitExpression(s.expression.right)) return undefined
  const call = s.expression.right.expression
  return ts.isCallExpression(call) ? call.expression.getText() : undefined
}
const newOf = (cls: string) => (n: ts.Node) => ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === cls
const blockedWith = (code: string) => (n: ts.Node) => newOf('SsrfBlocked')(n) && (() => { const a = (n as ts.NewExpression).arguments?.[0]; return a !== undefined && ts.isStringLiteral(a) && a.text === code })()

await t('new UpstreamFetchFailed appears exactly twice: in guarded-fetch.ts\'s catch around `await fetchImpl(…)` alone, and in response-view.ts\'s bodyReadFailure', () => {
  const sites = findAll(newOf('UpstreamFetchFailed'))
  assert.deepEqual(sites.map((n) => n.getSourceFile().fileName).sort(), ['guarded-fetch.ts', 'response-view.ts'])
  const gf = sites.find((n) => n.getSourceFile().fileName === 'guarded-fetch.ts')!
  assert.equal(soleAwaitedCall(tryOf(gf)!.tryBlock), 'fetchImpl')
  const rv = sites.find((n) => n.getSourceFile().fileName === 'response-view.ts')!
  assert.equal(fnName(rv), 'bodyReadFailure')
})

await t('bodyReadFailure is called only from the catch around `await reader.read()` alone', () => {
  const calls = findAll((n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'bodyReadFailure')
  assert.equal(calls.length, 1)
  assert.equal(soleAwaitedCall(tryOf(calls[0]!)!.tryBlock), 'reader.read')
})

await t('RESOLVER_UNAVAILABLE: exactly six sites, all in resolve.ts — three in queryOne, three in resolveTxt — each in a catch clause or under `if (!response.ok)`', () => {
  const sites = findAll(blockedWith('RESOLVER_UNAVAILABLE'))
  assert.equal(sites.length, 6)
  assert.ok(sites.every((n) => n.getSourceFile().fileName === 'resolve.ts'))
  assert.deepEqual(sites.map(fnName).sort(), ['queryOne', 'queryOne', 'queryOne', 'resolveTxt', 'resolveTxt', 'resolveTxt'])
  for (const n of sites) {
    const inCatch = tryOf(n) !== undefined
    const ifStmt = enclosing(n, ts.isIfStatement)
    const underNotOk = ifStmt !== undefined && ifStmt.expression.getText() === '!response.ok'
    assert.ok(inCatch || underNotOk, `${n.getText()} is neither in a catch clause nor under if (!response.ok)`)
  }
})

await t('every DoH answer body read in resolve.ts (queryOne and resolveTxt: two) is inside a try whose catch throws RESOLVER_UNAVAILABLE', () => {
  const reads = findAll((n) => ts.isCallExpression(n) && n.getSourceFile().fileName === 'resolve.ts' && n.expression.getText() === 'response.arrayBuffer')
  assert.deepEqual(reads.map(fnName).sort(), ['queryOne', 'resolveTxt'])
  for (const n of reads) {
    const tryStmt = enclosing(n, ts.isTryStatement)
    assert.ok(tryStmt !== undefined && n.pos >= tryStmt.tryBlock.pos && n.end <= tryStmt.tryBlock.end, `${fnName(n)}: read outside a try block`)
    const thrown = tryStmt!.catchClause === undefined ? [] : findAll(blockedWith('RESOLVER_UNAVAILABLE')).filter((s) => tryOf(s) === tryStmt)
    assert.equal(thrown.length, 1, `${fnName(n)}: its catch does not throw RESOLVER_UNAVAILABLE`)
  }
})

await t('the only assignment to a `.hop` property is in guardedFetch\'s catch clause', () => {
  const writes = findAll((n) => ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isPropertyAccessExpression(n.left) && n.left.name.text === 'hop')
  assert.equal(writes.length, 1)
  assert.equal(fnName(writes[0]!), 'guardedFetch')
  assert.ok(enclosing(writes[0]!, ts.isCatchClause) !== undefined)
})

await t('RESOLUTION_FAILED: exactly three sites, all in resolve.ts, none in a catch clause (the resolver answered)', () => {
  const sites = findAll(blockedWith('RESOLUTION_FAILED'))
  assert.equal(sites.length, 3)
  assert.deepEqual(sites.map(fnName).sort(), ['queryOne', 'resolveHost', 'resolveTxt'])
  assert.ok(sites.every((n) => tryOf(n) === undefined))
})

console.log('\nthe six first-party sites and the three server-side ones, by behaviour')

const codeOf = async (p: Promise<unknown>) => { try { await p; return 'resolved' } catch (e) { return e instanceof SsrfBlocked ? e.code : `other:${(e as Error).name}` } }
const dohReject = (async () => { throw new TypeError('Network connection lost.') }) as unknown as typeof fetch
const doh503 = (async () => new Response('', { status: 503 })) as unknown as typeof fetch
const dohGarbage = (async () => new Response(Uint8Array.from([1, 2, 3]), { status: 200 })) as unknown as typeof fetch
function dohRcode(rcode: number, ancount = 0): typeof fetch {
  return (async (_i: unknown, init?: RequestInit) => {
    const q = init!.body as Uint8Array
    return new Response(Uint8Array.from([0, 0, 0x81, 0x80 | rcode, 0, 1, 0, ancount, 0, 0, 0, 0, ...Array.from(q.slice(12))]), { status: 200 })
  }) as unknown as typeof fetch
}

const dohBodyUnreadable = (async () => new Response(new ReadableStream({ pull(c) { c.error(new TypeError('Network connection lost.')) } }), { status: 200 })) as unknown as typeof fetch

for (const [label, fetchImpl] of [['request rejected', dohReject], ['HTTP 503', doh503], ['unparseable answer', dohGarbage], ['answer body unreadable', dohBodyUnreadable]] as const) {
  await t(`queryOne (resolveHost), our resolver ${label} -> RESOLVER_UNAVAILABLE`, async () => {
    assert.equal(await codeOf(resolveHost('example.com', { fetchImpl })), 'RESOLVER_UNAVAILABLE')
  })
  await t(`resolveTxt, our resolver ${label} -> RESOLVER_UNAVAILABLE`, async () => {
    assert.equal(await codeOf(resolveTxt('_x.example.com', { fetchImpl })), 'RESOLVER_UNAVAILABLE')
  })
}
await t('queryOne, RCODE 3 -> RESOLUTION_FAILED', async () => assert.equal(await codeOf(resolveHost('example.com', { fetchImpl: dohRcode(3) })), 'RESOLUTION_FAILED'))
await t('resolveHost, NOERROR with no A or AAAA -> RESOLUTION_FAILED', async () => assert.equal(await codeOf(resolveHost('example.com', { fetchImpl: dohRcode(0) })), 'RESOLUTION_FAILED'))
await t('resolveTxt, RCODE 2 -> RESOLUTION_FAILED', async () => assert.equal(await codeOf(resolveTxt('_x.example.com', { fetchImpl: dohRcode(2) })), 'RESOLUTION_FAILED'))

console.log('\nresolveHost when A and AAAA fail differently: a fixed precedence (an answer beats a non-answer), never whichever settles first')

type Outcome = 'rcode3' | 'transport' | 'address'
/** A fake DoH answering the A and AAAA queries differently; `later` settles 20 ms after the other.
 *  `settled` records the order the two queries actually settled in. */
function dohPerType(a: Outcome, aaaa: Outcome, later: 'A' | 'AAAA', settled: string[]): typeof fetch {
  return (async (_i: unknown, init?: RequestInit) => {
    const q = init!.body as Uint8Array
    const type = ((q[q.length - 4]! << 8) | q[q.length - 3]!) === 1 ? 'A' : 'AAAA'
    if (type === later) await new Promise((r) => setTimeout(r, 20))
    settled.push(type)
    const outcome = type === 'A' ? a : aaaa
    if (outcome === 'transport') throw new TypeError('Network connection lost.')
    const answers = outcome === 'address' && type === 'A' ? [[1, 1, 1, 1]] : []
    const header = [0, 0, 0x81, 0x80 | (outcome === 'rcode3' ? 3 : 0), 0, 1, 0, answers.length, 0, 0, 0, 0]
    return new Response(Uint8Array.from([...header, ...Array.from(q.slice(12)), ...answers.flatMap((ip) => [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, ...ip])]), { status: 200 })
  }) as unknown as typeof fetch
}
async function resolveError(a: Outcome, aaaa: Outcome, later: 'A' | 'AAAA'): Promise<{ error: unknown; settled: string[] }> {
  const settled: string[] = []
  let error: unknown = new Error('expected resolveHost to reject')
  try { await resolveHost('example.com', { fetchImpl: dohPerType(a, aaaa, later, settled) }) } catch (e) { error = e }
  // Let the slower query settle too, so the recorded order is complete whatever resolveHost waited for.
  await new Promise((r) => setTimeout(r, 40))
  return { error, settled }
}

await t('R15 (a): A answered RCODE 3, AAAA transport failure, A settling first -> RESOLUTION_FAILED, the A site\'s own error', async () => {
  const { error, settled } = await resolveError('rcode3', 'transport', 'AAAA')
  assert.equal((error as SsrfBlocked).code, 'RESOLUTION_FAILED')
  assert.deepEqual(settled, ['A', 'AAAA'])
  assert.equal((error as Error).message, 'blocked (RESOLUTION_FAILED): DNS resolution failed with RCODE 3')
})
await t('R15 (a), order reversed: the AAAA transport failure settles FIRST, A answers RCODE 3 later -> still RESOLUTION_FAILED', async () => {
  const { error, settled } = await resolveError('rcode3', 'transport', 'A')
  assert.equal((error as SsrfBlocked).code, 'RESOLUTION_FAILED')
  assert.ok(error instanceof SsrfBlocked)
  assert.deepEqual(settled, ['AAAA', 'A'], 'the transport failure really settled first')
})
for (const later of ['A', 'AAAA'] as const) {
  await t(`R15 (b): A answered with an address, AAAA transport failure (${later} settling last) -> RESOLVER_UNAVAILABLE, the AAAA site's own error`, async () => {
    const { error } = await resolveError('address', 'transport', later)
    assert.ok(error instanceof SsrfBlocked && error.code === 'RESOLVER_UNAVAILABLE')
    assert.equal((error as Error).message, 'blocked (RESOLVER_UNAVAILABLE): DoH request to our own resolver failed: Network connection lost.')
  })
}
await t('R15: both queries transport failures -> RESOLVER_UNAVAILABLE; AAAA answered RCODE 3 after an A transport failure -> RESOLUTION_FAILED', async () => {
  assert.equal((await resolveError('transport', 'transport', 'AAAA')).error instanceof SsrfBlocked, true)
  assert.equal(((await resolveError('transport', 'transport', 'AAAA')).error as SsrfBlocked).code, 'RESOLVER_UNAVAILABLE')
  assert.equal(((await resolveError('transport', 'rcode3', 'AAAA')).error as SsrfBlocked).code, 'RESOLUTION_FAILED')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
