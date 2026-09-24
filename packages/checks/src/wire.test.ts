import assert from 'node:assert'
import { sendRequest, createProbeContext, ProbeAborted, parseRetryAfterSeconds } from './wire.ts'
import type { ProbeContext } from './wire.ts'
import type { FetchLike } from './types.ts'
import { BudgetExceeded, SsrfBlocked } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const BUDGET: ProbeBudget = { maxRedirects: 3, maxDurationMs: 10_000, maxBodyBytes: 2_097_152, maxRequests: 8 }

console.log('sendRequest：单次请求')

await t('返回 status / headers / bodyText / finalUrl，请求计数 +1', async () => {
  const fetchImpl: FetchLike = async () => new Response('hello', { status: 200, headers: { 'content-type': 'text/plain' } })
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST' }, BUDGET, ctx)
  assert.equal(r.status, 200)
  assert.equal(r.bodyText, 'hello')
  assert.equal(r.headers.get('content-type'), 'text/plain')
  assert.equal(r.finalUrl, 'https://example.com/mcp')
  assert.equal(ctx.requestCount, 1)
})

await t('fetchImpl 抛出的错误原样传播（不被吞掉、不被包装）', async () => {
  const boom = new Error('network unreachable')
  const fetchImpl: FetchLike = async () => { throw boom }
  const ctx = createProbeContext(Date.now())
  await assert.rejects(() => sendRequest(fetchImpl, 'https://example.com/mcp', {}, BUDGET, ctx), (e: unknown) => e === boom)
})

console.log('\ncreateProbeContext：调用方显式传入 startedAtMs')

await t('startedAtMs 就是调用方传入的值——wire.ts 内部不再有裸的 Date.now() 调用（NEXT.md 项目四）', () => {
  const ctx = createProbeContext(1_700_000_000_000)
  assert.equal(ctx.startedAtMs, 1_700_000_000_000)
})

console.log('\nsendRequest：请求预算')

await t('请求数达到 maxRequests 后，下一次调用抛 ProbeAborted，且不再实际调用 fetchImpl', async () => {
  let calls = 0
  const fetchImpl: FetchLike = async () => { calls++; return new Response('ok') }
  const ctx = createProbeContext(Date.now())
  const tinyBudget: ProbeBudget = { ...BUDGET, maxRequests: 1 }
  await sendRequest(fetchImpl, 'https://example.com/a', {}, tinyBudget, ctx)
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/b', {}, tinyBudget, ctx),
    (e: unknown) => e instanceof ProbeAborted && e.code === 'MAX_REQUESTS' && e.details.maxRequests === tinyBudget.maxRequests,
  )
  assert.equal(calls, 1, '第二次调用必须在触达 fetchImpl 之前就被拒绝')
})

await t('总耗时超过 maxDurationMs 后抛 ProbeAborted(MAX_DURATION)', async () => {
  const fetchImpl: FetchLike = async () => new Response('ok')
  const ctx = createProbeContext(Date.now())
  ctx.startedAtMs = Date.now() - 999_999 // 模拟"很久以前就开始了"
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx),
    (e: unknown) => e instanceof ProbeAborted && e.code === 'MAX_DURATION' && e.details.maxDurationMs === BUDGET.maxDurationMs,
  )
})

console.log('\nsendRequest：响应体预算')

await t('Content-Length 声明超过 maxBodyBytes 时抛 ProbeAborted(MAX_BODY_BYTES)，不读取 body', async () => {
  const fetchImpl: FetchLike = async () => new Response('short body', { headers: { 'content-length': '99999999' } })
  const ctx = createProbeContext(Date.now())
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx),
    (e: unknown) => e instanceof ProbeAborted && e.code === 'MAX_BODY_BYTES' && e.details.declaredBytes === 99999999 && e.details.maxBodyBytes === BUDGET.maxBodyBytes,
  )
})

await t('Content-Length 是一个极端数字串（解析为 Infinity）时，抛出的 ProbeAborted.details 里绝不能出现非有限的 declaredBytes —— maxBodyBytes 仍然存在且正确', async () => {
  const fetchImpl: FetchLike = async () => new Response('short body', { headers: { 'content-length': '9'.repeat(310) } })
  const ctx = createProbeContext(Date.now())
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx),
    (e: unknown) => {
      if (!(e instanceof ProbeAborted) || e.code !== 'MAX_BODY_BYTES') return false
      if (e.details.maxBodyBytes !== BUDGET.maxBodyBytes) return false
      // 第三方可控的 header 值一旦解析为 Infinity，就绝不能作为 declaredBytes 混进
      // details——这个 key 必须整个不存在，而不是存在但值为 Infinity（后者会在
      // canonicalizer 里触发 NON_FINITE_NUMBER，见 packages/canonicalizer）。
      return !('declaredBytes' in e.details)
    },
  )
})

await t('没有 Content-Length 时，实际读到的字节数超预算同样抛 ProbeAborted(MAX_BODY_BYTES)', async () => {
  const big = 'x'.repeat(3_000_000)
  const fetchImpl: FetchLike = async () => new Response(big)
  const ctx = createProbeContext(Date.now())
  const smallBudget: ProbeBudget = { ...BUDGET, maxBodyBytes: 1_000 }
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/a', {}, smallBudget, ctx),
    (e: unknown) => e instanceof ProbeAborted && e.code === 'MAX_BODY_BYTES' && e.details.actualBytes === 3_000_000 && e.details.maxBodyBytes === smallBudget.maxBodyBytes,
  )
})

await t('反例：预算内的正常大小 body 不受影响', async () => {
  const fetchImpl: FetchLike = async () => new Response('a normal small body')
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)
  assert.equal(r.bodyText, 'a normal small body')
})

console.log('\nsendRequest：重定向跟随')

await t('同主机重定向：自动跟随，返回最终响应，不标记跨主机', async () => {
  let call = 0
  const fetchImpl: FetchLike = async (input) => {
    call++
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url === 'https://example.com/old') return new Response(null, { status: 302, headers: { location: '/new' } })
    return new Response('final', { status: 200 })
  }
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://example.com/old', {}, BUDGET, ctx)
  assert.equal(r.status, 200)
  assert.equal(r.bodyText, 'final')
  assert.equal(r.finalUrl, 'https://example.com/new')
  assert.equal(ctx.requestCount, 2)
  assert.equal(ctx.redirectCrossHostObserved, false)
})

await t('跨主机重定向：跟随并标记 redirectCrossHostObserved = true', async () => {
  const fetchImpl: FetchLike = async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url === 'https://a.example.com/mcp') return new Response(null, { status: 302, headers: { location: 'https://b.example.com/mcp' } })
    return new Response('final', { status: 200 })
  }
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://a.example.com/mcp', {}, BUDGET, ctx)
  assert.equal(r.finalUrl, 'https://b.example.com/mcp')
  assert.equal(ctx.redirectCrossHostObserved, true)
})

await t('相对 Location 相对当前跳的 URL 解析，而不是相对原始 URL', async () => {
  const fetchImpl: FetchLike = async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url === 'https://example.com/a/start') return new Response(null, { status: 302, headers: { location: 'mid' } })
    if (url === 'https://example.com/a/mid') return new Response(null, { status: 302, headers: { location: '../end' } })
    if (url === 'https://example.com/end') return new Response('final', { status: 200 })
    throw new Error(`unexpected url ${url}`)
  }
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://example.com/a/start', {}, BUDGET, ctx)
  assert.equal(r.finalUrl, 'https://example.com/end')
})

await t('重定向跳数超过 maxRedirects 时抛 ProbeAborted(MAX_REDIRECTS)', async () => {
  const fetchImpl: FetchLike = async () => new Response(null, { status: 302, headers: { location: '/next' } })
  const ctx = createProbeContext(Date.now())
  const tightBudget: ProbeBudget = { ...BUDGET, maxRedirects: 1 }
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/start', {}, tightBudget, ctx),
    (e: unknown) => e instanceof ProbeAborted && e.code === 'MAX_REDIRECTS' && e.details.maxRedirects === tightBudget.maxRedirects,
  )
})

console.log('\nsendRequest：非 GET 不跟随重定向（P 任务——与 @mcpcheckup/ssrf-guard 的 guardedFetch 相同规则，独立实现于 wire.ts；纵深防御：两层各自执行同一条规则，不集中到一处共享信号，理由见 packages/ssrf-guard/README.md「Non-GET does not follow redirects」）')

await t('跨主机 POST 重定向：第二跳从未发出（不是只看最终结果），3xx 本身作为终态返回，redirectCrossHostObserved 标记为 true', async () => {
  let calls = 0
  const fetchImpl: FetchLike = async () => {
    calls++
    return new Response(null, { status: 302, headers: { location: 'https://mirror.example.com/mcp' } })
  }
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST', body: '{}' }, BUDGET, ctx)
  assert.equal(calls, 1, '第二跳绝不能被发出')
  assert.equal(r.status, 302)
  assert.equal(r.finalUrl, 'https://example.com/mcp', '没有跟随，finalUrl 就是发出 3xx 的那次请求本身')
  assert.equal(ctx.redirectCrossHostObserved, true)
  assert.equal(ctx.requestCount, 1)
})

await t('同主机 POST 重定向：同样不跟随（第二跳从未发出），但不标记跨主机', async () => {
  let calls = 0
  const fetchImpl: FetchLike = async () => {
    calls++
    return new Response(null, { status: 302, headers: { location: '/new' } })
  }
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://example.com/old', { method: 'POST' }, BUDGET, ctx)
  assert.equal(calls, 1)
  assert.equal(r.status, 302)
  assert.equal(ctx.redirectCrossHostObserved, false)
})

await t('POST + authorization 头 + 跨主机 3xx：第二跳从未发出——authorization 没有被重放到新主机的机会，因为压根没有第二次调用', async () => {
  const calls: RequestInit[] = []
  const fetchImpl: FetchLike = async (_input, init) => {
    calls.push(init ?? {})
    return new Response(null, { status: 302, headers: { location: 'https://attacker.example.com/mcp' } })
  }
  const ctx = createProbeContext(Date.now())
  const init: RequestInit = { method: 'POST', headers: { authorization: 'Bearer secret-token' }, body: '{}' }
  const r = await sendRequest(fetchImpl, 'https://example.com/mcp', init, BUDGET, ctx)
  assert.equal(calls.length, 1, '第二跳从未发出')
  assert.equal(r.status, 302)
  assert.equal(ctx.redirectCrossHostObserved, true)
})

console.log('\nsendRequest：DNS 答案变化信号（带外信道 —— 生产适配层通过 onGuardSignal 回调报告，不是通过响应）')

await t('fetchImpl 通过 onGuardSignal({ dnsAnswerChanged: true }) 报告时，标记 ctx.dnsAnswerChangedObserved', async () => {
  const fetchImpl: FetchLike = async (_input, _init, onGuardSignal) => {
    onGuardSignal({ dnsAnswerChanged: true })
    return new Response('ok')
  }
  const ctx = createProbeContext(Date.now())
  await sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)
  assert.equal(ctx.dnsAnswerChangedObserved, true)
})

await t('反例：fetchImpl 从不调用 onGuardSignal 时不标记', async () => {
  const fetchImpl: FetchLike = async () => new Response('ok')
  const ctx = createProbeContext(Date.now())
  await sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)
  assert.equal(ctx.dnsAnswerChangedObserved, false)
})

await t('安全回归：目标在响应里伪造旧的 x-mcpcheckup-dns-answer-changed 头也不生效——这个信号只能来自 onGuardSignal，目标完全控制的 Response 不再是任何信道', async () => {
  const fetchImpl: FetchLike = async () => new Response('ok', { headers: { 'x-mcpcheckup-dns-answer-changed': 'true' } })
  const ctx = createProbeContext(Date.now())
  await sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)
  assert.equal(ctx.dnsAnswerChangedObserved, false, '目标可以完全控制自己的响应头，不能让它变成一个安全信号')
})

console.log('\nsendRequest：目标要求稍后再来（429 / 带 Retry-After 的 503）——T6.9-A1')

await t('HTTP 429 抛 ProbeAborted(RATE_LIMITED)，且抛在读 body 之前（本轮到此为止）', async () => {
  let bodyRead = 0
  const fetchImpl: FetchLike = async () => {
    const res = new Response('这段 body 不该被读到', { status: 429 })
    const originalText = res.text.bind(res)
    res.text = async () => { bodyRead++; return originalText() }
    return res
  }
  const ctx = createProbeContext(Date.now())
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST' }, BUDGET, ctx),
    (e: unknown) => e instanceof ProbeAborted && e.code === 'RATE_LIMITED',
  )
  assert.equal(bodyRead, 0, '429 必须在读响应体之前就中止——对一台刚说「你太快了」的目标，连它的 body 都不再消费')
})

await t('429 的 details 记下状态码；没有 Retry-After 时不编造一个 retryAfterSeconds', async () => {
  const fetchImpl: FetchLike = async () => new Response(null, { status: 429 })
  const ctx = createProbeContext(Date.now())
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST' }, BUDGET, ctx),
    (e: unknown) => {
      const err = e as ProbeAborted
      assert.deepEqual(err.details, { status: 429 })
      assert.equal(err.retryAfterSeconds, undefined, '没有 Retry-After 就是没有，不能补一个默认值——那会让调度侧以为对方给过时间')
      return true
    },
  )
})

await t('429 + Retry-After: 3600 —— retryAfterSeconds 走独立的类型化字段，同时也进 details（签名证据里记下对方到底说了多久）', async () => {
  const fetchImpl: FetchLike = async () => new Response(null, { status: 429, headers: { 'retry-after': '3600' } })
  const ctx = createProbeContext(Date.now())
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST' }, BUDGET, ctx),
    (e: unknown) => {
      const err = e as ProbeAborted
      assert.equal(err.code, 'RATE_LIMITED')
      assert.equal(err.retryAfterSeconds, 3600)
      assert.deepEqual(err.details, { status: 429, retryAfterSeconds: 3600 })
      return true
    },
  )
})

await t('429 + 无法解析的 Retry-After（HTTP-date）：照样中止，只是没有「多久之后」这个提示', async () => {
  const fetchImpl: FetchLike = async () => new Response(null, { status: 429, headers: { 'retry-after': 'Wed, 21 Oct 2015 07:28:00 GMT' } })
  const ctx = createProbeContext(Date.now())
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST' }, BUDGET, ctx),
    (e: unknown) => {
      const err = e as ProbeAborted
      assert.equal(err.code, 'RATE_LIMITED', '解析不了的 Retry-After 不能反过来把「要不要停」这个判断也一起解掉')
      assert.equal(err.retryAfterSeconds, undefined)
      assert.deepEqual(err.details, { status: 429 })
      return true
    },
  )
})

await t('503 + Retry-After：按 429 同等处理，中止本轮', async () => {
  const fetchImpl: FetchLike = async () => new Response(null, { status: 503, headers: { 'retry-after': '120' } })
  const ctx = createProbeContext(Date.now())
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST' }, BUDGET, ctx),
    (e: unknown) => {
      const err = e as ProbeAborted
      assert.equal(err.code, 'RATE_LIMITED')
      assert.equal(err.retryAfterSeconds, 120)
      assert.deepEqual(err.details, { status: 503, retryAfterSeconds: 120 })
      return true
    },
  )
})

await t('反例：503 不带 Retry-After —— 不中止，照常把这次响应返回给调用方（不带 Retry-After 的 503 通常只是瞬时故障，不是限流意图）', async () => {
  const fetchImpl: FetchLike = async () => new Response('service unavailable', { status: 503 })
  const ctx = createProbeContext(Date.now())
  const r = await sendRequest(fetchImpl, 'https://example.com/mcp', { method: 'POST' }, BUDGET, ctx)
  assert.equal(r.status, 503, '必须作为普通响应返回，由既有判定去处理')
  assert.equal(r.bodyText, 'service unavailable')
})

await t('反例：Retry-After 的有无是 503 唯一的判据——同一段代码对这两种输入必须给出相反的结果', async () => {
  const withHeader: FetchLike = async () => new Response(null, { status: 503, headers: { 'retry-after': '30' } })
  const withoutHeader: FetchLike = async () => new Response(null, { status: 503 })
  await assert.rejects(
    () => sendRequest(withHeader, 'https://example.com/a', {}, BUDGET, createProbeContext(Date.now())),
    (e: unknown) => e instanceof ProbeAborted,
  )
  const r = await sendRequest(withoutHeader, 'https://example.com/b', {}, BUDGET, createProbeContext(Date.now()))
  assert.equal(r.status, 503)
})

console.log('\nsendRequest：每次请求只拿到整轮预算的剩余时间（TODO 458）')

/** Fails the test instead of hanging it when a mutation removes the deadline. */
function watchdog<T>(p: Promise<T>, ms = 3_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const guard = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error(`watchdog: still pending after ${ms} ms — nothing bounded this call`)), ms) })
  return Promise.race([p, guard]).finally(() => clearTimeout(timer))
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
/** A ctx whose run started so long ago that `leftMs` of the budget remain. */
const ctxWithLeft = (leftMs: number, budget: ProbeBudget = BUDGET) => {
  const ctx = createProbeContext(Date.now())
  ctx.startedAtMs = Date.now() - (budget.maxDurationMs - leftMs)
  return ctx
}
/** The run's deadline, as sendRequest computes it. */
const deadlineOf = (ctx: ProbeContext, budget: ProbeBudget = BUDGET) => ctx.startedAtMs + budget.maxDurationMs
/** Spins synchronously until Date.now() reaches `atMs`. No timer callback can
 *  run while this spins, and a promise settled right after it settles in
 *  microtasks — before any timer macrotask — so "how much time was left when
 *  the step settled" is fixed by construction, not by the runner's speed.
 *  (TODO 458 R3: a ctx built with 1 ms left and then assumed to still have
 *  it when the request starts was flaky on CI.) */
const busyUntil = (atMs: number) => { while (Date.now() < atMs) { /* spin */ } }
const isDurationAbort = (budget: ProbeBudget) => (e: unknown) =>
  e instanceof ProbeAborted && e.code === 'MAX_DURATION' && e.message === `探测已超过 ${budget.maxDurationMs}ms 的总预算` &&
  JSON.stringify(e.details) === JSON.stringify({ maxDurationMs: budget.maxDurationMs })

await t('fetchImpl 收到第 4 参 { timeoutMs }，值是整轮预算的剩余时间，不是一份全新的 maxDurationMs', async () => {
  const seen: unknown[] = []
  const fetchImpl: FetchLike = async (_i, _init, _s, options) => { seen.push(options); return new Response('ok') }
  await sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctxWithLeft(1_000))
  assert.equal(seen.length, 1)
  const timeoutMs = (seen[0] as { timeoutMs: number }).timeoutMs
  assert.ok(timeoutMs > 0 && timeoutMs <= 1_000, `timeoutMs 必须是剩余的约 1000 ms，实得 ${timeoutMs}`)
  assert.deepEqual(Object.keys(seen[0] as object), ['timeoutMs'])
})

await t('重定向循环的每一跳都重新计算剩余时间：第二跳拿到的比第一跳少，少的正是第一跳花掉的时间', async () => {
  const timeouts: number[] = []
  const fetchImpl: FetchLike = async (input, _init, _s, options) => {
    timeouts.push(options!.timeoutMs)
    if (String(input).endsWith('/a')) { await sleep(60); return new Response(null, { status: 302, headers: { location: '/b' } }) }
    return new Response('ok')
  }
  const r = await sendRequest(fetchImpl, 'https://example.com/a', { method: 'GET' }, BUDGET, createProbeContext(Date.now()))
  assert.equal(r.bodyText, 'ok')
  assert.equal(timeouts.length, 2)
  assert.ok(timeouts[0]! <= BUDGET.maxDurationMs && timeouts[0]! > BUDGET.maxDurationMs - 50, `第一跳 ${timeouts[0]}`)
  assert.ok(timeouts[1]! <= timeouts[0]! - 50, `第二跳 ${timeouts[1]} 必须比第一跳 ${timeouts[0]} 少掉约 60 ms`)
})

await t('时钟倒退（startedAtMs 在未来）时 timeoutMs 也不超过 maxDurationMs', async () => {
  const seen: number[] = []
  const fetchImpl: FetchLike = async (_i, _init, _s, options) => { seen.push(options!.timeoutMs); return new Response('ok') }
  await sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, createProbeContext(Date.now() + 60_000))
  assert.deepEqual(seen, [BUDGET.maxDurationMs])
})

await t('剩余时间恰为 0：抛 ProbeAborted(MAX_DURATION)（原文案、原 details），fetchImpl 一次都不被调用，请求计数不变', async () => {
  let calls = 0
  const fetchImpl: FetchLike = async () => { calls++; return new Response('ok') }
  const ctx = ctxWithLeft(0)
  await assert.rejects(() => sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx), isDurationAbort(BUDGET))
  assert.equal(calls, 0)
  assert.equal(ctx.requestCount, 0)
})

await t('一直不返回的 fetchImpl（无视 timeoutMs）：在剩余时间到点时被 wire.ts 自己的计时器截断，抛 ProbeAborted(MAX_DURATION)', async () => {
  let calls = 0
  const fetchImpl: FetchLike = () => { calls++; return new Promise<Response>(() => {}) }
  const ctx = ctxWithLeft(200)
  await assert.rejects(() => watchdog(sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)), isDurationAbort(BUDGET))
  const lateBy = Date.now() - deadlineOf(ctx)
  assert.equal(calls, 1, '前提：请求确实发出了，是计时器而不是请求前检查结束了它')
  assert.ok(lateBy >= -2 && lateBy <= 150, `应在截止时间截断，实际相差 ${lateBy} ms`)
})

await t('读 body 也在截止时间之内：响应头及时到了、body 迟迟读不完，照样在到点时抛 ProbeAborted(MAX_DURATION)', async () => {
  let textCalls = 0
  const slowBody = { status: 200, headers: new Headers(), text: () => { textCalls++; return sleep(1_000).then(() => 'late') } } as unknown as Response
  const fetchImpl: FetchLike = async () => slowBody
  const ctx = ctxWithLeft(200)
  await assert.rejects(() => watchdog(sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)), isDurationAbort(BUDGET))
  assert.equal(textCalls, 1, '前提：body 确实开始读了，是计时器而不是读之前的检查结束了它')
  assert.ok(Date.now() - deadlineOf(ctx) <= 150, '不得等到 body 读完')
})

await t('R1 ⑤：被截止时间中止的请求，其后到达的 Response 一个字节都不读，其后报告的 GuardSignals 一律丢弃', async () => {
  let textCalls = 0
  let lateSignalDelivered = false
  let calls = 0
  const fetchImpl: FetchLike = async (_i, _init, onGuardSignal) => {
    calls++
    await sleep(500) // 截止时间在 200 ms 之后
    onGuardSignal({ dnsAnswerChanged: true })
    lateSignalDelivered = true
    return { status: 200, headers: new Headers(), text: async () => { textCalls++; return 'late body' } } as unknown as Response
  }
  const ctx = ctxWithLeft(200)
  await assert.rejects(() => watchdog(sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)), isDurationAbort(BUDGET))
  await sleep(600) // 让那个迟到的调用自己跑完
  assert.equal(calls, 1, '前提：请求确实发出了')
  assert.equal(lateSignalDelivered, true, '前提：迟到的信号确实被报告了')
  assert.equal(ctx.dnsAnswerChangedObserved, false, '中止之后报告的 DNS 变化不得记入本轮')
  assert.equal(textCalls, 0, '中止之后到达的响应一个字节都不读')
})

await t('Codex P2：响应在截止时间之后才交回（已缓冲好的 body）——body 一个字节都不读，结论是 ProbeAborted(MAX_DURATION)', async () => {
  let textCalls = 0
  const ctx = ctxWithLeft(50)
  const fetchImpl: FetchLike = async () => {
    busyUntil(deadlineOf(ctx) + 1) // 同步越过截止时间：期间没有任何计时器能触发
    return { status: 200, headers: new Headers(), text: async () => { textCalls++; return 'buffered' } } as unknown as Response
  }
  await assert.rejects(() => sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx), isDurationAbort(BUDGET))
  assert.equal(textCalls, 0, '截止时间之后不得再开始读 body——哪怕它早已缓冲好、会在零延迟计时器之前读完')
})

await t('Codex P2：截止时间在上一跳重定向期间过去——下一跳请求根本不发出，结论是 ProbeAborted(MAX_DURATION)', async () => {
  let calls = 0
  const ctx = ctxWithLeft(50)
  const fetchImpl: FetchLike = async () => {
    calls++
    busyUntil(deadlineOf(ctx) + 1)
    return new Response(null, { status: 302, headers: { location: '/next' } })
  }
  await assert.rejects(() => sendRequest(fetchImpl, 'https://example.com/a', { method: 'GET' }, BUDGET, ctx), isDurationAbort(BUDGET))
  assert.equal(calls, 1, '截止时间之后不得再发起下一跳请求')
  assert.equal(ctx.requestCount, 1)
})

await t('时长与请求数同时用完时，时长优先（与 TODO 458 之前的检查顺序相同），且不发请求', async () => {
  let calls = 0
  const ctx = ctxWithLeft(0)
  ctx.requestCount = BUDGET.maxRequests
  await assert.rejects(() => sendRequest(async () => { calls++; return new Response('ok') }, 'https://example.com/a', {}, BUDGET, ctx), isDurationAbort(BUDGET))
  assert.equal(calls, 0)
})

await t('对照：同一个 DNS 变化信号在截止时间之前报告，照常记入本轮（上一条的「丢弃」不是因为信号根本没接上）', async () => {
  const fetchImpl: FetchLike = async (_i, _init, onGuardSignal) => {
    onGuardSignal({ dnsAnswerChanged: true })
    return new Response('ok')
  }
  const ctx = ctxWithLeft(5_000)
  await sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx)
  assert.equal(ctx.dnsAnswerChangedObserved, true)
})

await t('离截止时间只剩 1–5 ms 时 fetchImpl 自己失败：错误原样上抛——「时间预算用完」只由 wire.ts 自己的计时器触发，不看时钟离截止还有多近（review R1 B1）', async () => {
  // The ctx starts with ample time, so the request certainly starts; fetchImpl
  // then spins until exactly k ms remain and throws. Nothing can interleave
  // with that synchronous spin, and the rejection settles in microtasks before
  // our timer's macrotask could run — so every case really settles with ≤ k ms
  // left, on any runner.
  let calls = 0
  let ctx = ctxWithLeft(50)
  const leftAtThrow: number[] = []
  const throwing = (err: unknown, k: number): FetchLike => async () => {
    calls++
    busyUntil(deadlineOf(ctx) - k)
    leftAtThrow.push(deadlineOf(ctx) - Date.now())
    throw err
  }
  const errors: unknown[] = [
    new TypeError('socket hang up'),
    new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'),
    new BudgetExceeded('MAX_REDIRECTS', 'probe exceeded its 3-redirect budget'),
    new BudgetExceeded('MAX_DURATION', 'probe exceeded its 3ms wall-clock budget'),
    new Error('trial probe declined to fetch "evil.example.com"'),
  ]
  for (const leftMs of [1, 3, 5]) {
    for (const err of errors) {
      ctx = ctxWithLeft(50)
      await assert.rejects(
        () => sendRequest(throwing(err, leftMs), 'https://example.com/a', {}, BUDGET, ctx),
        (e: unknown) => e === err,
        `剩 ${leftMs} ms 时 ${(err as Error).name}: ${(err as Error).message} 必须原样上抛，不得改写成 MAX_DURATION`,
      )
    }
  }
  assert.equal(calls, 15, '前提：每一次都真的发出了请求，失败发生在请求之后，不是被请求前检查拦下')
  assert.ok(leftAtThrow.every((l, i) => l <= [1, 3, 5][Math.floor(i / 5)]!), `前提：每次抛出时剩余时间都 ≤ k：${leftAtThrow.join(',')}`)
})

await t('不按错误名泛化：离截止时间还远时，即使 fetchImpl 抛的是 BudgetExceeded(MAX_DURATION) 或 TimeoutError，也原样上抛、不改写', async () => {
  const guardTimeout = new BudgetExceeded('MAX_DURATION', 'probe exceeded its 10000ms wall-clock budget')
  await assert.rejects(() => sendRequest(async () => { throw guardTimeout }, 'https://example.com/a', {}, BUDGET, ctxWithLeft(5_000)), (e: unknown) => e === guardTimeout)
  const domTimeout = new DOMException('The operation was aborted due to timeout', 'TimeoutError')
  await assert.rejects(() => sendRequest(async () => { throw domTimeout }, 'https://example.com/a', {}, BUDGET, ctxWithLeft(5_000)), (e: unknown) => e === domTimeout)
})

await t('截止时间之前开始读 body 时的 body 超限仍是 MAX_BODY_BYTES：我们自己的 ProbeAborted 保留原代码', async () => {
  const ctx = ctxWithLeft(100)
  const fetchImpl: FetchLike = async () => {
    busyUntil(deadlineOf(ctx) - 20)
    return new Response('short body', { headers: { 'content-length': '99999999' } })
  }
  await assert.rejects(
    () => sendRequest(fetchImpl, 'https://example.com/a', {}, BUDGET, ctx),
    (e: unknown) => e instanceof ProbeAborted && e.code === 'MAX_BODY_BYTES',
  )
})

await t('计时器在每条路径上都被清掉：成功 / fetchImpl 抛错 / body 超限 / 429 / 重定向超限 / 截止中止 / 请求前中止之后，没有遗留的 Timeout', async () => {
  const timeouts = () => process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length
  const before = timeouts()
  const paths: [string, FetchLike, ProbeContext, RequestInit][] = [
    ['成功', async () => new Response('ok'), createProbeContext(Date.now()), {}],
    ['fetchImpl 抛错', async () => { throw new Error('boom') }, createProbeContext(Date.now()), {}],
    ['body 超限', async () => new Response('x', { headers: { 'content-length': '99999999' } }), createProbeContext(Date.now()), {}],
    ['429', async () => new Response('', { status: 429 }), createProbeContext(Date.now()), {}],
    ['重定向超限', async () => new Response(null, { status: 302, headers: { location: '/again' } }), createProbeContext(Date.now()), { method: 'GET' }],
    ['截止中止', () => new Promise<Response>(() => {}), ctxWithLeft(20), {}],
    ['请求前中止', async () => new Response('ok'), ctxWithLeft(0), {}],
  ]
  for (const [label, fetchImpl, ctx, init] of paths) {
    await sendRequest(fetchImpl, 'https://example.com/a', init, BUDGET, ctx).catch(() => {})
    assert.equal(timeouts(), before, `${label} 之后遗留了计时器`)
  }
})

console.log('\nparseRetryAfterSeconds：只认 delay-seconds，且只认非负安全整数')

await t('逐条对照 delay-seconds / HTTP-date / 几种「像数字但不是」的输入', () => {
  const cases: [string | null, number | undefined][] = [
    ['3600', 3600],
    ['  3600  ', 3600],
    ['0', 0],
    ['Wed, 21 Oct 2015 07:28:00 GMT', undefined],
    ['1e3', undefined],
    ['0x10', undefined],
    ['-5', undefined],
    ['3.5', undefined],
    ['', undefined],
    ['9'.repeat(310), undefined],
    ['9007199254740993', undefined],
    [null, undefined],
  ]
  for (const [raw, expected] of cases) {
    assert.equal(parseRetryAfterSeconds(raw), expected, 'Retry-After: ' + JSON.stringify(raw))
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
