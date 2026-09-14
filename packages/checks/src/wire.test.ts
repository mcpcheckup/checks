import assert from 'node:assert'
import { sendRequest, createProbeContext, ProbeAborted, parseRetryAfterSeconds } from './wire.ts'
import type { FetchLike } from './types.ts'
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
