import assert from 'node:assert'
import { guardedFetch } from './guarded-fetch.ts'
import { DEFAULT_PROBE_BUDGET } from './budget.ts'
import { SsrfBlocked, BudgetExceeded, RateLimited } from './errors.ts'
import type { ResolvedAddress } from './resolve.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ALLOW: import('./rate-limit.ts').RateLimitDecision = { allowed: true, scope: ['caller_ip'] }
const DENY: import('./rate-limit.ts').RateLimitDecision = { allowed: false, scope: ['caller_ip'], reason: '测试用拒绝' }

function publicV4(ip: string): ResolvedAddress[] {
  return [{ ip, family: 4 }]
}

/** 每个 hostname 一个应答队列：每次解析 shift 一个出来；队列耗尽后重复最后一个。 */
function makeResolver(byHostname: Record<string, ResolvedAddress[][]>) {
  const calls: string[] = []
  const cursors = new Map<string, number>()
  return {
    calls,
    impl: async (hostname: string): Promise<ResolvedAddress[]> => {
      calls.push(hostname)
      const queue = byHostname[hostname]
      if (!queue) throw new Error(`test bug: no mock DNS answer configured for ${hostname}`)
      const i = cursors.get(hostname) ?? 0
      cursors.set(hostname, Math.min(i + 1, queue.length - 1))
      const addrs = queue[Math.min(i, queue.length - 1)]!
      return addrs
    },
  }
}

/** 校验版：复用同一份队列，但对每个返回值跑一遍真实的 classifyIp 语义会太重——这里
 *  测的是 guardedFetch 的编排逻辑，不是 ip-policy 本身（已有独立测试），所以校验版
 *  resolver 只在"应该被拒绝"的用例里直接 throw SsrfBlocked，模拟 resolveAndValidateHost
 *  真实会做的事。 */
function makeValidatingResolver(byHostname: Record<string, ResolvedAddress[][] | SsrfBlocked>) {
  const calls: string[] = []
  const cursors = new Map<string, number>()
  return {
    calls,
    impl: async (hostname: string): Promise<ResolvedAddress[]> => {
      calls.push(hostname)
      const entry = byHostname[hostname]
      if (!entry) throw new Error(`test bug: no mock DNS answer configured for ${hostname}`)
      if (entry instanceof SsrfBlocked) throw entry
      const i = cursors.get(hostname) ?? 0
      cursors.set(hostname, Math.min(i + 1, entry.length - 1))
      return entry[Math.min(i, entry.length - 1)]!
    },
  }
}

interface FetchCall { url: string }
function makeFetch(byUrl: Record<string, () => Response>) {
  const calls: FetchCall[] = []
  return {
    calls,
    impl: async (input: unknown): Promise<Response> => {
      const url = String(input)
      calls.push({ url })
      const make = byUrl[url]
      if (!make) throw new Error(`test bug: no mock fetch response configured for ${url}`)
      return make()
    },
  }
}

const textParser = async (h: import('./response-view.ts').SafeResponseHandle) => ({ status: h.status, body: await h.text() })

console.log('guardedFetch: 限流闸门必须最先检查，早于任何网络访问')

await t('限流拒绝：抛 RateLimited，且没有发出任何 DNS 或 fetch 请求', async () => {
  const dns = makeValidatingResolver({})
  const net = makeFetch({})
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, DENY, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
      }),
    RateLimited,
  )
  assert.equal(dns.calls.length, 0)
  assert.equal(net.calls.length, 0)
})

await t('没有提供限流决定（undefined）：同样在联网前拒绝', async () => {
  const net = makeFetch({})
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, undefined, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
      }),
    RateLimited,
  )
  assert.equal(net.calls.length, 0)
})

console.log('\nguardedFetch: 正例——合法请求成功通过')

await t('公网目标、无重定向：成功，parseResponse 拿到结构化结果', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://example.com/mcp': () => new Response('{"ok":true}', { status: 200 }) })
  const result = await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  assert.equal(result.status, 200)
  assert.deepEqual(result.result, { status: 200, body: '{"ok":true}' })
  assert.equal(result.finalUrl, 'https://example.com/mcp')
  assert.equal(result.hops.length, 1)
})

await t('返回结果里不携带原始 Response 或 body 字段——只有调用方 parser 算出来的结构化结果', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://example.com/mcp': () => new Response('secret body content', { status: 200 }) })
  const result = await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: async () => 'parsed',
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  const json = JSON.stringify(result)
  assert.ok(!json.includes('secret body content'), 'raw target body must never leak into the GuardedFetchResult')
  assert.ok(!('body' in result) && !('rawResponse' in result) && !('response' in result))
})

console.log('\nguardedFetch: IP 字面量目标——跳过 DNS，也跳过 DNS 变化检测')

await t('目标是公网 IP 字面量：成功，且从未调用过 DNS resolver', async () => {
  const dns = makeValidatingResolver({})
  const net = makeFetch({ 'https://93.184.216.34/mcp': () => new Response('ok', { status: 200 }) }) // scan-secrets-allow: example.com's long-documented public IP, used as a real public IPv4 literal
  const result = await guardedFetch('https://93.184.216.34/mcp', DEFAULT_PROBE_BUDGET, ALLOW, { // scan-secrets-allow: same
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  assert.equal(dns.calls.length, 0)
  assert.equal(result.dnsAnswerChangedDuringProbe, false)
})

console.log('\nguardedFetch: 重定向链攻击——第一跳合法，第二跳指向云 metadata')

await t('hop1 合法公网域名 -> 302 -> hop2 解析到 169.254.169.254：整体被拒绝，且拒绝发生在 hop2（hop1 的 fetch 已经发出，hop2 的 fetch 从未发出）', async () => {
  const dns = makeValidatingResolver({
    'public.example.com': [publicV4('93.184.216.34')],
    'attacker.example.com': new SsrfBlocked('CLOUD_METADATA', '169.254.169.254 is a cloud instance metadata address'),
  })
  const net = makeFetch({
    'https://public.example.com/mcp': () =>
      new Response(null, { status: 302, headers: { location: 'https://attacker.example.com/mcp' } }),
    'https://attacker.example.com/mcp': () => new Response('should never be reached', { status: 200 }),
  })
  await assert.rejects(
    () =>
      guardedFetch('https://public.example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
        resolveHostImpl: dns.impl,
      }),
    (e: unknown) => e instanceof SsrfBlocked && e.code === 'CLOUD_METADATA',
  )
  assert.deepEqual(net.calls.map((c) => c.url), ['https://public.example.com/mcp'], 'hop2 的 fetch 绝不能被发出')
  // hop1: fetch 前校验一次 + fetch 后复查一次（每一跳 fetch 完都复查，不只是最后一跳）；
  // hop2: fetch 前校验就直接被拒绝，从未走到 fetch 这一步
  assert.deepEqual(dns.calls, ['public.example.com', 'public.example.com', 'attacker.example.com'])
})

console.log('\nguardedFetch: 相对 Location 基于当前 URL 正确解析')

await t('Location 是相对路径：下一跳基于当前 URL 正确拼出绝对地址', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({
    'https://example.com/a/b': () => new Response(null, { status: 302, headers: { location: '../c' } }),
    'https://example.com/c': () => new Response('final', { status: 200 }),
  })
  const result = await guardedFetch('https://example.com/a/b', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  assert.equal(result.finalUrl, 'https://example.com/c')
})

console.log('\nguardedFetch: 重定向跳数预算——边界测试')

function redirectChainFetch(hops: number) {
  const byUrl: Record<string, () => Response> = {}
  for (let i = 0; i < hops; i++) {
    byUrl[`https://example.com/${i}`] = () => new Response(null, { status: 302, headers: { location: `/${i + 1}` } })
  }
  byUrl[`https://example.com/${hops}`] = () => new Response('final', { status: 200 })
  return makeFetch(byUrl)
}

await t('跳数刚好用完（maxRedirects=2，恰好 2 次重定向）：成功', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = redirectChainFetch(2)
  const result = await guardedFetch('https://example.com/0', { ...DEFAULT_PROBE_BUDGET, maxRedirects: 2, maxRequests: 10 }, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  assert.equal(result.finalUrl, 'https://example.com/2')
})

await t('超一跳（maxRedirects=2，需要 3 次重定向）：抛 BudgetExceeded', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = redirectChainFetch(3)
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/0', { ...DEFAULT_PROBE_BUDGET, maxRedirects: 2, maxRequests: 10 }, ALLOW, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
        resolveHostImpl: dns.impl,
      }),
    BudgetExceeded,
  )
})

console.log('\nguardedFetch: 请求数预算')

await t('maxRequests=1 但重定向链需要 2 次请求：在发出第 2 个请求前拒绝', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = redirectChainFetch(1)
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/0', { ...DEFAULT_PROBE_BUDGET, maxRedirects: 5, maxRequests: 1 }, ALLOW, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
        resolveHostImpl: dns.impl,
      }),
    BudgetExceeded,
  )
  assert.equal(net.calls.length, 1)
})

console.log('\nguardedFetch: 探测期间 DNS 答案变化检测（不阻断连接，只产生证据）')

await t('同一 hostname，fetch 前后两次解析答案不同：dnsAnswerChangedDuringProbe=true，但请求仍然成功', async () => {
  const dns = makeResolver({ 'example.com': [publicV4('93.184.216.34'), publicV4('203.0.113.9')] })
  const net = makeFetch({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
  const result = await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  assert.equal(result.status, 200, '答案变化不能阻断已经发生的连接')
  assert.equal(result.dnsAnswerChangedDuringProbe, true)
  assert.equal(dns.calls.length, 2, 'fetch 前后各解析一次')
})

await t('同一 hostname，fetch 前后两次解析答案相同：dnsAnswerChangedDuringProbe=false', async () => {
  const dns = makeResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
  const result = await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  assert.equal(result.dnsAnswerChangedDuringProbe, false)
})

console.log('\nguardedFetch: TODO 591——复查时我方解析器没有应答（RESOLVER_UNAVAILABLE）不算「答案变了」，原样重抛；其余复查失败仍算「变了」')

/** 复查（resolveHostImpl）按调用顺序逐次给出的结果：地址集，或要抛出的错误。 */
function scriptedRecheck(steps: (ResolvedAddress[] | unknown)[]) {
  let i = 0
  return async (_hostname: string): Promise<ResolvedAddress[]> => {
    const step = steps[Math.min(i++, steps.length - 1)]
    if (Array.isArray(step)) return step as ResolvedAddress[]
    throw step
  }
}

/** 一个 body 可观察是否被 cancel 的响应。 */
function cancellableResponse(status: number, headers: Record<string, string> = {}) {
  const state = { cancelled: false }
  const response = new Response(new ReadableStream({ cancel() { state.cancelled = true } }), { status, headers })
  return { state, response }
}

const tick = () => new Promise((r) => setTimeout(r, 0))
const PRE = publicV4('93.184.216.34')

await t('复查抛 SsrfBlocked RESOLVER_UNAVAILABLE（hop 0）：原样重抛同一个错误对象，hop=0；这一跳的响应从未交给 parseResponse，body 被 cancel；onAudit 记录 dnsAnswerChangedDuringProbe=false', async () => {
  const unavailable = new SsrfBlocked('RESOLVER_UNAVAILABLE', 'DoH request to our own resolver failed: test')
  const target = cancellableResponse(200)
  const net = makeFetch({ 'https://example.com/mcp': () => target.response })
  let parsed = 0
  let captured: import('./audit.ts').ProbeAuditRecord | undefined
  let thrown: unknown
  await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: async () => { parsed++; return 'parsed' },
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: async () => PRE,
    resolveHostImpl: scriptedRecheck([unavailable]),
    onAudit: (record) => { captured = record },
  }).then(() => assert.fail('guardedFetch must reject'), (e: unknown) => { thrown = e })
  assert.strictEqual(thrown, unavailable, '重抛的必须是解析器抛出的同一个对象')
  assert.equal((thrown as SsrfBlocked).code, 'RESOLVER_UNAVAILABLE')
  assert.equal((thrown as SsrfBlocked).hop, 0)
  assert.equal(parsed, 0, '复查失败那一跳的响应绝不能被解析')
  await tick()
  assert.equal(target.state.cancelled, true, '被丢弃的响应的 body 必须被 cancel')
  assert.ok(captured)
  assert.equal(captured!.outcome, 'blocked')
  assert.equal(captured!.dnsAnswerChangedDuringProbe, false, '没有第二个应答，就没有观察到变化')
})

await t('GET 跟随一次重定向后，hop 1 的复查抛 RESOLVER_UNAVAILABLE：错误的 hop=1（不是 0，也不是缺失）；hop 1 的响应未被解析且 body 被 cancel', async () => {
  const unavailable = new SsrfBlocked('RESOLVER_UNAVAILABLE', 'DoH request to our own resolver failed: test')
  const final = cancellableResponse(200)
  const net = makeFetch({
    'https://example.com/a': () => new Response(null, { status: 302, headers: { location: '/b' } }),
    'https://example.com/b': () => final.response,
  })
  let parsed = 0
  let thrown: unknown
  await guardedFetch('https://example.com/a', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: async () => { parsed++; return 'parsed' },
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: async () => PRE,
    resolveHostImpl: scriptedRecheck([PRE, unavailable]),
  }).then(() => assert.fail('guardedFetch must reject'), (e: unknown) => { thrown = e })
  assert.deepEqual(net.calls.map((c) => c.url), ['https://example.com/a', 'https://example.com/b'])
  assert.strictEqual(thrown, unavailable)
  assert.equal((thrown as SsrfBlocked).hop, 1)
  assert.equal(parsed, 0)
  await tick()
  assert.equal(final.state.cancelled, true)
})

await t('Q2：复查抛 SsrfBlocked RESOLUTION_FAILED（解析器答了，名字不解析）：仍算「变了」，请求照常成功，dnsAnswerChangedDuringProbe=true', async () => {
  const net = makeFetch({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
  const result = await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: async () => PRE,
    resolveHostImpl: scriptedRecheck([new SsrfBlocked('RESOLUTION_FAILED', 'DNS resolution failed with RCODE 3')]),
  }).catch((e: unknown) => assert.fail(`RESOLUTION_FAILED on the re-check must count as changed, not reject: ${String(e)}`))
  assert.equal(result.status, 200)
  assert.equal(result.dnsAnswerChangedDuringProbe, true)
})

await t('故障安全：复查抛出其它错误——非 SsrfBlocked 的 Error、其它 code 的 SsrfBlocked、只是长得像（code 同为 RESOLVER_UNAVAILABLE 但不是 SsrfBlocked 实例）的对象——一律算「变了」，不重抛', async () => {
  const lookalike = Object.assign(new Error('lookalike'), { code: 'RESOLVER_UNAVAILABLE' })
  for (const failure of [new TypeError('boom'), new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), lookalike, 'a thrown string']) {
    const net = makeFetch({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
    const result = await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
      callerIdentifier: 'test-caller',
      parseResponse: textParser,
      fetchImpl: net.impl,
      resolveAndValidateHostImpl: async () => PRE,
      resolveHostImpl: scriptedRecheck([failure]),
    }).catch((e: unknown) => assert.fail(`re-check failure ${String(failure)} must count as changed, not reject: ${String(e)}`))
    assert.equal(result.dnsAnswerChangedDuringProbe, true, `re-check failure ${String(failure)} must count as changed`)
  }
})

await t('cancel 不能挂住调用、也不能替换原错误：cancel 返回永不 settle 的 promise / 返回 reject 的 promise / body getter 同步抛错——guardedFetch 都立即以原来那个 RESOLVER_UNAVAILABLE 拒绝', async () => {
  const shapes: [string, () => Response][] = [
    ['cancel never settles', () => new Response(new ReadableStream({ cancel: () => new Promise<void>(() => {}) }), { status: 200 })],
    ['cancel rejects', () => new Response(new ReadableStream({ cancel: () => Promise.reject(new Error('cancel failed')) }), { status: 200 })],
    ['body getter throws', () => ({ status: 200, headers: new Headers(), get body(): never { throw new Error('body getter failed') } }) as unknown as Response],
  ]
  for (const [label, make] of shapes) {
    const unavailable = new SsrfBlocked('RESOLVER_UNAVAILABLE', 'DoH request to our own resolver failed: test')
    const net = makeFetch({ 'https://example.com/mcp': make })
    const call = guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
      callerIdentifier: 'test-caller',
      parseResponse: textParser,
      fetchImpl: net.impl,
      resolveAndValidateHostImpl: async () => PRE,
      resolveHostImpl: scriptedRecheck([unavailable]),
    }).then(() => 'resolved', (e: unknown) => e)
    const outcome = await Promise.race([call, new Promise((r) => setTimeout(() => r('hung'), 1000))])
    assert.strictEqual(outcome, unavailable, `${label}: expected the original RESOLVER_UNAVAILABLE, got ${String(outcome)}`)
  }
})

await t('onAudit 在抛错路径上带着更早一跳观察到的变化：hop 0 复查答案不同，hop 1 的 fetch 失败——记录里 dnsAnswerChangedDuringProbe=true', async () => {
  const net = makeFetch({
    'https://example.com/a': () => new Response(null, { status: 302, headers: { location: '/b' } }),
  })
  let captured: import('./audit.ts').ProbeAuditRecord | undefined
  await assert.rejects(() =>
    guardedFetch('https://example.com/a', DEFAULT_PROBE_BUDGET, ALLOW, {
      callerIdentifier: 'test-caller',
      parseResponse: textParser,
      fetchImpl: net.impl, // /b 没有配置：mock fetch 抛错 → UpstreamFetchFailed
      resolveAndValidateHostImpl: async () => PRE,
      resolveHostImpl: scriptedRecheck([publicV4('203.0.113.9')]),
      onAudit: (record) => { captured = record },
    }),
  )
  assert.ok(captured)
  assert.equal(captured!.outcome, 'network_error')
  assert.equal(captured!.dnsAnswerChangedDuringProbe, true)
})

console.log('\nguardedFetch: 可审计记录——成功与失败都要拿到')

await t('成功路径：onAudit 收到 outcome=success 的完整记录', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
  let captured: import('./audit.ts').ProbeAuditRecord | undefined
  await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'caller-42',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    onAudit: (record) => { captured = record },
  })
  assert.ok(captured)
  assert.equal(captured!.outcome, 'success')
  assert.equal(captured!.callerIdentifier, 'caller-42')
  assert.equal(captured!.targetHost, 'example.com')
  assert.equal(captured!.hopCount, 1)
  assert.equal(captured!.blockedReason, null)
})

await t('失败路径（被拒绝）：即使 promise reject，onAudit 依然收到 outcome=blocked 的记录', async () => {
  const dns = makeValidatingResolver({
    'attacker.example.com': new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'),
  })
  const net = makeFetch({})
  let captured: import('./audit.ts').ProbeAuditRecord | undefined
  await assert.rejects(() =>
    guardedFetch('https://attacker.example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
      callerIdentifier: 'caller-42',
      parseResponse: textParser,
      fetchImpl: net.impl,
      resolveAndValidateHostImpl: dns.impl,
      resolveHostImpl: dns.impl,
      onAudit: (record) => { captured = record },
    }),
  )
  assert.ok(captured, 'onAudit 必须在失败路径也被调用')
  assert.equal(captured!.outcome, 'blocked')
  assert.ok(captured!.blockedReason?.includes('private-use'))
})

await t('失败路径（限流拒绝）：onAudit 收到 outcome=rate_limited', async () => {
  let captured: import('./audit.ts').ProbeAuditRecord | undefined
  await assert.rejects(() =>
    guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, DENY, {
      callerIdentifier: 'caller-42',
      parseResponse: textParser,
      onAudit: (record) => { captured = record },
    }),
  )
  assert.ok(captured)
  assert.equal(captured!.outcome, 'rate_limited')
})

console.log('\nguardedFetch: method/headers/body（N 任务，T1）——header allowlist')

interface FetchCallWithInit { url: string; init: RequestInit }
function makeFetchCapturingInit(byUrl: Record<string, (init: RequestInit) => Response>) {
  const calls: FetchCallWithInit[] = []
  return {
    calls,
    impl: async (input: unknown, init: RequestInit = {}): Promise<Response> => {
      const url = String(input)
      calls.push({ url, init })
      const make = byUrl[url]
      if (!make) throw new Error(`test bug: no mock fetch response configured for ${url}`)
      return make(init)
    },
  }
}

await t('allowlist 内的 header（大小写不敏感）原样透传给 fetchImpl，key 被归一化成小写', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetchCapturingInit({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
  await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    headers: { 'Content-Type': 'application/json', 'MCP-Protocol-Version': '2026-07-28' },
  })
  assert.deepEqual(net.calls[0]!.init.headers, {
    'content-type': 'application/json',
    'mcp-protocol-version': '2026-07-28',
  })
})

await t('allowlist 外的 header：抛 SsrfBlocked，错误信息里点名是哪个 header 被拒，且从未发出任何 DNS 或 fetch 请求', async () => {
  const dns = makeValidatingResolver({})
  const net = makeFetch({})
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
        headers: { 'X-Evil-Header': 'boo' },
      }),
    (e: unknown) => e instanceof SsrfBlocked && e.code === 'HEADER_NOT_ALLOWED' && e.message.includes('X-Evil-Header'),
  )
  assert.equal(dns.calls.length, 0)
  assert.equal(net.calls.length, 0)
})

await t('allowlist 边界：accept / authorization / mcp-session-id / mcp-method / mcp-name / user-agent 都被允许（VERIFIED 对照 packages/checks/src/protocol.ts 的真实 modernHeaders() 调用点，而不是只信任任务书里给的 5 个；user-agent 是 L2b 加的第 6 个，见该 commit）', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetchCapturingInit({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
  await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    headers: {
      accept: 'application/json, text/event-stream',
      authorization: 'Bearer test-token',
      'mcp-session-id': 'abc',
      'mcp-method': 'tools/list',
      'mcp-name': 'search',
      'user-agent': 'MCPCheckup-Probe/1.0 (+https://mcpcheckup.com/probe)',
    },
  })
  assert.deepEqual(net.calls[0]!.init.headers, {
    accept: 'application/json, text/event-stream',
    authorization: 'Bearer test-token',
    'mcp-session-id': 'abc',
    'mcp-method': 'tools/list',
    'mcp-name': 'search',
    'user-agent': 'MCPCheckup-Probe/1.0 (+https://mcpcheckup.com/probe)',
  })
})

console.log('\nguardedFetch: method 限制——只开 GET / POST')

await t('method 未指定：默认 GET，透传给 fetchImpl', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetchCapturingInit({ 'https://example.com/mcp': () => new Response('ok', { status: 200 }) })
  await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
  })
  assert.equal(net.calls[0]!.init.method, 'GET')
})

await t('method 是 GET/POST 之外的值：抛 SsrfBlocked，且从未发出任何 DNS 或 fetch 请求', async () => {
  const dns = makeValidatingResolver({})
  const net = makeFetch({})
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
        method: 'PUT' as 'GET',
      }),
    (e: unknown) => e instanceof SsrfBlocked && e.code === 'METHOD_NOT_ALLOWED',
  )
  assert.equal(dns.calls.length, 0)
  assert.equal(net.calls.length, 0)
})

console.log('\nguardedFetch: body——仅 POST 允许，计入 maxBodyBytes 预算')

await t('POST + body：body 原样透传给 fetchImpl', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetchCapturingInit({ 'https://example.com/mcp': () => new Response('{"ok":true}', { status: 200 }) })
  await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
  })
  assert.equal(net.calls[0]!.init.method, 'POST')
  assert.equal(net.calls[0]!.init.body, '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
})

await t('GET + body：抛 SsrfBlocked（body 只允许配 POST），从未发出任何请求', async () => {
  const dns = makeValidatingResolver({})
  const net = makeFetch({})
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
        body: '{}',
      }),
    (e: unknown) => e instanceof SsrfBlocked && e.code === 'BODY_REQUIRES_POST',
  )
  assert.equal(net.calls.length, 0)
})

await t('POST body 超过 maxBodyBytes：抛 BudgetExceeded，从未发出任何请求（请求体大小计入既有预算维度，不是新开一条）', async () => {
  const dns = makeValidatingResolver({})
  const net = makeFetch({})
  const tinyBudget = { ...DEFAULT_PROBE_BUDGET, maxBodyBytes: 4 }
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/mcp', tinyBudget, ALLOW, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        resolveAndValidateHostImpl: dns.impl,
        method: 'POST',
        body: 'this body is way over 4 bytes',
      }),
    BudgetExceeded,
  )
  assert.equal(net.calls.length, 0)
})

console.log('\nguardedFetch: 非 GET 不跟随重定向（N 任务安全要求 2）')

await t('POST 收到跨主机 302：不发第二跳的 fetch，重定向作为最终响应返回，redirectCrossHostObserved=true', async () => {
  const dns = makeValidatingResolver({ 'public.example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({
    'https://public.example.com/mcp': () =>
      new Response(null, { status: 307, headers: { location: 'https://other.example.com/mcp' } }),
  })
  const result = await guardedFetch('https://public.example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    method: 'POST',
    body: '{}',
  })
  assert.equal(result.status, 307)
  assert.equal(result.redirectCrossHostObserved, true)
  assert.deepEqual(net.calls.map((c) => c.url), ['https://public.example.com/mcp'], '第二跳的 fetch 绝不能被发出')
})

await t('POST 收到同主机 302：同样不跟随（默认不跟，不区分同源/跨主机），redirectCrossHostObserved=false', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({
    'https://example.com/a': () => new Response(null, { status: 302, headers: { location: 'https://example.com/b' } }),
  })
  const result = await guardedFetch('https://example.com/a', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    method: 'POST',
  })
  assert.equal(result.status, 302)
  assert.equal(result.redirectCrossHostObserved, false)
  assert.equal(net.calls.length, 1)
})

console.log('\nguardedFetch: followRedirects: false —— GET 的 3xx 与非 GET 一样原样返回，由调用方自己逐跳跟随')

/** One GET that answers `status` with `location`, through the real orchestration, with
 *  the audit record captured. `followRedirects` undefined = the option is absent. */
async function getOnce(location: string, followRedirects: boolean | undefined, budget = DEFAULT_PROBE_BUDGET, status = 302) {
  const dns = makeValidatingResolver({ 'public.example.com': [publicV4('93.184.216.34')], 'other.example.com': [publicV4('203.0.113.5')] })
  const net = makeFetch({
    'https://public.example.com/a': () => new Response('moved', { status, headers: { location } }),
    'https://public.example.com/b': () => new Response('same-host target', { status: 200 }),
    'https://other.example.com/c': () => new Response('other-host target', { status: 200 }),
  })
  const audits: import('./audit.ts').ProbeAuditRecord[] = []
  const result = await guardedFetch('https://public.example.com/a', budget, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    onAudit: (r) => audits.push(structuredClone(r)),
    ...(followRedirects === undefined ? {} : { followRedirects }),
  })
  return { result, urls: net.calls.map((c) => c.url), audits }
}

await t('GET + followRedirects:false 收到跨主机 302：恰好一次 fetch，3xx 原样作为结果返回（status / Location / redirectCrossHostObserved=true），审计记录一条 success', async () => {
  const { result, urls, audits } = await getOnce('https://other.example.com/c', false)
  assert.deepEqual(urls, ['https://public.example.com/a'], '第二跳绝不能被发出')
  assert.equal(result.status, 302)
  assert.equal(result.result.body, 'moved')
  assert.equal(result.finalUrl, 'https://public.example.com/a')
  assert.equal(result.redirectCrossHostObserved, true)
  assert.equal(audits.length, 1)
  assert.equal(audits[0]!.outcome, 'success')
  assert.equal(audits[0]!.hopCount, 1)
  assert.equal(audits[0]!.redirectCrossHostObserved, true)
})

await t('GET + followRedirects:false 收到同主机 302：同样恰好一次 fetch，redirectCrossHostObserved=false', async () => {
  const { result, urls, audits } = await getOnce('/b', false)
  assert.deepEqual(urls, ['https://public.example.com/a'])
  assert.equal(result.status, 302)
  assert.equal(result.redirectCrossHostObserved, false)
  assert.equal(audits[0]!.redirectCrossHostObserved, false)
})

await t('GET + followRedirects:false 与 maxRedirects=0 同时出现：仍是原样返回 302，绝不抛 MAX_REDIRECTS（「不跟随」不是「跳数超限」）', async () => {
  const { result, urls } = await getOnce('https://other.example.com/c', false, { ...DEFAULT_PROBE_BUDGET, maxRedirects: 0 })
  assert.deepEqual(urls, ['https://public.example.com/a'])
  assert.equal(result.status, 302)
})

await t('GET + followRedirects:false 收到每一种重定向状态（301/302/303/307/308）都原样返回', async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    const { result, urls } = await getOnce('https://other.example.com/c', false, DEFAULT_PROBE_BUDGET, status)
    assert.deepEqual(urls, ['https://public.example.com/a'], `${status}`)
    assert.equal(result.status, status)
  }
})

for (const [label, option] of [['选项缺省', undefined], ['followRedirects:true', true]] as const) {
  await t(`GET + ${label}：照旧跟随（跨主机两跳 fetch，返回最终 200，redirectCrossHostObserved=true）`, async () => {
    const { result, urls } = await getOnce('https://other.example.com/c', option)
    assert.deepEqual(urls, ['https://public.example.com/a', 'https://other.example.com/c'])
    assert.equal(result.status, 200)
    assert.equal(result.result.body, 'other-host target')
    assert.equal(result.redirectCrossHostObserved, true)
  })
}

await t('POST + followRedirects:true 也不跟随：这个选项只能让 GET 更严，不能让非 GET 变松', async () => {
  const dns = makeValidatingResolver({ 'public.example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({
    'https://public.example.com/mcp': () => new Response(null, { status: 307, headers: { location: 'https://other.example.com/mcp' } }),
  })
  const result = await guardedFetch('https://public.example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    method: 'POST',
    body: '{}',
    followRedirects: true,
  })
  assert.equal(result.status, 307)
  assert.equal(net.calls.length, 1)
})

console.log('\nguardedFetch: authorization 头绝不跨主机传递（N 任务安全要求 3，独立于「非 GET 不跟随重定向」的第二道锁）')

await t('GET 多跳，hop2 跨主机：hop1 的 fetch 带 authorization，hop2 的 fetch 不带；同主机 hop 之间 authorization 保留', async () => {
  const dns = makeValidatingResolver({
    'public.example.com': [publicV4('93.184.216.34')],
    'other.example.com': [publicV4('203.0.113.5')],
  })
  const net = makeFetchCapturingInit({
    'https://public.example.com/a': () =>
      new Response(null, { status: 302, headers: { location: 'https://public.example.com/b' } }),
    'https://public.example.com/b': () =>
      new Response(null, { status: 302, headers: { location: 'https://other.example.com/c' } }),
    'https://other.example.com/c': () => new Response('final', { status: 200 }),
  })
  await guardedFetch('https://public.example.com/a', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    headers: { authorization: 'Bearer secret-token', accept: 'application/json' },
  })
  assert.equal(net.calls.length, 3)
  assert.equal((net.calls[0]!.init.headers as Record<string, string>).authorization, 'Bearer secret-token', 'hop1（原始请求）必须带上 authorization')
  assert.equal((net.calls[1]!.init.headers as Record<string, string>).authorization, 'Bearer secret-token', 'hop2 仍是同主机（public.example.com -> public.example.com），authorization 必须保留')
  assert.equal((net.calls[2]!.init.headers as Record<string, string>).authorization, undefined, 'hop3 跨主机（public.example.com -> other.example.com），authorization 绝不能出现')
  assert.equal((net.calls[2]!.init.headers as Record<string, string>).accept, 'application/json', '跨主机只剥离 authorization，其余 allowlist 内的 header 不受影响')
})

console.log('\nguardedFetch: onAudit / 限流 对 POST 路径同样生效（N 任务安全要求 5）')

await t('POST + 限流拒绝：抛 RateLimited，且没有发出任何 DNS 或 fetch 请求（与 GET 路径同一把闸门）', async () => {
  const net = makeFetch({})
  await assert.rejects(
    () =>
      guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, DENY, {
        callerIdentifier: 'test-caller',
        parseResponse: textParser,
        fetchImpl: net.impl,
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      }),
    RateLimited,
  )
  assert.equal(net.calls.length, 0)
})

await t('POST 成功路径：onAudit 收到 outcome=success，redirectCrossHostObserved=false', async () => {
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://example.com/mcp': () => new Response('{"ok":true}', { status: 200 }) })
  let captured: import('./audit.ts').ProbeAuditRecord | undefined
  await guardedFetch('https://example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'caller-42',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    method: 'POST',
    body: '{}',
    onAudit: (record) => { captured = record },
  })
  assert.ok(captured)
  assert.equal(captured!.outcome, 'success')
  assert.equal(captured!.redirectCrossHostObserved, false)
})

await t('POST 被跨主机重定向截断的路径：onAudit 依然收到一条 outcome=success 的记录（重定向本身不是错误），redirectCrossHostObserved=true', async () => {
  const dns = makeValidatingResolver({ 'public.example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({
    'https://public.example.com/mcp': () =>
      new Response(null, { status: 307, headers: { location: 'https://other.example.com/mcp' } }),
  })
  let captured: import('./audit.ts').ProbeAuditRecord | undefined
  await guardedFetch('https://public.example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'caller-42',
    parseResponse: textParser,
    fetchImpl: net.impl,
    resolveAndValidateHostImpl: dns.impl,
    resolveHostImpl: dns.impl,
    method: 'POST',
    onAudit: (record) => { captured = record },
  })
  assert.ok(captured)
  assert.equal(captured!.outcome, 'success')
  assert.equal(captured!.redirectCrossHostObserved, true)
})

console.log('\nguardedFetch: a followed redirect hop\'s body is cancelled, never left open')

/** A 3xx whose body records whether it was cancelled. */
function trackedRedirect(location: string) {
  const state = { cancelled: false }
  const body = new ReadableStream<Uint8Array>({
    start(controller) { controller.enqueue(new TextEncoder().encode('moved')) },
    cancel() { state.cancelled = true },
  })
  return { state, response: () => new Response(body, { status: 302, headers: { location } }) }
}

await t('GET follows a 302: that hop\'s body is cancelled, and the next hop is still fetched and parsed', async () => {
  const hop = trackedRedirect('https://example.com/b')
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({
    'https://example.com/a': hop.response,
    'https://example.com/b': () => new Response('final', { status: 200 }),
  })
  const r = await guardedFetch('https://example.com/a', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller', parseResponse: textParser,
    fetchImpl: net.impl, resolveAndValidateHostImpl: dns.impl, resolveHostImpl: dns.impl,
  })
  assert.deepEqual(r.result, { status: 200, body: 'final' })
  assert.deepEqual(net.calls.map((c) => c.url), ['https://example.com/a', 'https://example.com/b'])
  assert.equal(hop.state.cancelled, true, 'the followed hop\'s body must be cancelled')
})

await t('GET 302 with maxRedirects 0: MAX_REDIRECTS is thrown, and that hop\'s body is cancelled first', async () => {
  const hop = trackedRedirect('https://example.com/b')
  const dns = makeValidatingResolver({ 'example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://example.com/a': hop.response })
  await assert.rejects(
    () => guardedFetch('https://example.com/a', { ...DEFAULT_PROBE_BUDGET, maxRedirects: 0 }, ALLOW, {
      callerIdentifier: 'test-caller', parseResponse: textParser,
      fetchImpl: net.impl, resolveAndValidateHostImpl: dns.impl, resolveHostImpl: dns.impl,
    }),
    (e: unknown) => e instanceof BudgetExceeded && e.code === 'MAX_REDIRECTS',
  )
  assert.equal(net.calls.length, 1)
  assert.equal(hop.state.cancelled, true, 'the hop that hit the redirect budget must have its body cancelled')
})

console.log('\nguardedFetch: an onAudit that throws is called once, never changes the outcome, and leaves one warn line')

const WARN_PREFIX = 'ssrf-guard onAudit threw'
const MARKER = 'audit-marker-7f3c'

/** Runs `fn` with console.warn captured, then always restores it. */
async function captureWarn<R>(fn: () => Promise<R>): Promise<{ value: R, warns: string[] }> {
  const saved = console.warn
  const warns: string[] = []
  console.warn = (...a: unknown[]) => { warns.push(a.map(String).join(' ')) }
  try { return { value: await fn(), warns } } finally { console.warn = saved }
}

/** One audited call to a public host, with the given onAudit. */
function auditedCall(onAudit: (r: import('./audit.ts').ProbeAuditRecord) => void) {
  const dns = makeValidatingResolver({ 'audit-host.example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://audit-host.example.com/mcp': () => new Response('ok', { status: 200 }) })
  return guardedFetch('https://audit-host.example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller', parseResponse: textParser,
    fetchImpl: net.impl, resolveAndValidateHostImpl: dns.impl, resolveHostImpl: dns.impl,
    onAudit,
  })
}

await t('success path, onAudit throws: the result is still returned, onAudit ran once, one warn line with only the error\'s name', async () => {
  let calls = 0
  const { value, warns } = await captureWarn(() => auditedCall(() => {
    calls++
    throw new TypeError(`${MARKER} https://audit-host.example.com/mcp audit-host.example.com`)
  }))
  assert.deepEqual(value.result, { status: 200, body: 'ok' })
  assert.equal(value.status, 200)
  assert.equal(calls, 1)
  assert.equal(warns.length, 1, JSON.stringify(warns))
  assert.ok(warns[0]!.startsWith(WARN_PREFIX), warns[0])
  assert.equal(warns[0], `${WARN_PREFIX}: TypeError`)
  for (const leaked of [MARKER, 'https://audit-host.example.com/mcp', 'audit-host.example.com']) {
    assert.ok(!warns[0]!.includes(leaked), `the warn line must not carry ${leaked}`)
  }
})

await t('the warn line never carries the thrown value itself: a thrown string, and an Error whose name is not a native error name', async () => {
  const thrown: unknown[] = [`${MARKER} audit-host.example.com`, Object.assign(new Error(MARKER), { name: `${MARKER} audit-host.example.com` })]
  const lines: string[] = []
  for (const v of thrown) {
    const { warns } = await captureWarn(() => auditedCall(() => { throw v }))
    lines.push(...warns)
  }
  assert.deepEqual(lines, [`${WARN_PREFIX}: non-Error string`, `${WARN_PREFIX}: Error`])
})

await t('redirect returned as the result (POST 302), onAudit throws: still returned, onAudit ran once, one warn line', async () => {
  const dns = makeValidatingResolver({ 'audit-host.example.com': [publicV4('93.184.216.34')] })
  const net = makeFetch({ 'https://audit-host.example.com/mcp': () => new Response('moved', { status: 302, headers: { location: 'https://other.example.com/x' } }) })
  let calls = 0
  const { value, warns } = await captureWarn(() => guardedFetch('https://audit-host.example.com/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller', parseResponse: textParser, method: 'POST',
    fetchImpl: net.impl, resolveAndValidateHostImpl: dns.impl, resolveHostImpl: dns.impl,
    onAudit: () => { calls++; throw new RangeError(MARKER) },
  }))
  assert.equal(value.status, 302)
  assert.equal(calls, 1)
  assert.deepEqual(warns, [`${WARN_PREFIX}: RangeError`])
})

await t('blocked call (loopback IP literal), onAudit throws: the original SsrfBlocked is rethrown, onAudit ran once, one warn line', async () => {
  let calls = 0
  let outcome: string | undefined
  const { value: error, warns } = await captureWarn(async () => {
    try {
      await guardedFetch('https://127.0.0.1/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
        callerIdentifier: 'test-caller', parseResponse: textParser,
        fetchImpl: async () => { throw new Error('test bug: a blocked target must never be fetched') },
        onAudit: (r) => { calls++; outcome = r.outcome; throw new Error(MARKER) },
      })
    } catch (e) { return e }
    return undefined
  })
  assert.ok(error instanceof SsrfBlocked, `expected the original SsrfBlocked, got ${String(error)}`)
  assert.equal(error.code, 'LOOPBACK')
  assert.ok(!error.message.includes(MARKER))
  assert.equal(calls, 1)
  assert.equal(outcome, 'blocked')
  assert.deepEqual(warns, [`${WARN_PREFIX}: Error`])
})

const LEAK_URL = 'https://leak.example.com/secret-path'
/** An Error whose `name` getter throws (carrying the URL in its own message). */
const nameGetterThrows = () => Object.defineProperty(new Error(MARKER), 'name', { get() { throw new Error(`${MARKER} ${LEAK_URL}`) } })
/** An Error-backed Proxy whose getPrototypeOf trap throws, so even `instanceof` throws. */
const prototypeTrapThrows = () => new Proxy(new Error(MARKER), { getPrototypeOf() { throw new Error(`${MARKER} ${LEAK_URL}`) } })

await t('success path, the thrown value\'s name getter (or a Proxy trap) throws: still returned, onAudit ran once, one `Error` line', async () => {
  for (const make of [nameGetterThrows, prototypeTrapThrows]) {
    let calls = 0
    const { value, warns } = await captureWarn(() => auditedCall(() => { calls++; throw make() }))
    assert.deepEqual(value.result, { status: 200, body: 'ok' })
    assert.equal(calls, 1)
    assert.deepEqual(warns, [`${WARN_PREFIX}: Error`])
  }
})

await t('blocked call, the thrown value\'s name getter throws: the original SsrfBlocked LOOPBACK is rethrown, onAudit ran once, one `Error` line', async () => {
  let calls = 0
  const { value: error, warns } = await captureWarn(() => guardedFetch('https://127.0.0.1/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller', parseResponse: textParser,
    onAudit: () => { calls++; throw nameGetterThrows() },
  }).then(() => undefined, (e: unknown) => e))
  assert.ok(error instanceof SsrfBlocked, `expected the original SsrfBlocked, got ${String(error)}`)
  assert.equal(error.code, 'LOOPBACK')
  assert.equal(calls, 1)
  assert.deepEqual(warns, [`${WARN_PREFIX}: Error`])
})

await t('a name getter that answers differently on each read: the line prints the value it checked, never a later URL', async () => {
  let reads = 0
  const shifty = Object.defineProperty(new Error(MARKER), 'name', { get() { reads++; return reads <= 2 ? 'TypeError' : LEAK_URL } })
  const { value, warns } = await captureWarn(() => auditedCall(() => { throw shifty }))
  assert.equal(value.status, 200)
  assert.equal(warns.length, 1, JSON.stringify(warns))
  for (const leaked of [LEAK_URL, 'leak.example.com']) assert.ok(!warns[0]!.includes(leaked), `the warn line must not carry ${leaked}`)
  assert.equal(warns[0], `${WARN_PREFIX}: TypeError`)
})

await t('only a native ECMAScript error name is printed: `localhost` and `SsrfBlocked` give `Error`, a TypeError stays `TypeError`', async () => {
  const thrown = [
    Object.assign(new Error(MARKER), { name: 'localhost' }),
    Object.assign(new Error(MARKER), { name: 'SsrfBlocked' }),
    new SsrfBlocked('LOOPBACK', MARKER),
    new TypeError(MARKER),
  ]
  const lines: string[] = []
  for (const v of thrown) {
    const { value, warns } = await captureWarn(() => auditedCall(() => { throw v }))
    assert.equal(value.status, 200)
    lines.push(...warns)
  }
  assert.deepEqual(lines, [`${WARN_PREFIX}: Error`, `${WARN_PREFIX}: Error`, `${WARN_PREFIX}: Error`, `${WARN_PREFIX}: TypeError`])
})

await t('console.warn itself throws: a success still returns and a blocked call still rethrows its own SsrfBlocked, onAudit once each', async () => {
  const saved = console.warn
  let warnCalls = 0
  console.warn = () => { warnCalls++; throw new Error(`${MARKER} console broke`) }
  try {
    let calls = 0
    const ok = await auditedCall(() => { calls++; throw new TypeError(MARKER) })
    assert.deepEqual(ok.result, { status: 200, body: 'ok' })
    assert.equal(calls, 1)
    let blockedCalls = 0
    const error = await guardedFetch('https://127.0.0.1/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
      callerIdentifier: 'test-caller', parseResponse: textParser,
      onAudit: () => { blockedCalls++; throw new TypeError(MARKER) },
    }).then(() => undefined, (e: unknown) => e)
    assert.ok(error instanceof SsrfBlocked, `expected the original SsrfBlocked, got ${String(error)}`)
    assert.equal(error.code, 'LOOPBACK')
    assert.equal(blockedCalls, 1)
    assert.equal(warnCalls, 2)
  } finally {
    console.warn = saved
  }
})

await t('sanity: an onAudit that does not throw leaves no warn line, success or failure', async () => {
  let calls = 0
  const ok = await captureWarn(() => auditedCall(() => { calls++ }))
  const blocked = await captureWarn(() => guardedFetch('https://127.0.0.1/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller', parseResponse: textParser, onAudit: () => { calls++ },
  }).catch((e: unknown) => e))
  assert.equal(ok.value.status, 200)
  assert.ok(blocked.value instanceof SsrfBlocked)
  assert.equal(calls, 2)
  assert.deepEqual([...ok.warns, ...blocked.warns], [])
})

console.log('\nguardedFetch: an onAudit that returns a promise which rejects gets the same one warn line, and is never left unhandled')

/** Long enough for a rejection, and Node's unhandled-rejection check, to have run. */
const settle = () => new Promise((r) => setTimeout(r, 20))

/** Runs `fn` with console.warn captured and unhandled rejections recorded, until things settle. */
async function captureSettled<R>(fn: () => Promise<R>): Promise<{ value: R, warns: string[], unhandled: unknown[] }> {
  const unhandled: unknown[] = []
  const onUnhandled = (reason: unknown) => { unhandled.push(reason) }
  process.on('unhandledRejection', onUnhandled)
  try {
    const { value, warns } = await captureWarn(async () => { const v = await fn(); await settle(); return v })
    return { value, warns, unhandled }
  } finally {
    process.off('unhandledRejection', onUnhandled)
  }
}

/** A blocked call (loopback IP literal) with the given onAudit; resolves to what it threw. */
function blockedAuditedCall(onAudit: (r: import('./audit.ts').ProbeAuditRecord) => void) {
  return guardedFetch('https://127.0.0.1/mcp', DEFAULT_PROBE_BUDGET, ALLOW, {
    callerIdentifier: 'test-caller', parseResponse: textParser,
    fetchImpl: async () => { throw new Error('test bug: a blocked target must never be fetched') },
    onAudit,
  }).then(() => undefined, (e: unknown) => e)
}

const hostileName = () => Object.defineProperty(new Error(MARKER), 'name', { get() { throw new Error(`${MARKER} ${LEAK_URL}`) } })

for (const [label, make, expected] of [
  ['an Error (RangeError)', () => new RangeError(`${MARKER} ${LEAK_URL}`), 'RangeError'],
  ['a non-Error (a string)', () => `${MARKER} ${LEAK_URL}`, 'non-Error string'],
  ['an Error whose name getter throws', hostileName, 'Error'],
  ['an Error named after a host', () => Object.assign(new Error(MARKER), { name: 'audit-host.example.com' }), 'Error'],
] as const) {
  await t(`async onAudit rejecting with ${label}: called once, the result unchanged, exactly one warn line "${expected}", nothing unhandled`, async () => {
    let calls = 0
    const ok = await captureSettled(() => auditedCall(async () => { calls++; throw make() }))
    assert.deepEqual(ok.value.result, { status: 200, body: 'ok' })
    assert.equal(ok.value.status, 200)
    assert.deepEqual(ok.warns, [`${WARN_PREFIX}: ${expected}`])
    assert.deepEqual(ok.unhandled, [])
    const blocked = await captureSettled(() => blockedAuditedCall(async () => { calls++; await tick(); throw make() }))
    assert.ok(blocked.value instanceof SsrfBlocked, `expected the original SsrfBlocked, got ${String(blocked.value)}`)
    assert.equal(blocked.value.code, 'LOOPBACK')
    assert.ok(!blocked.value.message.includes(MARKER))
    assert.deepEqual(blocked.warns, [`${WARN_PREFIX}: ${expected}`])
    assert.deepEqual(blocked.unhandled, [])
    assert.equal(calls, 2)
    for (const line of [...ok.warns, ...blocked.warns]) assert.ok(!line.includes(MARKER) && !line.includes(LEAK_URL), line)
  })
}

await t('async onAudit that resolves: called once, no warn line, nothing unhandled', async () => {
  let calls = 0
  const ok = await captureSettled(() => auditedCall(async () => { calls++; await tick() }))
  const blocked = await captureSettled(() => blockedAuditedCall(async () => { calls++ }))
  assert.equal(ok.value.status, 200)
  assert.ok(blocked.value instanceof SsrfBlocked)
  assert.equal(calls, 2)
  assert.deepEqual([...ok.warns, ...blocked.warns, ...ok.unhandled, ...blocked.unhandled], [])
})

await t('the returned promise is never awaited: an onAudit whose promise never settles does not hold up a success or a rejection', async () => {
  const never = () => new Promise<void>(() => {})
  const ok = await captureSettled(() => auditedCall(never as () => void))
  const blocked = await captureSettled(() => blockedAuditedCall(never as () => void))
  assert.equal(ok.value.status, 200)
  assert.ok(blocked.value instanceof SsrfBlocked)
  assert.deepEqual([...ok.warns, ...blocked.warns], [])
})

await t('a hostile return value: a `then` getter that throws, a `then` that throws, or a throwing Proxy escapes nowhere and writes no line', async () => {
  const getterThrows = Object.defineProperty({}, 'then', { get() { throw new Error(`${MARKER} ${LEAK_URL}`) } })
  const thenThrows = { then() { throw new Error(`${MARKER} ${LEAK_URL}`) } }
  const proxyTrap = new Proxy({}, { get() { throw new Error(`${MARKER} ${LEAK_URL}`) } })
  for (const hostile of [getterThrows, thenThrows, proxyTrap]) {
    let calls = 0
    const ok = await captureSettled(() => auditedCall((() => { calls++; return hostile }) as () => void))
    const blocked = await captureSettled(() => blockedAuditedCall((() => { calls++; return hostile }) as () => void))
    assert.deepEqual(ok.value.result, { status: 200, body: 'ok' })
    assert.ok(blocked.value instanceof SsrfBlocked && blocked.value.code === 'LOOPBACK', String(blocked.value))
    assert.equal(calls, 2)
    assert.deepEqual([...ok.warns, ...blocked.warns, ...ok.unhandled, ...blocked.unhandled], [])
  }
})

await t('a thenable that calls its rejection handler twice still gives exactly one warn line', async () => {
  const twice = { then(_onFulfilled: unknown, onRejected: (e: unknown) => void) { onRejected(new TypeError(MARKER)); onRejected(new RangeError(MARKER)) } }
  const ok = await captureSettled(() => auditedCall((() => twice) as () => void))
  assert.equal(ok.value.status, 200)
  assert.deepEqual(ok.warns, [`${WARN_PREFIX}: TypeError`])
})

console.log('\nguardedFetch: a native promise is handled through the built-in then, whatever own `then` it carries')

/** A rejected native promise, made inside onAudit, whose own `then` is replaced by `then`. */
const rejectedWithOwnThen = (then: unknown) => () => {
  const p = Promise.reject(new RangeError(`${MARKER} ${LEAK_URL}`))
  Object.defineProperty(p, 'then', { value: then })
  return p
}

for (const [label, then] of [
  ['a non-function (42)', 42],
  ['a function that does nothing', () => {}],
] as const) {
  await t(`a rejecting native promise whose own then is ${label}: called once, the result unchanged, one warn line "RangeError", nothing unhandled`, async () => {
    let calls = 0
    const make = rejectedWithOwnThen(then)
    const ok = await captureSettled(() => auditedCall((() => { calls++; return make() }) as () => void))
    assert.deepEqual(ok.value.result, { status: 200, body: 'ok' })
    assert.deepEqual(ok.warns, [`${WARN_PREFIX}: RangeError`])
    assert.deepEqual(ok.unhandled, [])
    const blocked = await captureSettled(() => blockedAuditedCall((() => { calls++; return make() }) as () => void))
    assert.ok(blocked.value instanceof SsrfBlocked && blocked.value.code === 'LOOPBACK', String(blocked.value))
    assert.deepEqual(blocked.warns, [`${WARN_PREFIX}: RangeError`])
    assert.deepEqual(blocked.unhandled, [])
    assert.equal(calls, 2)
  })
}

await t('the documented limit: a rejecting Promise subclass whose Symbol.species getter throws gets no handler, writes no line, and its rejection is left unhandled', async () => {
  class SpeciesThrows extends Promise<void> {}
  Object.defineProperty(SpeciesThrows, Symbol.species, { get() { throw new Error(`${MARKER} ${LEAK_URL}`) } })
  const reason = new RangeError(MARKER)
  let calls = 0
  const ok = await captureSettled(() => auditedCall((() => { calls++; return new SpeciesThrows((_resolve, reject) => reject(reason)) }) as () => void))
  assert.deepEqual(ok.value.result, { status: 200, body: 'ok' })
  assert.equal(calls, 1)
  assert.deepEqual(ok.warns, [])
  assert.deepEqual(ok.unhandled, [reason])
})

await t('an object that only inherits from Promise.prototype: the built-in then refuses it, its own then is used instead, and its rejection gives one warn line "TypeError"', async () => {
  const fake = () => Object.assign(Object.create(Promise.prototype) as object, {
    then(_onFulfilled: unknown, onRejected: (e: unknown) => void) { onRejected(new TypeError(`${MARKER} ${LEAK_URL}`)) },
  })
  assert.ok(fake() instanceof Promise, 'the case under test: it passes instanceof Promise')
  let calls = 0
  const ok = await captureSettled(() => auditedCall((() => { calls++; return fake() }) as () => void))
  assert.deepEqual(ok.value.result, { status: 200, body: 'ok' })
  assert.deepEqual(ok.warns, [`${WARN_PREFIX}: TypeError`])
  const blocked = await captureSettled(() => blockedAuditedCall((() => { calls++; return fake() }) as () => void))
  assert.ok(blocked.value instanceof SsrfBlocked && blocked.value.code === 'LOOPBACK', String(blocked.value))
  assert.deepEqual(blocked.warns, [`${WARN_PREFIX}: TypeError`])
  assert.equal(calls, 2)
  assert.deepEqual([...ok.unhandled, ...blocked.unhandled], [])
})

await t('the documented limit: a Proxy around a rejecting promise: the built-in then refuses the Proxy, its own then (the built-in one, called on the Proxy) throws too: no line, the rejection left unhandled', async () => {
  const reason = new RangeError(MARKER)
  let calls = 0
  const ok = await captureSettled(() => auditedCall((() => { calls++; return new Proxy(Promise.reject(reason), {}) }) as () => void))
  assert.deepEqual(ok.value.result, { status: 200, body: 'ok' })
  assert.equal(calls, 1)
  assert.deepEqual(ok.warns, [])
  assert.deepEqual(ok.unhandled, [reason])
})

console.log('\nguardedFetch: promise shapes, each pinned to what it actually does')

type ThenArgs = Parameters<Promise<unknown>['then']>
const rejecting = () => Promise.reject(new RangeError(`${MARKER} ${LEAK_URL}`))
const hostileTrap = () => { throw new Error(`${MARKER} ${LEAK_URL}`) }
/** A get trap that forwards `then` to the target promise, bound to it. */
const forwardThen = (target: Promise<unknown>, key: string | symbol) => (key === 'then' ? target.then.bind(target) : Reflect.get(target, key))
const rejectTwice = (onRejected: (e: unknown) => void) => { onRejected(new TypeError(MARKER)); onRejected(new RangeError(MARKER)) }

/** Every shape measured; the keys are the rows of the comparison table below. */
const SHAPES: Record<string, () => unknown> = {
  P1: () => new Proxy(rejecting(), {}),
  P2: () => new Proxy(rejecting(), { get: (t, k) => (k === 'then' ? (...a: ThenArgs) => t.then(...a) : Reflect.get(t, k)) }),
  P3: () => new Proxy(rejecting(), { get: forwardThen }),
  P4: () => new Proxy(rejecting(), { get: forwardThen, getPrototypeOf: hostileTrap }),
  P5: () => new Proxy(rejecting(), { get: forwardThen, getPrototypeOf: () => Object.prototype }),
  P6: () => new Proxy(rejecting(), { get: (t, k, receiver) => Reflect.get(t, k, receiver) }),
  P7: () => new Proxy(rejecting(), { get: (t, k) => (k === 'then' ? (...a: ThenArgs) => Promise.prototype.then.apply(t, a) : Reflect.get(t, k)) }),
  P8: () => new Proxy({ then: (_f: unknown, onRejected: (e: unknown) => void) => onRejected(new TypeError(MARKER)) }, { getPrototypeOf: hostileTrap }),
  S1: () => {
    class SpeciesThrows extends Promise<void> {}
    Object.defineProperty(SpeciesThrows, Symbol.species, { get: hostileTrap })
    return new SpeciesThrows((_resolve, reject) => reject(new RangeError(MARKER)))
  },
  S2: () => Object.defineProperty(rejecting(), 'constructor', { get: hostileTrap }),
  S3a: () => Object.assign(rejecting(), { constructor: 5 }),
  S3b: () => Object.assign(rejecting(), { constructor: { [Symbol.species]: 5 } }),
  N0: () => rejecting(),
  F: () => Object.assign(Object.create(Promise.prototype) as object, { then: (_f: unknown, onRejected: (e: unknown) => void) => onRejected(new TypeError(MARKER)) }),
  D: () => ({ then: (_f: unknown, onRejected: (e: unknown) => void) => rejectTwice(onRejected) }),
}

for (const [label, shape] of [
  ['S2, a native promise whose own `constructor` getter throws', 'S2'],
  ['S3a, a native promise whose `constructor` is 5 (not an object)', 'S3a'],
] as const) {
  await t(`species lookup throws: ${label}: no line, the rejection left unhandled`, async () => {
    const r = await captureSettled(() => auditedCall(SHAPES[shape] as () => void))
    assert.deepEqual(r.value.result, { status: 200, body: 'ok' })
    assert.deepEqual(r.warns, [])
    assert.equal(r.unhandled.length, 1)
    assert.ok(r.unhandled[0] instanceof RangeError)
  })
}

for (const [label, shape, name] of [
  ['P2, a Proxy whose get trap forwards `then` to the promise', 'P2', 'RangeError'],
  ['P4, a Proxy that forwards `then` and whose getPrototypeOf trap throws', 'P4', 'RangeError'],
  ['P8, a Proxy around a plain thenable whose getPrototypeOf trap throws', 'P8', 'TypeError'],
] as const) {
  await t(`${label}: one warn line "${name}", nothing unhandled`, async () => {
    let calls = 0
    const r = await captureSettled(() => auditedCall((() => { calls++; return SHAPES[shape]!() }) as () => void))
    assert.deepEqual(r.value.result, { status: 200, body: 'ok' })
    assert.equal(calls, 1)
    assert.deepEqual(r.warns, [`${WARN_PREFIX}: ${name}`])
    assert.deepEqual(r.unhandled, [])
  })
}

/**
 * [shape, warn lines on 0badc66f, warn lines now, unhandled rejections now]. The 0badc66f
 * column is that commit's guarded-fetch.ts, which reads `then` directly with no
 * instanceof check. It was measured once, by running each SHAPES factory through one
 * successful guardedFetch call against that commit, with console.warn counted and an
 * unhandledRejection listener; it is fixed here because that code is not importable.
 */
const COMPARED: [string, number, number, number][] = [
  ['P1', 0, 0, 1], // measured on 0badc66f: 0
  ['P2', 1, 1, 0], // measured on 0badc66f: 1
  ['P3', 1, 1, 0], // measured on 0badc66f: 1
  ['P4', 1, 1, 0], // measured on 0badc66f: 1
  ['P5', 1, 1, 0], // measured on 0badc66f: 1
  ['P6', 0, 0, 1], // measured on 0badc66f: 0
  ['P7', 1, 1, 0], // measured on 0badc66f: 1
  ['P8', 1, 1, 0], // measured on 0badc66f: 1
  ['S1', 0, 0, 1], // measured on 0badc66f: 0
  ['S2', 0, 0, 1], // measured on 0badc66f: 0
  ['S3a', 0, 0, 1], // measured on 0badc66f: 0
  ['S3b', 0, 0, 1], // measured on 0badc66f: 0
  ['N0', 1, 1, 0], // measured on 0badc66f: 1
  ['F', 1, 1, 0], // measured on 0badc66f: 1
  ['D', 1, 1, 0], // measured on 0badc66f: 1
]

await t('no shape gets fewer warn lines than on 0badc66f, and each shape\'s current counts are pinned', async () => {
  assert.deepEqual(COMPARED.map(([shape]) => shape).sort(), Object.keys(SHAPES).sort(), 'every shape has a row')
  for (const [shape, before, warns, unhandled] of COMPARED) {
    const r = await captureSettled(() => auditedCall(SHAPES[shape] as () => void))
    assert.ok(r.warns.length >= before, `${shape}: ${r.warns.length} warn lines, fewer than the ${before} on 0badc66f`)
    assert.equal(r.warns.length, warns, `${shape}: warn lines`)
    assert.equal(r.unhandled.length, unhandled, `${shape}: unhandled rejections`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
