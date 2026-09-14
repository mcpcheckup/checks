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

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
