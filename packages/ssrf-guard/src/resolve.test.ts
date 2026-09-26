import assert from 'node:assert'
import { resolveHost, validateAddresses, resolveAndValidateHost, resolveTxt, DOH_ENDPOINT, DOH_TIMEOUT_MS } from './resolve.ts'
import { SsrfBlocked } from './errors.ts'
import { QTYPE_A, QTYPE_AAAA, QTYPE_TXT } from './dns-wire.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---- 手工构造 DoH wireformat 响应字节（独立于 dns-wire.ts 的实现，只依赖 RFC 1035 格式）----

function header(id: number, rcode: number, ancount: number): number[] {
  return [
    (id >> 8) & 0xff, id & 0xff,
    0x81, 0x80 | (rcode & 0x0f),
    0x00, 0x01, // QDCOUNT
    (ancount >> 8) & 0xff, ancount & 0xff,
    0x00, 0x00,
    0x00, 0x00,
  ]
}

function question(hostname: string, qtype: number): number[] {
  const out: number[] = []
  for (const label of hostname.split('.')) {
    out.push(label.length, ...Array.from(Buffer.from(label, 'ascii')))
  }
  out.push(0, (qtype >> 8) & 0xff, qtype & 0xff, 0x00, 0x01)
  return out
}

function aRecord(ip: string): number[] {
  const octets = ip.split('.').map(Number)
  return [0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, ...octets]
}

function aaaaRecord(groups: number[]): number[] {
  const rdata: number[] = []
  for (const g of groups) rdata.push((g >> 8) & 0xff, g & 0xff)
  return [0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10, ...rdata]
}

function buildResponse(hostname: string, qtype: number, rcode: number, records: number[][]): Uint8Array<ArrayBuffer> {
  return Uint8Array.from([
    ...header(0, rcode, records.length),
    ...question(hostname, qtype),
    ...records.flat(),
  ])
}

interface FetchCall { url: string; method: string; contentType: string | null; body: Uint8Array<ArrayBuffer> }

function mockFetch(byQtype: Partial<Record<number, Uint8Array<ArrayBuffer> | 'network-error' | number>>, calls: FetchCall[]) {
  return async (input: unknown, init?: RequestInit): Promise<Response> => {
    const body = init?.body as Uint8Array<ArrayBuffer>
    const method = init?.method ?? 'GET'
    const contentType = (init?.headers as Record<string, string> | undefined)?.['content-type'] ?? null
    calls.push({ url: String(input), method, contentType, body })
    // 从请求体里读出 QTYPE（偏移量见 dns-wire 的 QNAME 布局：这里请求都是单标签一次性构造，
    // 直接从尾部倒数第 4-3 字节读 QTYPE，兼容任意主机名长度）
    const qtype = (body[body.length - 4]! << 8) | body[body.length - 3]!
    const outcome = byQtype[qtype]
    if (outcome === 'network-error') throw new TypeError('network error (simulated)')
    if (typeof outcome === 'number') return new Response(null, { status: outcome })
    if (outcome === undefined) return new Response(null, { status: 200 }) // 空 body -> 解码会抛错，模拟未预期到的 qtype
    return new Response(outcome, { status: 200, headers: { 'content-type': 'application/dns-message' } })
  }
}

console.log('resolveHost: 正常解析')

await t('A + AAAA 都有记录：返回两条地址，family 标注正确', async () => {
  const calls: FetchCall[] = []
  const fetchImpl = mockFetch(
    {
      [QTYPE_A]: buildResponse('example.com', QTYPE_A, 0, [aRecord('93.184.216.34')]),
      [QTYPE_AAAA]: buildResponse('example.com', QTYPE_AAAA, 0, [aaaaRecord([0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111])]),
    },
    calls,
  )
  const result = await resolveHost('example.com', { fetchImpl })
  assert.deepEqual(
    result.sort((a, b) => a.family - b.family),
    [
      { ip: '93.184.216.34', family: 4 },
      { ip: '2606:4700:4700:0:0:0:0:1111', family: 6 },
    ],
  )
})

await t('只有 A 记录（AAAA 是 NOERROR + 零 answer，真实世界最常见的情况）：只返回 A 地址', async () => {
  const calls: FetchCall[] = []
  const fetchImpl = mockFetch(
    {
      [QTYPE_A]: buildResponse('example.com', QTYPE_A, 0, [aRecord('93.184.216.34')]),
      [QTYPE_AAAA]: buildResponse('example.com', QTYPE_AAAA, 0, []),
    },
    calls,
  )
  const result = await resolveHost('example.com', { fetchImpl })
  assert.deepEqual(result, [{ ip: '93.184.216.34', family: 4 }])
})

await t('请求形状正确：POST、content-type: application/dns-message、固定指向 Cloudflare 自己的 resolver', async () => {
  const calls: FetchCall[] = []
  const fetchImpl = mockFetch(
    {
      [QTYPE_A]: buildResponse('example.com', QTYPE_A, 0, [aRecord('1.2.3.4')]),
      [QTYPE_AAAA]: buildResponse('example.com', QTYPE_AAAA, 0, []),
    },
    calls,
  )
  await resolveHost('example.com', { fetchImpl })
  assert.equal(calls.length, 2)
  for (const call of calls) {
    assert.equal(call.url, DOH_ENDPOINT)
    assert.equal(call.method, 'POST')
    assert.equal(call.contentType, 'application/dns-message')
  }
})

console.log('\nresolveHost: fail closed')

await t('网络层失败（fetch 本身 throw）：resolveHost 拒绝，不能当成"无记录"悄悄放过', async () => {
  const fetchImpl = mockFetch({ [QTYPE_A]: 'network-error', [QTYPE_AAAA]: buildResponse('x', QTYPE_AAAA, 0, []) }, [])
  await assert.rejects(() => resolveHost('example.com', { fetchImpl }))
})

await t('HTTP 状态非 200：resolveHost 拒绝', async () => {
  const fetchImpl = mockFetch({ [QTYPE_A]: 500, [QTYPE_AAAA]: buildResponse('x', QTYPE_AAAA, 0, []) }, [])
  await assert.rejects(() => resolveHost('example.com', { fetchImpl }))
})

await t('RCODE=3 (NXDOMAIN)：resolveHost 拒绝，不能返回空数组悄悄放过', async () => {
  const fetchImpl = mockFetch(
    { [QTYPE_A]: buildResponse('example.com', QTYPE_A, 3, []), [QTYPE_AAAA]: buildResponse('example.com', QTYPE_AAAA, 3, []) },
    [],
  )
  await assert.rejects(() => resolveHost('example.com', { fetchImpl }))
})

await t('A、AAAA 都是 NOERROR 但零 answer（域名存在但没有任何地址记录）：resolveHost 拒绝，因为没有可连接的目标', async () => {
  const fetchImpl = mockFetch(
    { [QTYPE_A]: buildResponse('example.com', QTYPE_A, 0, []), [QTYPE_AAAA]: buildResponse('example.com', QTYPE_AAAA, 0, []) },
    [],
  )
  await assert.rejects(() => resolveHost('example.com', { fetchImpl }))
})

await t('响应字节畸形（解码失败）：resolveHost 拒绝', async () => {
  const fetchImpl = mockFetch({ [QTYPE_A]: Uint8Array.from([1, 2, 3]), [QTYPE_AAAA]: buildResponse('x', QTYPE_AAAA, 0, []) }, [])
  await assert.rejects(() => resolveHost('example.com', { fetchImpl }))
})

console.log('\nvalidateAddresses')

await t('全部是公网地址：不抛错', () => {
  validateAddresses([{ ip: '93.184.216.34', family: 4 }, { ip: '8.8.8.8', family: 4 }])
})

await t('多个地址中有一个是私有网段：整体拒绝（不是"有一个公网的就放行"）', () => {
  assert.throws(
    () => validateAddresses([{ ip: '93.184.216.34', family: 4 }, { ip: '10.0.0.1', family: 4 }]),
    (e: unknown) => e instanceof SsrfBlocked && e.code === 'PRIVATE_USE',
  )
})

console.log('\nresolveAndValidateHost：解析与校验串联（重定向链攻击的单跳基础）')

await t('主机名解析到云 metadata 地址：拒绝，code 是 CLOUD_METADATA', async () => {
  const fetchImpl = mockFetch(
    {
      [QTYPE_A]: buildResponse('attacker.example.com', QTYPE_A, 0, [aRecord('169.254.169.254')]),
      [QTYPE_AAAA]: buildResponse('attacker.example.com', QTYPE_AAAA, 0, []),
    },
    [],
  )
  await assert.rejects(
    () => resolveAndValidateHost('attacker.example.com', { fetchImpl }),
    (e: unknown) => e instanceof SsrfBlocked && e.code === 'CLOUD_METADATA',
  )
})

await t('正常公网解析：返回校验通过的地址列表', async () => {
  const fetchImpl = mockFetch(
    {
      [QTYPE_A]: buildResponse('example.com', QTYPE_A, 0, [aRecord('93.184.216.34')]),
      [QTYPE_AAAA]: buildResponse('example.com', QTYPE_AAAA, 0, []),
    },
    [],
  )
  const result = await resolveAndValidateHost('example.com', { fetchImpl })
  assert.deepEqual(result, [{ ip: '93.184.216.34', family: 4 }])
})

console.log('\nresolveTxt')

function txtRecord(text: string): number[] {
  const strBytes = Array.from(Buffer.from(text, 'utf8'))
  const rdata = [strBytes.length, ...strBytes]
  return [0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, (rdata.length >> 8) & 0xff, rdata.length & 0xff, ...rdata]
}

// 只针对 resolveTxt 的单一 QTYPE_TXT 查询，不像 mockFetch 那样要区分 A/AAAA 两次请求。
function stubDoh(opts: { rcode?: number; txt?: string[] }) {
  const rcode = opts.rcode ?? 0
  const records = (opts.txt ?? []).map(txtRecord)
  const body = buildResponse('_x.example.com', QTYPE_TXT, rcode, records)
  return async (): Promise<Response> => new Response(body, { status: 200, headers: { 'content-type': 'application/dns-message' } })
}

await t('resolveTxt returns all TXT strings for a name', async () => {
  const fetchImpl = stubDoh({ txt: ['token-a', 'token-b'] })
  assert.deepEqual(await resolveTxt('_x.example.com', { fetchImpl }), ['token-a', 'token-b'])
})

await t('resolveTxt returns [] on NXDOMAIN instead of throwing', async () => {
  // 这是与 resolveHost 的关键语义差异：记录还没建 ≠ 查询失败。
  const fetchImpl = stubDoh({ rcode: 3 }) // NXDOMAIN
  assert.deepEqual(await resolveTxt('_x.example.com', { fetchImpl }), [])
})

await t('resolveTxt returns [] when the name exists but has no TXT records', async () => {
  const fetchImpl = stubDoh({ rcode: 0, txt: [] })
  assert.deepEqual(await resolveTxt('_x.example.com', { fetchImpl }), [])
})

await t('resolveTxt still throws SsrfBlocked on a transport failure — code RESOLVER_UNAVAILABLE, our own resolver (T85)', async () => {
  const fetchImpl = () => Promise.reject(new Error('boom'))
  await assert.rejects(() => resolveTxt('_x.example.com', { fetchImpl }), (e: unknown) => e instanceof SsrfBlocked && e.code === 'RESOLVER_UNAVAILABLE')
})

await t('resolveTxt throws RESOLVER_UNAVAILABLE (not []) when the response cannot be decoded as a DNS message', async () => {
  // 与 NXDOMAIN 的 [] 要分清：解码失败意味着"没问成"，不是"问过了、没有记录"。
  const fetchImpl = async () => new Response(Uint8Array.from([1, 2, 3]), { status: 200, headers: { 'content-type': 'application/dns-message' } })
  await assert.rejects(() => resolveTxt('_x.example.com', { fetchImpl }), (e: unknown) => e instanceof SsrfBlocked && e.code === 'RESOLVER_UNAVAILABLE')
})

await t('resolveTxt throws RESOLUTION_FAILED on RCODE=2 (SERVFAIL) —— 只有 RCODE=3 (NXDOMAIN) 才返回 []', async () => {
  const fetchImpl = stubDoh({ rcode: 2 })
  await assert.rejects(() => resolveTxt('_x.example.com', { fetchImpl }), /RESOLUTION_FAILED/)
})

console.log('\nDoH timeout (T85 PR-1b, R16): every DoH request is bounded; a hang ends as RESOLVER_UNAVAILABLE')

// A small injected timeout (DnsDeps.timeoutMs) instead of a real 3 s wait. GUARD_MS is the test's own
// timer: a query the code fails to bound turns into an assertion failure here, never a hung runner.
const TIMEOUT_MS = 30
const GUARD_MS = 1_000

/** Awaits p's rejection. Fails the test (AssertionError) if p resolves, or has not settled within GUARD_MS. */
async function rejectionWithinGuard(p: Promise<unknown>): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const guard = new Promise<'guard'>((resolve) => { timer = setTimeout(() => resolve('guard'), GUARD_MS) })
  const outcome = await Promise.race([p.then(() => 'resolved' as const, (error: unknown) => ({ error })), guard])
  clearTimeout(timer)
  if (outcome === 'guard') assert.fail(`did not settle within the test's ${GUARD_MS} ms guard: the DoH request is not bounded`)
  if (outcome === 'resolved') assert.fail('expected a rejection')
  return outcome.error
}

const qtypeOf = (init?: RequestInit) => { const b = init!.body as Uint8Array; return (b[b.length - 4]! << 8) | b[b.length - 3]! }
/** A DoH request that never answers; like a real fetch it rejects with the signal's reason on abort,
 *  and records that reason's name. Without a signal it never settles. */
function hangingRequest(init: RequestInit | undefined, aborts: string[]): Promise<Response> {
  return new Promise((_resolve, reject) => {
    const signal = init?.signal
    signal?.addEventListener('abort', () => { aborts.push((signal.reason as Error).name); reject(signal.reason) }, { once: true })
  })
}
const isResolverUnavailable = (e: unknown) => e instanceof SsrfBlocked && e.code === 'RESOLVER_UNAVAILABLE'

for (const hangs of [QTYPE_AAAA, QTYPE_A]) {
  const [fastName, hangName] = hangs === QTYPE_A ? ['AAAA', 'A'] : ['A', 'AAAA']
  await t(`(a) resolveHost: ${fastName} fails fast, ${hangName} never answers -> RESOLVER_UNAVAILABLE once the ${hangName} query times out`, async () => {
    const aborts: string[] = []
    const fetchImpl = (async (_i: unknown, init?: RequestInit) => {
      if (qtypeOf(init) === hangs) return hangingRequest(init, aborts)
      throw new TypeError('network error (simulated)')
    }) as unknown as typeof fetch
    const error = await rejectionWithinGuard(resolveHost('example.com', { fetchImpl, timeoutMs: TIMEOUT_MS }))
    assert.ok(isResolverUnavailable(error), String(error))
    assert.deepEqual(aborts, ['TimeoutError'], 'the hanging query was ended by its own timeout')
  })
}

await t('(b) resolveTxt: the DoH request never answers -> RESOLVER_UNAVAILABLE once it times out', async () => {
  const aborts: string[] = []
  const fetchImpl = (async (_i: unknown, init?: RequestInit) => hangingRequest(init, aborts)) as unknown as typeof fetch
  const error = await rejectionWithinGuard(resolveTxt('_x.example.com', { fetchImpl, timeoutMs: TIMEOUT_MS }))
  assert.ok(isResolverUnavailable(error), String(error))
  assert.match((error as Error).message, /DoH request to our own resolver failed/)
  assert.deepEqual(aborts, ['TimeoutError'])
})

/** Headers arrive at once; the answer body never does, and errors with the signal's reason on abort. */
const bodyNeverArrives = (async (_i: unknown, init?: RequestInit) => new Response(new ReadableStream({
  start(c) { const signal = init?.signal; signal?.addEventListener('abort', () => c.error(signal.reason), { once: true }) },
}), { status: 200 })) as unknown as typeof fetch

await t('(c) an abort during the answer-body read -> RESOLVER_UNAVAILABLE from the decode try (resolveHost and resolveTxt)', async () => {
  for (const p of [resolveHost('example.com', { fetchImpl: bodyNeverArrives, timeoutMs: TIMEOUT_MS }), resolveTxt('_x.example.com', { fetchImpl: bodyNeverArrives, timeoutMs: TIMEOUT_MS })]) {
    const error = await rejectionWithinGuard(p)
    assert.ok(isResolverUnavailable(error), String(error))
    assert.match((error as Error).message, /unparseable response: The operation was aborted due to timeout/)
  }
})

await t('by default every DoH request (both resolveHost queries, resolveTxt) gets AbortSignal.timeout(DOH_TIMEOUT_MS = 3,000); timeoutMs overrides it', async () => {
  assert.equal(DOH_TIMEOUT_MS, 3_000)
  const realTimeout = AbortSignal.timeout
  const requested: number[] = []
  const signals: unknown[] = []
  AbortSignal.timeout = (ms: number) => { requested.push(ms); return realTimeout.call(AbortSignal, ms) }
  try {
    const answer = mockFetch({ [QTYPE_A]: buildResponse('example.com', QTYPE_A, 0, [aRecord('1.2.3.4')]), [QTYPE_AAAA]: buildResponse('example.com', QTYPE_AAAA, 0, []), [QTYPE_TXT]: buildResponse('_x.example.com', QTYPE_TXT, 3, []) }, [])
    const fetchImpl = (async (i: unknown, init?: RequestInit) => { signals.push(init?.signal); return answer(i, init) }) as unknown as typeof fetch
    await resolveHost('example.com', { fetchImpl })
    await resolveTxt('_x.example.com', { fetchImpl })
    assert.deepEqual(requested, [3_000, 3_000, 3_000])
    await resolveTxt('_x.example.com', { fetchImpl, timeoutMs: 7 })
    assert.deepEqual(requested, [3_000, 3_000, 3_000, 7])
  } finally {
    AbortSignal.timeout = realTimeout
  }
  assert.equal(signals.length, 4)
  assert.ok(signals.every((s) => s instanceof AbortSignal))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
