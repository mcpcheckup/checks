/**
 * T85 R4 — the guard's allow / block decisions are unchanged by T85, which only
 * renamed the code on six first-party resolver failures (RESOLUTION_FAILED ->
 * RESOLVER_UNAVAILABLE) and wrapped the target's own fetch / body-read
 * rejections (UpstreamFetchFailed). One case per existing block code, each
 * through guardedFetch itself, plus the allowed controls.
 *
 * Every case records its DECISION: the thrown class and code (or the HTTP
 * status when allowed) and how many requests reached the target. The table
 * below is the expected set; the printed `DECISION|…` lines are the same data,
 * so this file run against the pre-T85 package (it imports only API that
 * existed before T85) gives a line-for-line before/after diff. The only
 * expected differences are the three RESOLVER_UNAVAILABLE rows, which were
 * RESOLUTION_FAILED before — still SsrfBlocked, still zero requests — and the
 * round-2 row for an unreadable DoH answer body, which was the runtime's own
 * TypeError before: rejected before, rejected now, zero requests either way.
 */
import assert from 'node:assert'
import { readdirSync, readFileSync } from 'node:fs'
import ts from 'typescript'
import { guardedFetch, SsrfBlocked, BudgetExceeded, RateLimited, resolveAndValidateHost, validateAddresses, DEFAULT_PROBE_BUDGET } from './index.ts'
import type { GuardedFetchOptions, ResolvedAddress, RateLimitDecision, ProbeBudget } from './index.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ALLOW: RateLimitDecision = { allowed: true, scope: [] }
const DENY: RateLimitDecision = { allowed: false, scope: [], reason: 'test' }

/** A DoH wireformat answer for whatever A / AAAA query it is sent (RFC 1035, built by hand). */
function doh(opts: { rcode?: number; a?: number[][]; status?: number; reject?: boolean; garbage?: boolean; unreadable?: boolean }): typeof fetch {
  return (async (_input: unknown, init?: RequestInit) => {
    if (opts.reject) throw new TypeError('Network connection lost.')
    if (opts.status !== undefined) return new Response('', { status: opts.status })
    if (opts.garbage) return new Response(Uint8Array.from([1, 2, 3]), { status: 200 })
    if (opts.unreadable) return new Response(new ReadableStream({ pull(c) { c.error(new TypeError('Network connection lost.')) } }), { status: 200 })
    const q = init!.body as Uint8Array
    const qtype = (q[q.length - 4]! << 8) | q[q.length - 3]!
    const answers = qtype === 1 ? (opts.a ?? []) : []
    const header = [0, 0, 0x81, 0x80 | ((opts.rcode ?? 0) & 0x0f), 0, 1, 0, answers.length, 0, 0, 0, 0]
    const question = Array.from(q.slice(12))
    const records = answers.flatMap((o) => [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, ...o])
    return new Response(Uint8Array.from([...header, ...question, ...records]), { status: 200 })
  }) as typeof fetch
}

interface Case {
  name: string
  url: string
  decision?: RateLimitDecision | null
  budget?: ProbeBudget
  opts?: Partial<GuardedFetchOptions<number>>
  resolve?: (hostname: string) => Promise<ResolvedAddress[]>
  expected: string
}

const viaDoh = (o: Parameters<typeof doh>[0]) => (hostname: string) => resolveAndValidateHost(hostname, { fetchImpl: doh(o) })

const CASES: Case[] = [
  // url-target.ts
  { name: 'unparseable URL', url: 'not a url', expected: 'SsrfBlocked:MALFORMED_URL|0' },
  { name: 'http scheme', url: 'http://example.com/', expected: 'SsrfBlocked:NON_HTTPS_SCHEME|0' },
  { name: 'credentials in URL', url: 'https://u:p@example.com/', expected: 'SsrfBlocked:CREDENTIALS_IN_URL|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: 'non-standard port', url: 'https://example.com:8443/', expected: 'SsrfBlocked:NON_STANDARD_PORT|0' },
  // guarded-fetch.ts request shape
  { name: 'header outside the allowlist', url: 'https://example.com/', opts: { headers: { 'x-forwarded-for': '1' } }, expected: 'SsrfBlocked:HEADER_NOT_ALLOWED|0' },
  { name: 'method PUT', url: 'https://example.com/', opts: { method: 'PUT' as 'GET' }, expected: 'SsrfBlocked:METHOD_NOT_ALLOWED|0' },
  { name: 'body on GET', url: 'https://example.com/', opts: { body: 'x' }, expected: 'SsrfBlocked:BODY_REQUIRES_POST|0' },
  // rate-limit.ts / budget
  { name: 'rate-limit decision denies', url: 'https://example.com/', decision: DENY, expected: 'RateLimited:RATE_LIMITED|0' },
  { name: 'no rate-limit decision', url: 'https://example.com/', decision: null, expected: 'RateLimited:RATE_LIMITED|0' },
  { name: 'request body over budget', url: 'https://example.com/', opts: { method: 'POST', body: 'xx' }, budget: { ...DEFAULT_PROBE_BUDGET, maxBodyBytes: 1 }, expected: 'BudgetExceeded:MAX_BODY_BYTES|0' },
  { name: 'zero request budget', url: 'https://example.com/', budget: { ...DEFAULT_PROBE_BUDGET, maxRequests: 0 }, expected: 'BudgetExceeded:MAX_REQUESTS|0' },
  // ip-policy.ts, IP literals
  { name: '10.0.0.1', url: 'https://10.0.0.1/', expected: 'SsrfBlocked:PRIVATE_USE|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '127.0.0.1', url: 'https://127.0.0.1/', expected: 'SsrfBlocked:LOOPBACK|0' },
  { name: '169.254.1.1', url: 'https://169.254.1.1/', expected: 'SsrfBlocked:LINK_LOCAL|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '169.254.169.254', url: 'https://169.254.169.254/', expected: 'SsrfBlocked:CLOUD_METADATA|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '0.1.2.3', url: 'https://0.1.2.3/', expected: 'SsrfBlocked:THIS_NETWORK|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '100.64.0.1', url: 'https://100.64.0.1/', expected: 'SsrfBlocked:CGNAT|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '192.0.2.1', url: 'https://192.0.2.1/', expected: 'SsrfBlocked:DOCUMENTATION|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '198.18.0.1', url: 'https://198.18.0.1/', expected: 'SsrfBlocked:BENCHMARKING|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '224.0.0.1', url: 'https://224.0.0.1/', expected: 'SsrfBlocked:MULTICAST|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '240.0.0.1', url: 'https://240.0.0.1/', expected: 'SsrfBlocked:RESERVED|0' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: '[fc00::1]', url: 'https://[fc00::1]/', expected: 'SsrfBlocked:UNIQUE_LOCAL|0' },
  { name: '[::]', url: 'https://[::]/', expected: 'SsrfBlocked:UNSPECIFIED|0' },
  { name: '[fe80::1]', url: 'https://[fe80::1]/', expected: 'SsrfBlocked:LINK_LOCAL|0' },
  { name: '[fd00:ec2::254]', url: 'https://[fd00:ec2::254]/', expected: 'SsrfBlocked:CLOUD_METADATA|0' },
  { name: '[::ffff:127.0.0.1]', url: 'https://[::ffff:127.0.0.1]/', expected: 'SsrfBlocked:LOOPBACK|0' },
  // resolve.ts through the real validating resolver, fake DoH
  { name: 'name resolving to 10.0.0.1', url: 'https://example.com/', resolve: viaDoh({ a: [[10, 0, 0, 1]] }), expected: 'SsrfBlocked:PRIVATE_USE|0' },
  { name: 'name resolving to 169.254.169.254', url: 'https://example.com/', resolve: viaDoh({ a: [[169, 254, 169, 254]] }), expected: 'SsrfBlocked:CLOUD_METADATA|0' },
  { name: 'resolved address that is not an address', url: 'https://example.com/', resolve: async () => { const a: ResolvedAddress[] = [{ ip: '999.1.1.1', family: 4 }]; validateAddresses(a); return a }, expected: 'SsrfBlocked:MALFORMED|0' },
  { name: 'NXDOMAIN (server side)', url: 'https://example.com/', resolve: viaDoh({ rcode: 3 }), expected: 'SsrfBlocked:RESOLUTION_FAILED|0' },
  { name: 'SERVFAIL (server side)', url: 'https://example.com/', resolve: viaDoh({ rcode: 2 }), expected: 'SsrfBlocked:RESOLUTION_FAILED|0' },
  { name: 'no A or AAAA records (server side)', url: 'https://example.com/', resolve: viaDoh({ a: [] }), expected: 'SsrfBlocked:RESOLUTION_FAILED|0' },
  { name: 'our DoH request rejected', url: 'https://example.com/', resolve: viaDoh({ reject: true }), expected: 'SsrfBlocked:RESOLVER_UNAVAILABLE|0' },
  { name: 'our DoH resolver answered HTTP 503', url: 'https://example.com/', resolve: viaDoh({ status: 503 }), expected: 'SsrfBlocked:RESOLVER_UNAVAILABLE|0' },
  { name: 'our DoH resolver answered garbage', url: 'https://example.com/', resolve: viaDoh({ garbage: true }), expected: 'SsrfBlocked:RESOLVER_UNAVAILABLE|0' },
  { name: 'our DoH resolver answer body unreadable', url: 'https://example.com/', resolve: viaDoh({ unreadable: true }), expected: 'SsrfBlocked:RESOLVER_UNAVAILABLE|0' },
  // allowed controls
  { name: 'public IP literal', url: 'https://1.1.1.1/', expected: 'ok:200|1' }, // scan-secrets-allow: RFC special-use / placeholder address, a block-code test input, never contacted
  { name: 'name resolving to a public address', url: 'https://example.com/', resolve: viaDoh({ a: [[1, 1, 1, 1]] }), expected: 'ok:200|1' },
  { name: 'POST with an allowlisted header', url: 'https://example.com/', opts: { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } }, expected: 'ok:200|1' },
]

async function decide(c: Case): Promise<string> {
  let requests = 0
  const fetchImpl = (async () => { requests++; return new Response('ok', { status: 200 }) }) as typeof fetch
  const resolve = c.resolve ?? (async (): Promise<ResolvedAddress[]> => [{ ip: '1.1.1.1', family: 4 }])
  try {
    const r = await guardedFetch(c.url, c.budget ?? DEFAULT_PROBE_BUDGET, c.decision === undefined ? ALLOW : c.decision, {
      callerIdentifier: 'block-set.test',
      fetchImpl,
      resolveAndValidateHostImpl: resolve,
      resolveHostImpl: resolve,
      parseResponse: (h) => h.status,
      ...c.opts,
    })
    return `ok:${r.result}|${requests}`
  } catch (e) {
    const cls = e instanceof SsrfBlocked ? 'SsrfBlocked' : e instanceof BudgetExceeded ? 'BudgetExceeded' : e instanceof RateLimited ? 'RateLimited' : `other:${(e as Error).name}`
    return `${cls}:${(e as { code?: string }).code ?? ''}|${requests}`
  }
}

console.log('T85 R4: guard decision table (one case per block code, plus allowed controls)')
for (const c of CASES) {
  const got = await decide(c)
  console.log(`DECISION|${c.name}|${got}`)
  await t(`${c.name} -> ${c.expected}`, () => assert.equal(got, c.expected))
}

/** Every SsrfBlocked code the source can raise, read off the TypeScript AST of
 *  this package's non-test files: the string-literal first argument of each
 *  `new SsrfBlocked(…)`, plus every member of the IpBlockCode union (the one
 *  site that passes a variable, `verdict.code`, is typed by it). A
 *  `new SsrfBlocked` whose code is neither is an error, not skipped. */
function blockCodesInSource(): string[] {
  const dir = new URL('./', import.meta.url)
  const codes = new Set<string>()
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))) {
    const sf = ts.createSourceFile(file, readFileSync(new URL(file, dir), 'utf8'), ts.ScriptTarget.Latest, true)
    const visit = (node: ts.Node): void => {
      if (ts.isTypeAliasDeclaration(node) && node.name.text === 'IpBlockCode' && ts.isUnionTypeNode(node.type)) {
        for (const m of node.type.types) if (ts.isLiteralTypeNode(m) && ts.isStringLiteral(m.literal)) codes.add(m.literal.text)
      }
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'SsrfBlocked') {
        const arg = node.arguments?.[0]
        if (arg !== undefined && ts.isStringLiteral(arg)) codes.add(arg.text)
        else if (!(arg !== undefined && ts.isPropertyAccessExpression(arg) && arg.name.text === 'code')) throw new Error(`${file}: new SsrfBlocked with a code that is neither a literal nor verdict.code`)
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }
  return [...codes].sort()
}

await t('every block code in the source is in the table, and nothing else is (read off the AST)', () => {
  const inTable = new Set(CASES.map((c) => c.expected.split('|')[0]!).filter((o) => o.startsWith('SsrfBlocked:')).map((o) => o.slice('SsrfBlocked:'.length)))
  assert.deepEqual([...inTable].sort(), blockCodesInSource())
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
