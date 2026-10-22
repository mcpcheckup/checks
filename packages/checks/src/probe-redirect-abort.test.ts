// Suite 0.15.0: a cross-host redirect seen before an abort is still recorded.
// redirect_policy is COMPLETED/OBSERVED_RISK redirect_cross_host_observed, as on a run
// that finishes, whichever of the six aborts then ends the run: another host declined
// (OtherHostDeclined), a guard refusal (SsrfBlocked), the redirect budget (including
// the hop that goes over it), the request budget, the time budget, and the server
// asking us to back off (429). Every other check that never ran keeps the abort's own
// reason, SKIPPED/UNVERIFIED, never FAILED. The control: the same aborts after a
// same-host redirect leave redirect_policy with the abort's reason, as before.
//
// The run: a modern server whose handshake is fine and whose tools/list is
// credential-gated with a challenge naming a resource_metadata URL on the endpoint's
// host, so auth_metadata fetches that URL with a GET, the one request that follows
// redirects. That GET is answered with a 302.
import assert from 'node:assert'
import { DEFAULT_PROBE_BUDGET, SsrfBlocked } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { runProbe } from './probe.ts'
import { OtherHostDeclined } from './other-host-declined.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { ProbeInput, ProbeResult } from './index.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const HOST = 'notes-mcp.example.com'
const ENDPOINT = `https://${HOST}/mcp`
const METADATA = `https://${HOST}/.well-known/oauth-protected-resource`

/** What happens to the request that follows the 302 (the hop), or to the 302 itself. */
type Abort = 'declined' | 'ssrf' | 'MAX_REDIRECTS' | 'MAX_REQUESTS' | 'MAX_DURATION' | '429'

const BUDGETS: Record<Abort, ProbeBudget> = {
  declined: DEFAULT_PROBE_BUDGET,
  ssrf: DEFAULT_PROBE_BUDGET,
  // The first 302 is already over a zero-hop budget: wire.ts must read its Location first.
  MAX_REDIRECTS: { ...DEFAULT_PROBE_BUDGET, maxRedirects: 0 },
  // discover, tools/list, the metadata GET: the hop would be the fourth request.
  MAX_REQUESTS: { ...DEFAULT_PROBE_BUDGET, maxRequests: 3 },
  MAX_DURATION: { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 400 },
  '429': DEFAULT_PROBE_BUDGET,
}

const REASONS: Record<Abort, { key: string; params?: Record<string, string | number> }> = {
  declined: { key: 'probe_declined_other_host' },
  ssrf: { key: 'probe_blocked_by_policy', params: { code: 'PRIVATE_USE' } },
  MAX_REDIRECTS: { key: 'probe_budget_exhausted_redirects', params: { maxRedirects: 0 } },
  MAX_REQUESTS: { key: 'probe_budget_exhausted_requests', params: { maxRequests: 3 } },
  MAX_DURATION: { key: 'probe_budget_exhausted_duration', params: { maxDurationMs: 400 } },
  '429': { key: 'probe_rate_limited', params: { status: 429, retryAfterSeconds: 60 } },
}

const rpc = (id: unknown, body: Record<string, unknown>, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ jsonrpc: '2.0', id, ...body }), { status, headers: { 'content-type': 'application/json', ...headers } })

async function run(abort: Abort, crossHost: boolean): Promise<{ result: ProbeResult; hrefs: string[] }> {
  const hrefs: string[] = []
  const target = crossHost ? 'https://other.example.com/metadata' : `https://${HOST}/metadata-moved`
  const fetchImpl: ProbeInput['fetchImpl'] = async (input, init) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    hrefs.push(href)
    if (typeof init?.body === 'string') {
      const call = JSON.parse(init.body) as { id: unknown; method: string }
      if (call.method === 'server/discover') return rpc(call.id, { result: { supportedVersions: ['2026-07-28'], capabilities: { tools: {} } } })
      return new Response('', { status: 401, headers: { 'www-authenticate': `Bearer realm="mcp", resource_metadata="${METADATA}"` } })
    }
    if (href === METADATA) return new Response('', { status: 302, headers: { location: target } })
    assert.equal(href, target, 'only the redirect target is requested next')
    if (abort === 'declined') throw new OtherHostDeclined()
    if (abort === 'ssrf') throw Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 })
    if (abort === 'MAX_DURATION') return new Promise<Response>((resolve) => setTimeout(() => resolve(new Response('{}', { status: 200 })), 1500))
    if (abort === '429') return new Response('', { status: 429, headers: { 'retry-after': '60' } })
    throw new Error(`the ${abort} abort must come before this hop is sent`)
  }
  let seq = 0
  const result = await runProbe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget: BUDGETS[abort],
    now: () => '2026-10-22T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  })
  return { result, hrefs }
}

const row = (r: ProbeResult, id: string): Assertion => r.assertions.find((a) => a.check_id === id)!
const state = (a: Assertion) => [a.execution_status, a.assertion_status, a.reason]
const ABORTS: Abort[] = ['declined', 'ssrf', 'MAX_REDIRECTS', 'MAX_REQUESTS', 'MAX_DURATION', '429']

console.log('suite 0.15.0（TODO 779 / 797）：跨主机重定向之后中止，redirect_policy 照样记 OBSERVED_RISK；其余没跑的检查带中止原因，绝不 FAILED')

for (const abort of ABORTS) {
  await t(`${abort} after a cross-host 302: redirect_policy COMPLETED/OBSERVED_RISK redirect_cross_host_observed; auth_metadata takes the abort's reason; nothing FAILED`, async () => {
    const { result, hrefs } = await run(abort, true)
    assert.deepStrictEqual(hrefs.slice(0, 3), [ENDPOINT, ENDPOINT, METADATA])
    assert.deepStrictEqual(state(row(result, 'redirect_policy')), ['COMPLETED', 'OBSERVED_RISK', { key: 'redirect_cross_host_observed' }])
    assert.deepStrictEqual(row(result, 'redirect_policy').unverified_reason, null)
    assert.deepStrictEqual(state(row(result, 'auth_metadata')), ['SKIPPED', 'UNVERIFIED', REASONS[abort]])
    assert.deepStrictEqual(state(row(result, 'reachability')), ['COMPLETED', 'VERIFIED', null], 'the handshake had answered')
    assert.equal(row(result, 'tools_list').reason?.key, 'credential_required', 'what was recorded before the abort stays')
    assert.ok(result.assertions.every((a) => a.assertion_status !== 'FAILED'), 'no FAILED')
    assert.equal(result.assertions.filter((a) => a.assertion_status === 'OBSERVED_RISK').length, 1, 'redirect_policy is the only OBSERVED_RISK')
    if (abort === '429') assert.deepStrictEqual(result.rateLimited, { retryAfterSeconds: 60 })
  })
  await t(`control — ${abort} after a same-host 302: redirect_policy keeps the abort's reason (SKIPPED/UNVERIFIED), as before`, async () => {
    const { result } = await run(abort, false)
    assert.deepStrictEqual(state(row(result, 'redirect_policy')), ['SKIPPED', 'UNVERIFIED', REASONS[abort]])
    assert.deepStrictEqual(state(row(result, 'auth_metadata')), ['SKIPPED', 'UNVERIFIED', REASONS[abort]])
  })
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
