// suite-0150-remap.ts: the transcript recorder, the paged-run test and the remap the
// older differentials apply to a frozen result. suite-0150-differential.test.ts uses
// them against the real suites; these pin each rule on its own.
import assert from 'node:assert'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { pagedToolsList, recordSuite0150, suite0150Remap } from './suite-0150-remap.ts'
import { recordRequest } from './suite-0130-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const row = (check_id: string, execution_status: Assertion['execution_status'], assertion_status: Assertion['assertion_status'], reason: Assertion['reason']): Assertion => ({
  check_id, docs_version: 'v0.1.0', execution_status, assertion_status, evidence_provenance: 'INDEPENDENTLY_OBSERVED', reason, unverified_reason: assertion_status === 'UNVERIFIED' ? reason : null,
})
const result = (...assertions: Assertion[]): ProbeResult => ({ assertions, driftEvents: [], dnsAnswerChangedObserved: false, protocolRevisionDeclared: null })
const NONE = { crossHostRedirect: false, thrownClass: null }

console.log('suite0150Remap / recordSuite0150 / pagedToolsList')

await t('nothing seen: the result comes back equal, own keys in order, and a copy', () => {
  const old = result(row('redirect_policy', 'SKIPPED', 'UNVERIFIED', { key: 'probe_cascade_incomplete' }))
  const out = suite0150Remap(old, NONE)
  assert.deepStrictEqual(out, old)
  assert.notEqual(out.assertions[0], old.assertions[0])
})

await t('a cross-host redirect before an abort: redirect_policy\'s cascade row becomes COMPLETED/OBSERVED_RISK redirect_cross_host_observed, no other row moves', () => {
  const old = result(
    row('reachability', 'ERROR', 'UNVERIFIED', { key: 'probe_budget_exceeded', params: { kind: 'MAX_REDIRECTS' } }),
    row('redirect_policy', 'SKIPPED', 'UNVERIFIED', { key: 'probe_cascade_incomplete' }),
  )
  const out = suite0150Remap(old, { crossHostRedirect: true, thrownClass: null })
  assert.deepStrictEqual(out.assertions[0], old.assertions[0])
  assert.deepStrictEqual(out.assertions[1], { ...old.assertions[1], execution_status: 'COMPLETED', assertion_status: 'OBSERVED_RISK', reason: { key: 'redirect_cross_host_observed' }, unverified_reason: null })
})

await t('a cross-host redirect on a run that finished (already OBSERVED_RISK): unchanged; on a row that is neither, the remap refuses', () => {
  const done = result(row('redirect_policy', 'COMPLETED', 'OBSERVED_RISK', { key: 'redirect_cross_host_observed' }))
  assert.deepStrictEqual(suite0150Remap(done, { crossHostRedirect: true, thrownClass: null }), done)
  assert.throws(() => suite0150Remap(result(row('redirect_policy', 'COMPLETED', 'VERIFIED', null)), { crossHostRedirect: true, thrownClass: null }), /not an abort's cascade/)
})

await t('probe_aborted { message } becomes { error_class } with the thrown class, in reason and unverified_reason; refused when the transport threw nothing', () => {
  const old = result(row('reachability', 'ERROR', 'UNVERIFIED', { key: 'probe_aborted', params: { message: 'boom: secret detail' } }))
  const out = suite0150Remap(old, { crossHostRedirect: false, thrownClass: 'TypeError' })
  assert.deepStrictEqual(out.assertions[0]!.reason, { key: 'probe_aborted', params: { error_class: 'TypeError' } })
  assert.deepStrictEqual(out.assertions[0]!.unverified_reason, { key: 'probe_aborted', params: { error_class: 'TypeError' } })
  assert.ok(!JSON.stringify(out).includes('secret detail'))
  assert.throws(() => suite0150Remap(old, NONE), /transport threw nothing/)
})

await t('pagedToolsList: true only for a tools/list call whose params carry a cursor (also an empty one)', () => {
  const req = (body: unknown) => recordRequest('https://notes-mcp.example.com/mcp', { method: 'POST', body: JSON.stringify(body) })
  assert.equal(pagedToolsList([req({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })]), false)
  assert.equal(pagedToolsList([req({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { cursor: 'c1' } })]), false)
  assert.equal(pagedToolsList([recordRequest('https://notes-mcp.example.com/.well-known/x', { method: 'GET' })]), false)
  assert.equal(pagedToolsList([req({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: { cursor: '' } })]), true)
})

await t('recordSuite0150: a 3xx to another host is recorded on its chain (also the last hop, also relative Locations staying put are not), and a thrown class is kept', async () => {
  const answers: Record<string, () => Response> = {
    'https://a.example.com/start': () => new Response('', { status: 302, headers: { location: '/next' } }),
    'https://a.example.com/next': () => new Response('', { status: 302, headers: { location: 'https://b.example.com/x' } }),
  }
  const inner: FetchLike = async (input) => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const answer = answers[href]
    if (!answer) throw new RangeError('no answer')
    return answer()
  }
  const same = recordSuite0150(inner)
  await same.fetchImpl('https://a.example.com/start', { method: 'GET' }, () => {})
  assert.deepStrictEqual(same.observed(), { crossHostRedirect: false, thrownClass: null })
  await same.fetchImpl('https://a.example.com/next', { method: 'GET' }, () => {})
  assert.deepStrictEqual(same.observed(), { crossHostRedirect: true, thrownClass: null })
  await assert.rejects(same.fetchImpl('https://b.example.com/x', { method: 'GET' }, () => {}), RangeError)
  assert.deepStrictEqual(same.observed(), { crossHostRedirect: true, thrownClass: 'RangeError' })
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
