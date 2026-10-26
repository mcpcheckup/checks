// suite-0160-remap.ts: the recorder and the remap the older differentials apply to a
// frozen result. suite-0160-differential.test.ts uses them against the real suites;
// these pin each rule on its own.
import assert from 'node:assert'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { latency0160Remap, recordSuite0160, suite0160Remap } from './suite-0160-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const row = (check_id: string, execution_status: Assertion['execution_status'], assertion_status: Assertion['assertion_status'], reason: Assertion['reason']): Assertion => ({
  check_id, docs_version: 'v0.3.0', execution_status, assertion_status, evidence_provenance: 'INDEPENDENTLY_OBSERVED', reason, unverified_reason: assertion_status === 'UNVERIFIED' ? reason : null,
})
const result = (...assertions: Assertion[]): ProbeResult => ({ assertions, driftEvents: [], dnsAnswerChangedObserved: false, protocolRevisionDeclared: null })
const NOT_RECORDED = row('latency_profile', 'SKIPPED', 'UNVERIFIED', { key: 'latency_not_recorded' })
const NONE = { crossHostRedirect: false, thrownClass: null }

console.log('suite0160Remap / latency0160Remap / recordSuite0160')

await t('a POST was answered: the result comes back equal, own keys in order, and a copy', () => {
  const old = result(row('reachability', 'COMPLETED', 'VERIFIED', null), NOT_RECORDED)
  const out = suite0160Remap(old, { ...NONE, postAnswered: true })
  assert.deepStrictEqual(out, old)
  assert.notEqual(out.assertions[1], old.assertions[1])
})

await t('no POST answered: latency_profile becomes latency_no_samples (reason and unverified_reason), no other row moves, the input is not mutated', () => {
  const old = result(row('reachability', 'ERROR', 'UNVERIFIED', { key: 'probe_budget_exhausted_requests', params: { maxRequests: 0 } }), NOT_RECORDED)
  const before = structuredClone(old)
  const out = latency0160Remap(old, false)
  assert.deepStrictEqual(out.assertions[0], old.assertions[0])
  assert.deepStrictEqual(out.assertions[1], { ...NOT_RECORDED, reason: { key: 'latency_no_samples' }, unverified_reason: { key: 'latency_no_samples' } })
  assert.deepStrictEqual(old, before)
})

await t('the remap refuses a latency_profile row that is not the 0.12.0–0.15.0 one, and a result without exactly one', () => {
  assert.throws(() => latency0160Remap(result(row('latency_profile', 'COMPLETED', 'VERIFIED', null)), true), /not the 0.15.0 row/)
  assert.throws(() => latency0160Remap(result(row('latency_profile', 'SKIPPED', 'UNVERIFIED', { key: 'latency_not_recorded', params: { x: 1 } })), true), /not the 0.15.0 row/)
  assert.throws(() => latency0160Remap(result(row('reachability', 'COMPLETED', 'VERIFIED', null)), true), /0 latency_profile rows/)
  assert.throws(() => latency0160Remap(result(NOT_RECORDED, NOT_RECORDED), true), /2 latency_profile rows/)
})

await t('suite0160Remap applies the suite 0.15.0 rules first (probe_aborted { message } becomes { error_class })', () => {
  const old = result(row('reachability', 'ERROR', 'UNVERIFIED', { key: 'probe_aborted', params: { message: 'boom' } }), NOT_RECORDED)
  const out = suite0160Remap(old, { crossHostRedirect: false, thrownClass: 'TypeError', postAnswered: false })
  assert.deepStrictEqual(out.assertions[0]!.reason, { key: 'probe_aborted', params: { error_class: 'TypeError' } })
  assert.equal(out.assertions[1]!.reason?.key, 'latency_no_samples')
})

await t('recordSuite0160: postAnswered only once a POST resolved with a Response (not a GET, not a POST that threw), and the 0.15.0 observations come along', async () => {
  const inner: FetchLike = async (_input, init) => {
    if (init?.body === 'throw') throw new RangeError('no answer')
    return new Response('{}', { status: 200 })
  }
  const rec = recordSuite0160(inner)
  await rec.fetchImpl('https://a.example.com/x', { method: 'GET' }, () => {})
  assert.deepStrictEqual(rec.observed(), { crossHostRedirect: false, thrownClass: null, postAnswered: false })
  await assert.rejects(rec.fetchImpl('https://a.example.com/mcp', { method: 'POST', body: 'throw' }, () => {}), RangeError)
  assert.deepStrictEqual(rec.observed(), { crossHostRedirect: false, thrownClass: 'RangeError', postAnswered: false })
  await rec.fetchImpl('https://a.example.com/mcp', { method: 'post', body: '{}' }, () => {})
  assert.deepStrictEqual(rec.observed(), { crossHostRedirect: false, thrownClass: 'RangeError', postAnswered: true })
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
