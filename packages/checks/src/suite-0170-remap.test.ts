// suite-0170-remap.ts: the recorder and the remap the older differentials apply to a
// frozen result. suite-0170-differential.test.ts uses them against the real suites;
// these pin each rule on its own.
import assert from 'node:assert'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { hygiene0170Remap, recordSuite0170, suite0170Remap } from './suite-0170-remap.ts'
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
const RISK = row('tool_description_hygiene', 'COMPLETED', 'OBSERVED_RISK', { key: 'hygiene_risk_detected', params: { hitCount: 1, totalCount: 3 } })
const SEEN = { crossHostRedirect: false, thrownClass: null, postAnswered: true }

console.log('suite0170Remap / hygiene0170Remap / recordSuite0170')

await t('the hygiene row (OBSERVED_RISK, VERIFIED or UNVERIFIED) comes back equal, own keys in order, and a copy; the input is not mutated', () => {
  for (const hygiene of [RISK, row('tool_description_hygiene', 'COMPLETED', 'VERIFIED', null), row('tool_description_hygiene', 'SKIPPED', 'UNVERIFIED', { key: 'tools_list_unavailable' })]) {
    const old = result(row('reachability', 'COMPLETED', 'VERIFIED', null), hygiene, NOT_RECORDED)
    const before = structuredClone(old)
    const out = hygiene0170Remap(old)
    assert.deepStrictEqual(out, old)
    assert.deepStrictEqual(JSON.stringify(out), JSON.stringify(old))
    assert.notEqual(out.assertions[1], old.assertions[1])
    assert.deepStrictEqual(old, before)
  }
})

await t('the remap refuses a result without exactly one tool_description_hygiene row', () => {
  assert.throws(() => hygiene0170Remap(result(row('reachability', 'COMPLETED', 'VERIFIED', null))), /0 tool_description_hygiene rows/)
  assert.throws(() => hygiene0170Remap(result(RISK, RISK)), /2 tool_description_hygiene rows/)
})

await t('suite0170Remap applies the suite 0.16.0 rules first (no POST answered: latency_no_samples)', () => {
  const old = result(RISK, NOT_RECORDED)
  const out = suite0170Remap(old, { ...SEEN, postAnswered: false })
  assert.deepStrictEqual(out.assertions[0], RISK)
  assert.equal(out.assertions[1]!.reason?.key, 'latency_no_samples')
  assert.deepStrictEqual(suite0170Remap(old, SEEN), old)
})

await t('recordSuite0170 records what recordSuite0160 does', async () => {
  const inner: FetchLike = async () => new Response('{}', { status: 200 })
  const rec = recordSuite0170(inner)
  await rec.fetchImpl('https://a.example.com/x', { method: 'GET' }, () => {})
  assert.deepStrictEqual(rec.observed(), { crossHostRedirect: false, thrownClass: null, postAnswered: false })
  await rec.fetchImpl('https://a.example.com/mcp', { method: 'POST', body: '{}' }, () => {})
  assert.deepStrictEqual(rec.observed(), { crossHostRedirect: false, thrownClass: null, postAnswered: true })
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
