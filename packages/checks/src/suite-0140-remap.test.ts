// suite-0140-remap.ts's withoutAuthObservation: what the older differentials
// compare once the live result's one new key is set aside.
import assert from 'node:assert'
import { withoutAuthObservation } from './suite-0140-remap.ts'
import type { ProbeResult } from './types.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const base: ProbeResult = { assertions: [], driftEvents: [], dnsAnswerChangedObserved: false, protocolRevisionDeclared: null, probeOfferedRevision: '2025-11-25' }
const observation = { scheme: 'bearer', param_names: ['realm'], param_names_truncated: false, resource_metadata_url: null, resource_metadata_url_withheld: false, resource_metadata_body_digest: null }

console.log('withoutAuthObservation')

t('removes authObservation and nothing else, every other own key in its order', () => {
  const out = withoutAuthObservation({ ...base, authObservation: observation })
  assert.deepStrictEqual(Object.keys(out), Object.keys(base))
  assert.deepStrictEqual(out, base)
})

t('a result without authObservation comes back equal, own keys in the same order', () => {
  const out = withoutAuthObservation(base)
  assert.deepStrictEqual(Object.keys(out), Object.keys(base))
  assert.deepStrictEqual(out, base)
})

t('the input is not changed, and the copy shares nothing with it', () => {
  const input: ProbeResult = { ...base, assertions: [], authObservation: observation }
  const out = withoutAuthObservation(input)
  assert.equal(input.authObservation, observation)
  assert.notEqual(out.assertions, input.assertions)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
