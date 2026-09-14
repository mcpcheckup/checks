import assert from 'node:assert'
import * as pkg from './index.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('index：公开 API 面')

t('导出 runHygieneCheck / checkTool', () => {
  assert.equal(typeof pkg.runHygieneCheck, 'function')
  assert.equal(typeof pkg.checkTool, 'function')
})

t('导出 CHECKS_REGISTRY / getCheckIds / isKnownCheckId / getCheckDefinition', () => {
  assert.equal(pkg.CHECKS_REGISTRY.suite_id, 'remote-baseline-v0.1')
  assert.equal(typeof pkg.getCheckIds, 'function')
  assert.equal(typeof pkg.isKnownCheckId, 'function')
  assert.equal(typeof pkg.getCheckDefinition, 'function')
})

t('导出 runProbe', () => {
  assert.equal(typeof pkg.runProbe, 'function')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
