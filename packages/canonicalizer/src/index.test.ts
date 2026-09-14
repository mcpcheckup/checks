import assert from 'node:assert'
import * as pkg from './index.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('index：公开 API 面')

t('导出 canonicalize / canonicalBytes / digest / CanonicalizationError', () => {
  assert.equal(typeof pkg.canonicalize, 'function')
  assert.equal(typeof pkg.canonicalBytes, 'function')
  assert.equal(typeof pkg.digest, 'function')
  assert.equal(typeof pkg.CanonicalizationError, 'function')
})

t('导出 CANONICALIZATION_PROFILE = "nfc-jcs/v1"', () => {
  assert.equal(pkg.CANONICALIZATION_PROFILE, 'nfc-jcs/v1')
})

t('导出 TOOLSET_PROJECTION_VERSION / projectToolset / projectSchemas', () => {
  assert.equal(pkg.TOOLSET_PROJECTION_VERSION, 'v1')
  assert.equal(typeof pkg.projectToolset, 'function')
  assert.equal(typeof pkg.projectSchemas, 'function')
})

t('从 index 导入也能正常工作（不只是内部模块）', () => {
  assert.equal(pkg.canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
