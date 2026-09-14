import assert from 'node:assert'
import { CanonicalizationError } from './errors.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('CanonicalizationError')

t('是 Error 的实例', () => {
  const e = new CanonicalizationError('NON_FINITE_NUMBER', 'x')
  assert.ok(e instanceof Error)
  assert.ok(e instanceof CanonicalizationError)
})

t('携带 code', () => {
  const e = new CanonicalizationError('DUPLICATE_KEY_AFTER_NFC', 'dup key "a"')
  assert.equal(e.code, 'DUPLICATE_KEY_AFTER_NFC')
})

t('message 就是传入的第二个参数', () => {
  const e = new CanonicalizationError('LONE_SURROGATE', 'lone surrogate at index 3')
  assert.equal(e.message, 'lone surrogate at index 3')
})

t('name 是 CanonicalizationError（不是默认的 Error）', () => {
  const e = new CanonicalizationError('CIRCULAR_REFERENCE', 'x')
  assert.equal(e.name, 'CanonicalizationError')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
