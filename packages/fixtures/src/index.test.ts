import assert from 'node:assert'
import * as pkg from './index.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('index：公开 API 面')

t('导出 FIXTURE_CORPUS，一个非空数组', () => {
  assert.ok(Array.isArray(pkg.FIXTURE_CORPUS))
  assert.ok(pkg.FIXTURE_CORPUS.length > 0)
})

t('导出 FIXTURE_CORPUS_VERSION / corpusDigest', () => {
  assert.equal(typeof pkg.FIXTURE_CORPUS_VERSION, 'string')
  assert.equal(typeof pkg.corpusDigest, 'function')
})

t('每条具名导出的 fixture 也能在 FIXTURE_CORPUS 里按 id 找到（两条路径必须一致）', () => {
  const ids = new Set(pkg.FIXTURE_CORPUS.map((f) => f.id))
  assert.ok(ids.has(pkg.modernBaselineClean.id))
  assert.ok(ids.has(pkg.responseExceedsBudget.id))
  assert.ok(ids.has(pkg.toolsetDriftRun1.id))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
