import assert from 'node:assert'
import { FIXTURE_CORPUS_VERSION, corpusDigest } from './version.ts'
import { FIXTURE_CORPUS } from './index.ts'
import type { Fixture } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('version：FIXTURE_CORPUS_VERSION')

// `await` 是必须的，不是风格：t 是 async。这一条今天靠"后面还有一个 await 会把微任务
// 排空"侥幸没出错，但那是位置带来的运气，不是保证——把它移到末尾或把回调改成 async，
// 它就会和另外两处一样变成静默通过（守卫设计原则 #6，round 18e）。
await t('是一个非空字符串', () => {
  assert.equal(typeof FIXTURE_CORPUS_VERSION, 'string')
  assert.ok(FIXTURE_CORPUS_VERSION.length > 0)
})

console.log('\nversion：corpusDigest')

await t('格式是 sha256:<64 hex>', async () => {
  const d = await corpusDigest(FIXTURE_CORPUS)
  assert.match(d, /^sha256:[0-9a-f]{64}$/)
})

await t('同一份对拍集，重复计算得到相同 digest（确定性）', async () => {
  const d1 = await corpusDigest(FIXTURE_CORPUS)
  const d2 = await corpusDigest(FIXTURE_CORPUS)
  assert.equal(d1, d2)
})

await t('反例：故意改动一条 fixture 的 expectedAssertions，digest 必须变化（证明它真的绑定内容，不是摆设）', async () => {
  const original = await corpusDigest(FIXTURE_CORPUS)
  const mutated: Fixture[] = FIXTURE_CORPUS.map((f, i) =>
    i === 0 ? { ...f, expectedAssertions: [...f.expectedAssertions, { check_id: 'reachability', execution_status: 'COMPLETED', assertion_status: 'VERIFIED' }] } : f,
  )
  const changed = await corpusDigest(mutated)
  assert.notEqual(changed, original, 'digest 在对拍集内容变化后必须跟着变——否则它不是真的绑定内容')
})

await t('反例：fixture 顺序打乱不应该改变 digest（内容相同、顺序不同应视为同一份对拍集）', async () => {
  const original = await corpusDigest(FIXTURE_CORPUS)
  const shuffled = [...FIXTURE_CORPUS].reverse()
  const reordered = await corpusDigest(shuffled)
  assert.equal(reordered, original, 'digest 不应该受 fixture 数组顺序影响')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
