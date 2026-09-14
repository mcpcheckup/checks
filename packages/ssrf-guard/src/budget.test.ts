import assert from 'node:assert'
import { DEFAULT_PROBE_BUDGET, createProbeBudget } from './budget.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('budget: 默认值')
t('DEFAULT_PROBE_BUDGET 与规格一致', () => {
  assert.deepEqual(DEFAULT_PROBE_BUDGET, {
    maxRedirects: 3,
    maxDurationMs: 10000,
    maxBodyBytes: 2097152,
    maxRequests: 8,
  })
})

console.log('\nbudget: createProbeBudget 两档同值（T6.9-F，用户 2026-09-09 拍板取消减半）')
// 这三条钉的是新的不变式：createProbeBudget 目前不按 claimed 改动任何字段。
// 旧断言是 claimed=false -> maxRequests 减半为 4，它变红是这次改动的直接证据，
// 不是需要绕开的噪声：4 连一轮 legacy 协议（最少 5 次请求）都跑不完。
t('claimed=true 时逐字段等于 DEFAULT_PROBE_BUDGET', () => {
  assert.deepEqual(createProbeBudget({ claimed: true }), DEFAULT_PROBE_BUDGET)
})
t('claimed=false 时逐字段等于 DEFAULT_PROBE_BUDGET（不再减半）', () => {
  assert.deepEqual(createProbeBudget({ claimed: false }), DEFAULT_PROBE_BUDGET)
})
t('两档逐字段相等——claimed 目前不改动任何一个字段', () => {
  assert.deepEqual(createProbeBudget({ claimed: false }), createProbeBudget({ claimed: true }))
})
t('返回的是新对象，不是 DEFAULT_PROBE_BUDGET 本身（调用方改一份不得污染另一份）', () => {
  const a = createProbeBudget({ claimed: true })
  assert.notEqual(a, DEFAULT_PROBE_BUDGET)
  assert.notEqual(a, createProbeBudget({ claimed: true }))
})
t('maxRedirects / maxDurationMs / maxBodyBytes 三个 SSRF 相关字段一字未动', () => {
  for (const claimed of [true, false]) {
    const b = createProbeBudget({ claimed })
    assert.equal(b.maxRedirects, 3, `claimed=${claimed}`)
    assert.equal(b.maxDurationMs, 10000, `claimed=${claimed}`)
    assert.equal(b.maxBodyBytes, 2097152, `claimed=${claimed}`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
