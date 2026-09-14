import assert from 'node:assert'
import { assertRateLimitAllowed } from './rate-limit.ts'
import { RateLimited } from './errors.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('assertRateLimitAllowed: 默认拒绝，不是默认放行')

t('allowed=true 的决定：不抛错', () => {
  assertRateLimitAllowed({ allowed: true, scope: ['caller_ip'] })
})

t('allowed=false 的决定：抛 RateLimited，带上调用方给的 reason', () => {
  assert.throws(
    () => assertRateLimitAllowed({ allowed: false, scope: ['target_host'], reason: '目标 host 60 秒内已探测过 3 次' }),
    (e: unknown) => e instanceof RateLimited && e.message.includes('60 秒内已探测过 3 次'),
  )
})

t('没有提供决定（undefined）：抛 RateLimited——默认行为是拒绝，不是放行', () => {
  assert.throws(() => assertRateLimitAllowed(undefined), RateLimited)
})

t('提供 null：同样抛 RateLimited', () => {
  assert.throws(() => assertRateLimitAllowed(null), RateLimited)
})

t('决定对象畸形（缺 allowed 字段）：按拒绝处理，不能因为"看起来像通过"就放行', () => {
  assert.throws(() => assertRateLimitAllowed({ scope: ['global_concurrency'] } as never), RateLimited)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
