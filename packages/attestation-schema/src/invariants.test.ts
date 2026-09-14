import assert from 'node:assert'
import { assertUnverifiedHasReason, AssertionInvariantError } from './invariants.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('invariants: assertUnverifiedHasReason（第三层防护——不依赖 schema 或数据库也能捕捉这条规则）')

t('UNVERIFIED 且 unverified_reason 非空 → 不抛错', () => {
  assert.doesNotThrow(() =>
    assertUnverifiedHasReason({ assertion_status: 'UNVERIFIED', reason: null, unverified_reason: { key: 'no_credentials_to_observe_with' } }),
  )
})

t('UNVERIFIED 且只有 reason 非空（unverified_reason 为 null）→ 不抛错（reason 是合法兜底）', () => {
  assert.doesNotThrow(() =>
    assertUnverifiedHasReason({ assertion_status: 'UNVERIFIED', reason: { key: 'fallback_reason' }, unverified_reason: null }),
  )
})

t('UNVERIFIED 且两者都是 null → 抛 AssertionInvariantError（反例）', () => {
  assert.throws(
    () => assertUnverifiedHasReason({ assertion_status: 'UNVERIFIED', reason: null, unverified_reason: null }),
    (e: unknown) => {
      assert.ok(e instanceof AssertionInvariantError)
      assert.equal(e.code, 'UNVERIFIED_NEEDS_REASON')
      return true
    },
  )
})

t('UNVERIFIED 且 reason 是 {key: ""}（非 null，但 key 是空字符串）→ 抛 AssertionInvariantError（这一层不能只信任"非 null"就够了——是这一层自己的职责，不能依赖 schema 的 pattern 校验替它把关）', () => {
  assert.throws(
    () => assertUnverifiedHasReason({ assertion_status: 'UNVERIFIED', reason: { key: '' }, unverified_reason: null }),
    (e: unknown) => {
      assert.ok(e instanceof AssertionInvariantError)
      assert.equal(e.code, 'UNVERIFIED_NEEDS_REASON')
      return true
    },
  )
})

t('UNVERIFIED 且 unverified_reason 是 {key: ""}、reason 是 {key: "valid"} → 不抛错（空 key 的 unverified_reason 不算数，但 reason 兜底非空）', () => {
  assert.doesNotThrow(() =>
    assertUnverifiedHasReason({ assertion_status: 'UNVERIFIED', reason: { key: 'fallback_reason' }, unverified_reason: { key: '' } }),
  )
})

t('VERIFIED 且两者都是 null → 不抛错（约束只针对 UNVERIFIED）', () => {
  assert.doesNotThrow(() => assertUnverifiedHasReason({ assertion_status: 'VERIFIED', reason: null, unverified_reason: null }))
})

t('FAILED 且两者都是 null → 不抛错', () => {
  assert.doesNotThrow(() => assertUnverifiedHasReason({ assertion_status: 'FAILED', reason: null, unverified_reason: null }))
})

t('OBSERVED_RISK 且两者都是 null → 不抛错', () => {
  assert.doesNotThrow(() => assertUnverifiedHasReason({ assertion_status: 'OBSERVED_RISK', reason: null, unverified_reason: null }))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
