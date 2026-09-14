import assert from 'node:assert'
import { CHECKS_REGISTRY, isKnownCheckId, getCheckIds } from './registry.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('registry: checks.json 是单一事实来源')

t('CHECKS_REGISTRY 加载出真实内容（suite_id / checks 数组）', () => {
  assert.equal(CHECKS_REGISTRY.suite_id, 'remote-baseline-v0.1')
  assert.ok(Array.isArray(CHECKS_REGISTRY.checks))
  assert.ok(CHECKS_REGISTRY.checks.length >= 15)
})

t('getCheckIds() 返回全部 check_id，且包含已知的几个', () => {
  const ids = getCheckIds()
  for (const id of ['reachability', 'protocol_revision', 'discovery_handshake', 'tools_list', 'tool_description_hygiene', 'toolset_fingerprint', 'schema_fingerprint']) {
    assert.ok(ids.includes(id), `缺少 ${id}`)
  }
})

t('isKnownCheckId：真实存在的 check_id 返回 true', () => {
  assert.equal(isKnownCheckId('auth_metadata'), true)
})

t('isKnownCheckId：拼写错误的 check_id 返回 false（反例，防止 fixtures 用错字的 check_id 静默通过）', () => {
  assert.equal(isKnownCheckId('toolset_fingreprint'), false)
  assert.equal(isKnownCheckId('not_a_real_check'), false)
})

t('每个 check 条目的 _en 字段与 _zh 字段一一对称——O-19：不允许漏译', () => {
  for (const def of CHECKS_REGISTRY.checks) {
    assert.equal(typeof def.predicate_en, 'string', `${def.check_id}: predicate_en 缺失或不是 string`)
    assert.ok(def.predicate_en.length > 0, `${def.check_id}: predicate_en 是空字符串`)
    assert.equal(typeof def.explain.what_en, 'string', `${def.check_id}: explain.what_en 缺失`)
    assert.ok(def.explain.what_en.length > 0, `${def.check_id}: explain.what_en 是空字符串`)
    assert.equal(typeof def.explain.how_en, 'string', `${def.check_id}: explain.how_en 缺失`)
    assert.ok(def.explain.how_en.length > 0, `${def.check_id}: explain.how_en 是空字符串`)
    assert.equal(typeof def.explain.cannot_en, 'string', `${def.check_id}: explain.cannot_en 缺失`)
    assert.ok(def.explain.cannot_en.length > 0, `${def.check_id}: explain.cannot_en 是空字符串`)
    if (def.no_baseline_reason_zh !== undefined) {
      assert.equal(typeof def.no_baseline_reason_en, 'string', `${def.check_id}: 有 no_baseline_reason_zh 但缺 no_baseline_reason_en`)
    }
    if (def.p0_note_zh !== undefined) {
      assert.equal(typeof def.p0_note_en, 'string', `${def.check_id}: 有 p0_note_zh 但缺 p0_note_en`)
    }
  }
})

t('每个 group 的 description_en 与 description_zh 都存在', () => {
  for (const g of CHECKS_REGISTRY.groups) {
    assert.equal(typeof g.description_en, 'string', `${g.key}: description_en 缺失`)
    assert.ok(g.description_en.length > 0, `${g.key}: description_en 是空字符串`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
