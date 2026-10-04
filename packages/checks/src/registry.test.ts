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

t('failure_status 为 null 的 check：predicate / what / how 不得声称会记 OBSERVED_RISK 或 FAILED（说明文字不许承诺代码没有的结论）', () => {
  for (const def of CHECKS_REGISTRY.checks) {
    if (def.failure_status !== null) continue
    for (const k of ['predicate_zh', 'predicate_en'] as const) assert.doesNotMatch(def[k], /OBSERVED_RISK|FAILED/, `${def.check_id}.${k}`)
    for (const k of ['what_zh', 'what_en', 'how_zh', 'how_en'] as const) assert.doesNotMatch(def.explain[k], /OBSERVED_RISK|FAILED/, `${def.check_id}.explain.${k}`)
  }
})

t('transport_type：说明如实——不与声明的传输比对，也不声称握手成功；握手结果与 VERIFIED 无关（那是 discovery_handshake 的判定）', () => {
  const def = CHECKS_REGISTRY.checks.find((c) => c.check_id === 'transport_type')!
  assert.equal(def.failure_status, null)
  // predicate / what / how 都不得说「握手完成」（probe.ts 在握手失败、被凭据门控时同样记 VERIFIED），也不得承诺比对。
  for (const text of [def.predicate_zh, def.predicate_en, def.explain.what_zh, def.explain.what_en, def.explain.how_zh, def.explain.how_en]) {
    assert.doesNotMatch(text, /handshake (completed|completes|is completed)|握手[^，。；（]{0,8}完成/i, `transport_type 声称握手完成：${text}`)
  }
  for (const text of [def.predicate_zh, def.predicate_en, def.explain.what_zh, def.explain.what_en]) {
    assert.doesNotMatch(text, /matches (the )?declar|compared against|符合声明|做比对/i, `transport_type 仍承诺比对：${text}`)
  }
  assert.match(def.explain.how_en, /VERIFIED/)
  assert.match(def.explain.how_en, /whether or not the handshake itself succeeds/)
  assert.match(def.explain.how_en, /not compared against any transport the server declares/)
  assert.match(def.explain.how_zh, /VERIFIED/)
  assert.match(def.explain.how_zh, /无论握手本身是否成功/)
  assert.match(def.explain.how_zh, /不会与 server 声明的传输做比对/)
})

// R8 / R9 (approved copy): the four `how` strings pinned verbatim. Each states what probe.ts does on every branch —
// VERIFIED once performHandshake returns (whatever the handshake's own verdict), and on any stop before that the
// catch block writes reachability ERROR/UNVERIFIED and cascades the rest SKIPPED/UNVERIFIED with the abort's reason.
const how = (id: string) => CHECKS_REGISTRY.checks.find((c) => c.check_id === id)!.explain

t('transport_type.how_en 与签字原文逐字相同', () => {
  assert.equal(how('transport_type').how_en, `Recorded as VERIFIED when our handshake exchange over that transport finishes with an HTTP response from the endpoint, whether or not the handshake itself succeeds — that is discovery_handshake's verdict. If the probe stops before the exchange finishes — for example because the endpoint asks us to back off, a response is over the probe's size limit, or one of the probe's budgets runs out — this check is not recorded as VERIFIED, and the reason is recorded with it. It is not compared against any transport the server declares.`)
})

t('transport_type.how_zh 与签字原文逐字相同', () => {
  assert.equal(how('transport_type').how_zh, `我们经该传输的握手交换以端点的 HTTP 回应结束时，记 VERIFIED，无论握手本身是否成功（那由 discovery_handshake 判定）。如果探测在交换结束前停下——例如端点要求我们稍后再来、某个回应超出探测的大小上限、或探测的某项预算用尽——本项不记 VERIFIED，并同时记下原因。不会与 server 声明的传输做比对。`)
})

t('reachability.how_en 与签字原文逐字相同', () => {
  assert.equal(how('reachability').how_en, `Recorded as VERIFIED when our handshake exchange finishes with an HTTP response from the endpoint, whatever its status. If the probe stops before the exchange finishes — for example because the endpoint asks us to back off (429, or 503 with Retry-After), a response is over the size limit, the connection fails, or one of the probe's budgets runs out — this check is UNVERIFIED, with that reason, even if the endpoint had already answered an earlier request. The whole probe, handshake included, runs under hard caps: 8 requests and 10s in total, and 2MB per response.`)
})

t('reachability.how_zh 与签字原文逐字相同', () => {
  assert.equal(how('reachability').how_zh, `我们的握手交换以 endpoint 的 HTTP 回应结束时（任何状态码都算），记 VERIFIED。如果探测在交换结束前停下——例如 endpoint 要求我们稍后再来（429，或带 Retry-After 的 503）、某个回应超出大小上限、连接出错、或探测的某项预算用尽——本项记 UNVERIFIED 并附上原因，即使 endpoint 已经答复过之前的请求。整次探测（含握手）都在硬上限内进行：总共 8 个请求、10 s，每个回应 2 MB。`)
})

t('reachability.how 里写的预算数字等于 checks.json 的 budget 字段（文案不许和合同数字漂移）', () => {
  const b = CHECKS_REGISTRY.budget
  assert.equal(b.max_requests, 8)
  assert.equal(b.max_duration_ms, 10_000)
  assert.equal(b.max_body_bytes, 2 * 1024 * 1024)
})

t('no_baseline_reason：两项基线检查的「没有基线」原因逐字固定，且不把「未认领」当作原因（已认领但未确认基线的 target 也走这条）', () => {
  const withReason = CHECKS_REGISTRY.checks.filter((c) => c.no_baseline_reason_en !== undefined || c.no_baseline_reason_zh !== undefined)
  assert.deepEqual(withReason.map((c) => c.check_id).sort(), ['schema_unchanged_vs_approved', 'toolset_unchanged_vs_approved'])
  for (const c of withReason) {
    assert.equal(c.no_baseline_reason_en, 'No approved baseline exists for this target.', c.check_id)
    assert.equal(c.no_baseline_reason_zh, '该 target 没有已批准基线', c.check_id)
    assert.doesNotMatch(`${c.no_baseline_reason_en} ${c.no_baseline_reason_zh}`, /unclaimed|未认领|未被认领/i, c.check_id)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
