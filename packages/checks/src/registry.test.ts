import assert from 'node:assert'
import { CHECKS_REGISTRY, isKnownCheckId, getCheckIds } from './registry.ts'
import type { ChecksRegistry } from './registry.ts'
import frozen0140Checks from './frozen/suite-0.14.0/checks.json' with { type: 'json' }

/** Registry 0.13.0, the one suite 0.14.0 shipped with. */
const FROZEN_0130_REGISTRY: Pick<ChecksRegistry, 'registry_version' | 'checks'> = frozen0140Checks

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

// Approved copy: the four `how` strings pinned verbatim. Each states what probe.ts does on every branch —
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
  assert.equal(how('reachability').how_en, `Recorded as VERIFIED when our handshake exchange finishes with an HTTP response from the endpoint, whatever its status. If the probe stops before the exchange finishes — for example because the endpoint asks us to back off (429, or 503 with Retry-After), a response is over the size limit, the connection fails, or one of the probe's budgets runs out — this check is UNVERIFIED, with that reason, even if the endpoint had already answered an earlier request. The whole probe, handshake included, runs under hard caps: 8 requests and 10s in total, and 2MB per response. Reading the further pages of a long tool list adds at most 9 requests to the 8; they share the same 10s and the 2MB limit per response.`)
})

t('reachability.how_zh 与签字原文逐字相同', () => {
  assert.equal(how('reachability').how_zh, `我们的握手交换以 endpoint 的 HTTP 回应结束时（任何状态码都算），记 VERIFIED。如果探测在交换结束前停下——例如 endpoint 要求我们稍后再来（429，或带 Retry-After 的 503）、某个回应超出大小上限、连接出错、或探测的某项预算用尽——本项记 UNVERIFIED 并附上原因，即使 endpoint 已经答复过之前的请求。整次探测（含握手）都在硬上限内进行：总共 8 个请求、10 s，每个回应 2 MB。读取较长工具列表的后续页，最多在 8 个请求之外再加 9 个，同样受 10 s 和每个回应 2 MB 的限制。`)
})

t('reachability.how 里写的预算数字等于 checks.json 的 budget 字段（文案不许和合同数字漂移）', () => {
  const b = CHECKS_REGISTRY.budget
  assert.equal(b.max_requests, 8)
  assert.equal(b.max_duration_ms, 10_000)
  assert.equal(b.max_body_bytes, 2 * 1024 * 1024)
  // "at most 9 requests" on top of the 8: every page after the first.
  assert.equal(b.max_tools_list_pages, 10)
  assert.equal(b.max_tools_list_pages - 1, 9)
})

// Suite 0.15.0 (registry 0.14.0): seven more checks' how text gains exactly one
// sentence, about reading every tools/list page and what an incomplete list
// records. Each text is the registry 0.13.0 text (frozen/suite-0.14.0/checks.json)
// plus that sentence, verbatim, so nothing else in it moved.
const HOW_APPENDED_0140: Record<string, { en: string; zh: string }> = {
  tools_list: {
    en: ' When the server splits its list into pages, we follow nextCursor and read every page, up to 10 pages or 5,000 tools in one run. Pages after the first do not count toward the 8-request limit; the 10s time limit and the 2MB limit per response still apply. If the list is longer than that, or a later page runs out of the time limit, goes over the 2MB limit (in its request or its response) or is not a readable tool list, we stop reading pages there: this check is still judged on the first page, and nothing that depends on the whole list is recorded as VERIFIED (see each check). Any other failure on a later page (for example the server asking us to back off, or a failed connection) ends the run, as it would on any other request.',
    zh: '服务器把列表分页时，我们沿 nextCursor 读取每一页，一次 run 最多读 10 页或 5,000 个工具。第一页之后的页不计入 8 个请求的上限；10 s 的时间上限和每个回应 2 MB 的上限照样适用。列表超出这个范围，或后面某一页超时、请求或回应超过 2 MB、或读不出工具列表时，我们就停在那里不再翻页：本项仍按第一页判定，依赖完整列表的结论都不记为 VERIFIED（见各项检查）。后面某一页遇到其他失败（例如服务器要求我们稍后再来，或连接失败）时，和其他请求一样，本次 run 就此结束。',
  },
  toolset_fingerprint: {
    en: ' It is computed over every page of the tool list. If we could not read the whole list (see tools_list), no fingerprint is computed and this check is UNVERIFIED.',
    zh: '指纹按工具列表的全部页计算；没能读完整份列表时（见 tools_list）不计算指纹，本项记 UNVERIFIED。',
  },
  schema_fingerprint: {
    en: ' It is computed over every page of the tool list, and is UNVERIFIED when we could not read the whole list.',
    zh: '按工具列表的全部页计算；没能读完整份列表时记 UNVERIFIED。',
  },
  tool_description_hygiene: {
    en: ' We read every page of the tool list. If we could not read the whole list, a hit in the tools we did read is still OBSERVED_RISK, but no hit is UNVERIFIED rather than VERIFIED: the tools we did not see were not checked.',
    zh: '我们读取工具列表的全部页。没能读完整份列表时，已读到的工具里有命中仍记 OBSERVED_RISK；没有命中则记 UNVERIFIED 而不是 VERIFIED，因为没读到的工具没有检查过。',
  },
  toolset_unchanged_vs_approved: {
    en: ' If we could not read the whole tool list, there is nothing to compare and this check is UNVERIFIED.',
    zh: '没能读完整份工具列表时没有可比对的内容，记 UNVERIFIED。',
  },
  schema_unchanged_vs_approved: {
    en: ' If we could not read the whole tool list, it is UNVERIFIED.',
    zh: '没能读完整份工具列表时记 UNVERIFIED。',
  },
  error_taxonomy: {
    en: ' If we could not read the whole tool list (see tools_list), we do not send this call, since the name we would call could belong to a tool we did not see; this check is then UNVERIFIED with reason probe_tool_name_unverifiable, or probe_tool_name_collision when a page we did read lists that name.',
    zh: '没能读完整份工具列表时（见 tools_list），我们不发这次调用，因为要调用的名字可能属于一个没读到的工具；本项记 UNVERIFIED，原因 probe_tool_name_unverifiable；若已读到的某一页列出了这个名字，原因则是 probe_tool_name_collision。',
  },
}

t('suite 0.15.0：七项检查的 how_en / how_zh = registry 0.13.0 的原文 + 恰好一句（逐字固定），其余 explain / predicate 文字一字不动', () => {
  for (const [id, added] of Object.entries(HOW_APPENDED_0140)) {
    const before = FROZEN_0130_REGISTRY.checks.find((c) => c.check_id === id)!
    const now = CHECKS_REGISTRY.checks.find((c) => c.check_id === id)!
    assert.equal(now.explain.how_en, before.explain.how_en + added.en, `${id}.how_en`)
    assert.equal(now.explain.how_zh, before.explain.how_zh + added.zh, `${id}.how_zh`)
    for (const field of ['what_en', 'what_zh', 'cannot_en', 'cannot_zh'] as const) assert.equal(now.explain[field], before.explain[field], `${id}.${field}`)
    assert.equal(now.predicate_en, before.predicate_en, `${id}.predicate_en`)
    assert.equal(now.predicate_zh, before.predicate_zh, `${id}.predicate_zh`)
  }
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

// redirect_policy (registry 0.10.0): only auth.ts's metadata GET follows redirects
// (wire.ts sendRequest, `method === 'GET'`, up to budget.maxRedirects); a protocol POST's
// 3xx is that call's terminal response, with the cross-host Location still recorded.
// Suite 0.15.0 (registry 0.14.0, TODO 779 / 797): plus one sentence — a cross-host
// redirect seen before an abort is still recorded (probe.ts's catch).
t('redirect_policy.how_en 与签字原文逐字相同', () => {
  assert.equal(how('redirect_policy').how_en, `A cross-host redirect is recorded as OBSERVED_RISK. Only the GET for authorization metadata follows redirects, for at most 3 hops; a protocol POST that gets a redirect is recorded, not followed. A cross-host redirect is recorded even when the run stops afterwards, for example at the hop limit, at another host we do not connect to, or because the server asked us to back off.`)
})

t('redirect_policy.how_zh 与签字原文逐字相同', () => {
  assert.equal(how('redirect_policy').how_zh, `跨主机重定向记 OBSERVED_RISK。只有读取授权元数据的 GET 会跟随重定向，最多 3 跳；协议 POST 收到重定向时只记录，不跟随。即使 run 在这之后停止（例如超过跳数上限、遇到我们不连接的另一个主机，或服务器要求我们稍后再来），已观察到的跨主机重定向也照样记录。`)
})

t('redirect_policy.how 不再写「所有请求都跟随」的旧说法，写的跳数等于 checks.json 的 budget.max_redirects', () => {
  const h = how('redirect_policy')
  assert.doesNotMatch(h.how_en, /Followed for at most/)
  assert.doesNotMatch(h.how_zh, /最多跟 3 跳。/)
  assert.equal(CHECKS_REGISTRY.budget.max_redirects, 3)
})

// docs_version enters every signed assertion (probe.ts docsVersionFor), and moves when
// that one check changes (README). Registry 0.14.0 (suite 0.15.0) moves the ten checks
// whose conclusions or how text changed: reachability (how: the further tools/list pages),
// tools_list, the two fingerprints, tool_description_hygiene, the two baseline checks and
// error_taxonomy (an incomplete tool list), redirect_policy (recorded before an abort), and
// auth_metadata (the reserved-name call now goes out on a complete list of several pages,
// where suite 0.14.0 withheld it on a first-page nextCursor).
// Every other value is registry 0.13.0's (frozen/suite-0.14.0/checks.json). A later bump of
// any check updates this table in the same change, deliberately.
t('docs_version：registry 0.14.0 动了十项检查（各升一个次版本），其余 5 项与 registry 0.13.0 的 checks.json 逐条相同', () => {
  const previousRegistry = Object.fromEntries(FROZEN_0130_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0130_REGISTRY.registry_version, '0.13.0')
  assert.equal(CHECKS_REGISTRY.registry_version, '0.14.0')
  const now = Object.fromEntries(CHECKS_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(CHECKS_REGISTRY.checks.length, Object.keys(now).length, 'check_id 不得重复')
  assert.deepStrictEqual(now, {
    ...previousRegistry,
    reachability: 'v0.5.0',
    tools_list: 'v0.3.0',
    error_taxonomy: 'v0.3.0',
    redirect_policy: 'v0.3.0',
    auth_metadata: 'v0.3.0',
    tool_description_hygiene: 'v0.2.0',
    toolset_fingerprint: 'v0.2.0',
    schema_fingerprint: 'v0.2.0',
    toolset_unchanged_vs_approved: 'v0.2.0',
    schema_unchanged_vs_approved: 'v0.2.0',
  })
  assert.deepStrictEqual(previousRegistry, {
    reachability: 'v0.4.0', latency_profile: 'v0.2.0', transport_type: 'v0.2.0', protocol_revision: 'v0.2.0', discovery_handshake: 'v0.3.0',
    tools_list: 'v0.2.0', error_taxonomy: 'v0.2.0', tls_certificate: 'v0.1.0', redirect_policy: 'v0.2.0', auth_metadata: 'v0.2.0',
    tool_description_hygiene: 'v0.1.0', toolset_fingerprint: 'v0.1.0', schema_fingerprint: 'v0.1.0', toolset_unchanged_vs_approved: 'v0.1.0', schema_unchanged_vs_approved: 'v0.1.0',
  })
})

// latency_profile (registry 0.11.0, suite 0.12.0): the probe times nothing and records the check
// SKIPPED/UNVERIFIED latency_not_recorded on every branch, so no text may say a latency is
// observable or observed. Pinned verbatim, so a copy swap is one exact-once replacement.
t('latency_profile：predicate / what / cannot 不再说延迟「可观测」或「是我们观察到的」，逐字固定', () => {
  const def = CHECKS_REGISTRY.checks.find((c) => c.check_id === 'latency_profile')!
  assert.equal(def.predicate_en, 'p50 / p95 request latency (not measured yet)')
  assert.equal(def.predicate_zh, 'p50 / p95 请求延迟（尚未测量）')
  assert.equal(def.explain.what_en, 'The p50 / p95 request latency within a single run. Not run yet: this probe does not measure request latency.')
  assert.equal(def.explain.what_zh, '单次 run 内的 p50 / p95 请求延迟。尚未运行：探测器目前还不测量请求延迟。')
  assert.equal(def.explain.cannot_en, 'Once measured, this will be what our probe node observed — not what your users see.')
  assert.equal(def.explain.cannot_zh, '开始测量后，这将是从我们探测节点看到的值，不代表你用户看到的值。')
  for (const text of [def.predicate_en, def.predicate_zh, def.explain.what_en, def.explain.what_zh]) {
    assert.doesNotMatch(text, /observable within budget|在预算内可观测/, text)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
