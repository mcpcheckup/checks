import assert from 'node:assert'
import { runProbe } from './probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { ProbeAborted } from './wire.ts'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { DEFAULT_PROBE_BUDGET, createProbeBudget } from '@mcpcheckup/ssrf-guard'
import { assertUnverifiedHasReason } from '@mcpcheckup/attestation-schema'
import { REASON_MESSAGES } from './reason-messages.ts'
import type { ProbeInput, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const FIXED_NOW = '2026-08-18T00:00:00.000Z'

function makeInput(fetchImpl: ProbeInput['fetchImpl']): ProbeInput {
  let seq = 0
  return {
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: 'https://notes-mcp.example.com/mcp' },
    fetchImpl,
    budget: DEFAULT_PROBE_BUDGET,
    now: () => FIXED_NOW,
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  }
}

console.log(`corpus conformance：packages/fixtures 的全部 ${FIXTURE_CORPUS.length} 条 fixture 逐条验证`)
console.log('（比对的是 execution_status / assertion_status，不比对 reason 原文——见 NEXT.md 完成标准）')

// Populated by the corpus-conformance loop below and reused by the
// cross-consistency test at the end of this file, so that test doesn't have
// to re-invoke runProbe against every fixture a second time.
const corpusResults: ProbeResult[] = []

for (const fixture of FIXTURE_CORPUS) {
  await t(`${fixture.id}：产出的 assertions 与期望一致`, async () => {
    const result = await runProbe(makeInput(fixture.createHandler()))
    corpusResults.push(result)
    for (const expected of fixture.expectedAssertions) {
      const actual = result.assertions.find((a) => a.check_id === expected.check_id)
      assert.ok(actual, `${fixture.id}: 缺少 check_id=${expected.check_id} 的 assertion`)
      assert.equal(
        actual!.execution_status,
        expected.execution_status,
        `${fixture.id}/${expected.check_id}: execution_status 期望 ${expected.execution_status}，实际 ${actual!.execution_status}`,
      )
      assert.equal(
        actual!.assertion_status,
        expected.assertion_status,
        `${fixture.id}/${expected.check_id}: assertion_status 期望 ${expected.assertion_status}，实际 ${actual!.assertion_status}`,
      )
    }
  })
}

console.log('\n计数闭合：每个 check_id 恰好产出一条 assertion，覆盖 checks.json 注册表全部条目')

for (const fixture of FIXTURE_CORPUS) {
  await t(`${fixture.id}：assertions.length === registry.checks.length，且 check_id 集合完全一致`, async () => {
    const result = await runProbe(makeInput(fixture.createHandler()))
    assert.equal(result.assertions.length, CHECKS_REGISTRY.checks.length)
    const gotIds = new Set(result.assertions.map((a) => a.check_id))
    const wantIds = new Set(CHECKS_REGISTRY.checks.map((c) => c.check_id))
    assert.deepEqual(gotIds, wantIds)
  })
}

console.log('\nUNVERIFIED 硬约束：本探测器自己产出的每一条 UNVERIFIED 都必须带非空 reason（复用 attestation-schema 的不变量，不重新发明）')

for (const fixture of FIXTURE_CORPUS) {
  await t(`${fixture.id}：assertUnverifiedHasReason 对每条 assertion 都不抛错`, async () => {
    const result = await runProbe(makeInput(fixture.createHandler()))
    for (const a of result.assertions) {
      assert.doesNotThrow(() => assertUnverifiedHasReason(a))
    }
  })
}

console.log('\n预算耗尽：中止前已完成的检查保留其结果，不因后续中止被清空（NEXT.md 项目二）')

await t('response-exceeds-budget：reachability 与 discovery_handshake / protocol_revision / transport_type / latency_profile 在 tools/list 撞上 body 预算后全部保持 COMPLETED/VERIFIED', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'response-exceeds-budget')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  // T6.9-F：reachability 加进了这份名单。它在 performHandshake 返回时就已经为真
  // （server/discover 拿到了一个完整的 HTTP 响应），后面 tools/list 的预算中止没有
  // 资格回头改写它——那正是让 8/12 个未认领目标在握手全 VERIFIED 的同时报出 0%
  // 在线率的缺陷。把断言搬回 try 块末尾，这条的第一行就红。
  for (const check_id of ['reachability', 'discovery_handshake', 'protocol_revision', 'transport_type', 'latency_profile']) {
    const a = result.assertions.find((x) => x.check_id === check_id)!
    assert.equal(a.execution_status, 'COMPLETED', `${check_id}: execution_status`)
    assert.equal(a.assertion_status, 'VERIFIED', `${check_id}: assertion_status`)
  }
  // tools/list 本身从未跑完（预算在读它的响应体时耗尽），所以它和依赖它数据的
  // check 仍然级联为 SKIPPED/UNVERIFIED——不是"全部保留"，是"已完成的保留"。
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.equal(toolsList.execution_status, 'SKIPPED')
  assert.equal(toolsList.assertion_status, 'UNVERIFIED')
  // 中止的真实原因是 wire.ts 自己的 ProbeAborted(MAX_BODY_BYTES)——它必须映射到
  // 专属 key + 数值 params，绝不能把 wire.ts 内部的中文 prose 塞进 params 通道
  // （params 只允许第三方原始诊断文本，见 packages/checks/README.md 的
  // Security boundaries 一节）。中止原因现在挂在**没跑到的**那些 check 上，
  // 因为那才是它回答的问题（"为什么这条没跑"）。
  assert.equal(toolsList.reason?.key, 'probe_budget_exhausted_body')
  assert.equal(toolsList.reason?.params?.maxBodyBytes, DEFAULT_PROBE_BUDGET.maxBodyBytes)
  assert.equal(typeof toolsList.reason?.params?.actualBytes, 'number')
  assert.ok((toolsList.reason?.params?.actualBytes as number) > DEFAULT_PROBE_BUDGET.maxBodyBytes)
})

await t('response-exceeds-budget：cascade 理由不是只换了 key —— params 一起带上，REASON_MESSAGES 能真的把它渲染成两种语言的句子（渲染器对缺 param 是抛错，不是降级）', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'response-exceeds-budget')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  const skipped = result.assertions.filter((a) => a.execution_status === 'SKIPPED' && a.check_id !== 'tls_certificate')
  assert.ok(skipped.length >= 9, `没跑到的检查应当有 9 条以上，实际 ${skipped.length}`)
  for (const a of skipped) {
    const renderer = REASON_MESSAGES[a.unverified_reason!.key]
    assert.ok(renderer, `${a.check_id}: reason key ${a.unverified_reason!.key} 在 REASON_MESSAGES 里没有条目`)
    for (const locale of ['en', 'zh'] as const) {
      // 这一行如果 params 没跟着 key 一起传下来，requireParam 会抛
      // "missing required param" —— 抛在这里，而不是抛在生产的报告页上。
      const rendered = renderer![locale](a.unverified_reason!.params)
      assert.ok(rendered.includes(String(DEFAULT_PROBE_BUDGET.maxBodyBytes)), `${a.check_id}/${locale}: 渲染结果里应当出现真实的预算数值，实际是 ${rendered}`)
    }
  }
})

console.log('\nprobe_aborted 的 params 通道分流：ProbeAborted 的每个 code 都必须映射到独立的 reason key + 纯数值 params，绝不把 wire.ts 自己生成的中文 prose 泄漏进 params（params 是"仅第三方原始诊断文本"通道）；真正的第三方/系统异常仍然合法地走 probe_aborted + { message }')

const PROBE_ABORTED_KEY_BY_CODE = {
  MAX_REQUESTS: 'probe_budget_exhausted_requests',
  MAX_DURATION: 'probe_budget_exhausted_duration',
  MAX_REDIRECTS: 'probe_budget_exhausted_redirects',
  MAX_BODY_BYTES: 'probe_budget_exhausted_body',
} as const

const PROBE_ABORTED_CASES: [keyof typeof PROBE_ABORTED_KEY_BY_CODE, Record<string, number>][] = [
  ['MAX_REQUESTS', { maxRequests: 8 }],
  ['MAX_DURATION', { maxDurationMs: 10_000 }],
  ['MAX_REDIRECTS', { maxRedirects: 3 }],
  ['MAX_BODY_BYTES', { maxBodyBytes: 2_097_152 }],
]

for (const [code, details] of PROBE_ABORTED_CASES) {
  await t(`ProbeAborted('${code}') → reachability.reason = { key: '${PROBE_ABORTED_KEY_BY_CODE[code]}', params: e.details }，绝不包含 e.message 里的中文 prose`, async () => {
    // Thrown directly from fetchImpl rather than driven through a real wire.ts
    // budget trip: MAX_REDIRECTS specifically can never actually fire through
    // runProbe's real traffic (every request protocol.ts sends is POST, and
    // sendRequest only follows redirects for GET — see wire.ts's module doc),
    // so this exercises probe.ts's catch-block code->key mapping directly and
    // uniformly for all four codes, independent of which ones wire.ts's own
    // logic can reach in practice (that reachability is wire.test.ts's job).
    const fetchImpl: ProbeInput['fetchImpl'] = async () => {
      throw new ProbeAborted(code, '这段中文 prose 只应留在 Error.message / 日志里，绝不能出现在 reason.params 中', details)
    }
    const result = await runProbe(makeInput(fetchImpl))
    const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
    assert.equal(reachability.execution_status, 'ERROR')
    assert.equal(reachability.assertion_status, 'UNVERIFIED')
    assert.equal(reachability.reason?.key, PROBE_ABORTED_KEY_BY_CODE[code])
    assert.deepEqual(reachability.reason?.params, details)
  })
}

await t('genuine 的非 ProbeAborted 异常（例如 fetchImpl 自身抛出的网络错误）仍然走 probe_aborted + { message: e.message } —— 这是仍然合法的第三方诊断文本通道，不能回归', async () => {
  const fetchImpl: ProbeInput['fetchImpl'] = async () => { throw new Error('network unreachable') }
  const result = await runProbe(makeInput(fetchImpl))
  const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
  assert.equal(reachability.execution_status, 'ERROR')
  assert.equal(reachability.assertion_status, 'UNVERIFIED')
  assert.deepEqual(reachability.reason, { key: 'probe_aborted', params: { message: 'network unreachable' } })
})

console.log('\n确定性：同一 fixture + 同一注入时钟/ID 生成器 → 逐字节相同的输出')

await t('modern-baseline-clean：跑两次，assertions 与 toolSnapshot 完全相同', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'modern-baseline-clean')!
  const r1 = await runProbe(makeInput(fixture.createHandler()))
  const r2 = await runProbe(makeInput(fixture.createHandler()))
  assert.deepEqual(r1.assertions, r2.assertions)
  assert.deepEqual(r1.toolSnapshot, r2.toolSnapshot)
})

console.log('\nprotocolRevisionDeclared：握手中实际观察到的协议版本原样透出，独立于 protocol_revision 检查的判定结果')

await t('modern-baseline-clean：result.protocolRevisionDeclared === \'2026-07-28\'', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'modern-baseline-clean')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  assert.equal(result.protocolRevisionDeclared, '2026-07-28')
})

await t('legacy-baseline-clean：result.protocolRevisionDeclared === \'2025-06-18\'', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'legacy-baseline-clean')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  assert.equal(result.protocolRevisionDeclared, '2025-06-18')
})

console.log('\ndocs_version / evidence_provenance：每条 assertion 都必须携带，且来自 registry 而不是硬编码')

await t('modern-baseline-clean：每条 assertion 的 docs_version 与 checks.json 里对应条目一致', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'modern-baseline-clean')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  for (const a of result.assertions) {
    const def = CHECKS_REGISTRY.checks.find((c) => c.check_id === a.check_id)
    assert.equal(a.docs_version, def!.docs_version)
    assert.equal(a.evidence_provenance, 'INDEPENDENTLY_OBSERVED')
  }
})

console.log('\nkey/catalog 一致性：probe.ts 产出的每一个 reason key 都必须能在 REASON_MESSAGES 中查到（no_baseline_reason 除外，它经 checks.json 解析）')

await t('every key probe.ts can emit exists in REASON_MESSAGES (or is no_baseline_reason, which resolves via checks.json)', () => {
  const seenKeys = new Set<string>()
  for (const result of corpusResults) {
    for (const a of result.assertions) {
      if (a.reason) seenKeys.add(a.reason.key)
      if (a.unverified_reason) seenKeys.add(a.unverified_reason.key)
    }
    if (result.disqualifiedFromPublication) seenKeys.add(result.disqualifiedFromPublication.key)
  }
  assert.ok(seenKeys.size > 0, '期望至少观察到一个 reason key（否则这条断言等于没测）')
  for (const key of seenKeys) {
    assert.ok(
      key === 'no_baseline_reason' || key in REASON_MESSAGES,
      `probe.ts 产出了未登记在 REASON_MESSAGES 里的 reason key: ${key}`,
    )
  }
})

console.log('\nT73：error_taxonomy 的 reason 是签名证据 —— 凡是实际产出 OBSERVED_RISK 的 fixture，其期望必须声明 reason，且与 probe 产出逐字段相等（未声明 = 红，不是跳过）。与下面 N3 同一做法：单独钉 error_taxonomy，不加宽共享循环')

const errorTaxonomyReasonFixtures: string[] = []
for (const fixture of FIXTURE_CORPUS) {
  const expected = fixture.expectedAssertions.find((a) => a.check_id === 'error_taxonomy')
  if (expected?.assertion_status !== 'OBSERVED_RISK') continue
  errorTaxonomyReasonFixtures.push(fixture.id)
  await t(`${fixture.id}：error_taxonomy 的 reason 与 fixture 期望完全相等`, async () => {
    const result = await runProbe(makeInput(fixture.createHandler()))
    const actual = result.assertions.find((a) => a.check_id === 'error_taxonomy')!
    assert.ok(expected!.reason, `${fixture.id}: error_taxonomy 期望是 OBSERVED_RISK，但没有声明 reason —— 签名进记录的分类必须被 fixture 钉住`)
    assert.deepStrictEqual(actual.reason, expected!.reason)
  })
}

await t('没有漏网：每条实际产出 error_taxonomy OBSERVED_RISK 的 fixture 都在上面那组里，且至少 8 条（2 条既有 + 6 条 T73 新增）', () => {
  const observed = FIXTURE_CORPUS.filter((f, i) => corpusResults[i]?.assertions.find((a) => a.check_id === 'error_taxonomy')?.assertion_status === 'OBSERVED_RISK').map((f) => f.id)
  assert.equal(corpusResults.length, FIXTURE_CORPUS.length, 'corpus-conformance 循环没有为每条 fixture 留下结果')
  assert.deepEqual([...errorTaxonomyReasonFixtures].sort(), [...observed].sort())
  assert.ok(errorTaxonomyReasonFixtures.length >= 8, `只有 ${errorTaxonomyReasonFixtures.length} 条`)
})

console.log('\nT73b：FAILED 的 reason 也是签名证据 —— 五个 check 上凡是实际产出 FAILED 的 fixture，其期望必须声明 reason，且与 probe 产出逐字段相等（未声明 = 红）。fixture 里的 params: {} 表示签名记录里整个没有 params 字段（有一个空对象也算不等）')

const FAILED_REASON_CHECKS = ['discovery_handshake', 'protocol_revision', 'tools_list', 'toolset_fingerprint', 'schema_fingerprint']

/** One dedicated fixture per T73b key, and the one assertion in it that the
 *  fixture-swap red proof mutates. Written out here, independently of the
 *  fixture file: the per-fixture test below checks the PROBE's actual key for
 *  that assertion against this table (not the fixture's declaration), so a
 *  fixture that quietly stops pinning its key turns red here, while swapping a
 *  declared key turns exactly that fixture's test red. */
const T73B_DEDICATED: Record<string, [fixtureId: string, checkId: string]> = {
  handshake_discover_not_jsonrpc: ['handshake-discover-not-jsonrpc', 'discovery_handshake'],
  handshake_discover_jsonrpc_error: ['handshake-discover-jsonrpc-error', 'discovery_handshake'],
  handshake_discover_no_supported_versions: ['handshake-discover-no-supported-versions', 'discovery_handshake'],
  handshake_discover_rejected: ['handshake-discover-rejected', 'discovery_handshake'],
  handshake_discover_http_error: ['handshake-discover-http-error', 'discovery_handshake'],
  handshake_initialize_http_error: ['handshake-initialize-http-error', 'discovery_handshake'],
  handshake_initialize_not_jsonrpc: ['handshake-initialize-not-jsonrpc', 'discovery_handshake'],
  handshake_initialize_jsonrpc_error: ['handshake-initialize-jsonrpc-error', 'discovery_handshake'],
  handshake_initialize_no_protocol_version: ['handshake-initialize-no-protocol-version', 'discovery_handshake'],
  handshake_ack_http_error: ['handshake-ack-http-error', 'discovery_handshake'],
  protocol_revision_missing: ['protocol-revision-missing', 'protocol_revision'],
  protocol_revision_unknown: ['protocol-revision-unknown', 'protocol_revision'],
  tools_list_challenge_after_failed_handshake: ['tools-list-challenge-after-failed-handshake', 'tools_list'],
  tools_list_not_jsonrpc: ['tools-list-not-jsonrpc', 'tools_list'],
  tools_list_jsonrpc_error: ['tools-list-jsonrpc-error', 'tools_list'],
  tools_list_not_array: ['tools-list-not-array', 'tools_list'],
  fingerprint_tool_missing_name: ['fingerprint-tool-missing-name', 'toolset_fingerprint'],
  fingerprint_canonicalize_failed: ['fingerprint-canonicalize-failed', 'schema_fingerprint'],
}

const failedReasonCells: string[] = []
for (const fixture of FIXTURE_CORPUS) {
  const expectations = fixture.expectedAssertions.filter((a) => FAILED_REASON_CHECKS.includes(a.check_id) && a.assertion_status === 'FAILED')
  if (expectations.length === 0) continue
  for (const e of expectations) failedReasonCells.push(`${fixture.id}/${e.check_id}`)
  const dedicated = Object.entries(T73B_DEDICATED).find(([, [id]]) => id === fixture.id)
  await t(`${fixture.id}：FAILED 的 reason 与 fixture 期望完全相等（${expectations.map((e) => e.check_id).join(' / ')}）`, async () => {
    const result = await runProbe(makeInput(fixture.createHandler()))
    for (const e of expectations) {
      const actual = result.assertions.find((a) => a.check_id === e.check_id)!
      assert.ok(e.reason, `${fixture.id}/${e.check_id}: 期望是 FAILED，但没有声明 reason —— 签名进记录的原因必须被 fixture 钉住`)
      const { key, params } = e.reason!
      assert.deepStrictEqual(actual.reason, Object.keys(params).length > 0 ? { key, params } : { key }, `${fixture.id}/${e.check_id}`)
      assert.strictEqual(actual.unverified_reason, null, `${fixture.id}/${e.check_id}: FAILED 不写 unverified_reason`)
    }
    if (dedicated) {
      const [dedicatedKey, [, checkId]] = dedicated
      assert.equal(result.assertions.find((a) => a.check_id === checkId)!.reason?.key, dedicatedKey, `${fixture.id} 是 ${dedicatedKey} 的专属 fixture`)
    }
  })
}

await t('没有漏网：五个 check 上实际产出的每一格 FAILED 都在上面那组里（反之亦然），且每一格都带非空 reason', () => {
  assert.equal(corpusResults.length, FIXTURE_CORPUS.length, 'corpus-conformance 循环没有为每条 fixture 留下结果')
  const observed: string[] = []
  FIXTURE_CORPUS.forEach((f, i) => {
    for (const a of corpusResults[i]!.assertions) {
      if (!FAILED_REASON_CHECKS.includes(a.check_id) || a.assertion_status !== 'FAILED') continue
      observed.push(`${f.id}/${a.check_id}`)
      assert.ok(a.reason !== null && a.reason.key.length > 0, `${f.id}/${a.check_id}: FAILED 没有 reason`)
    }
  })
  assert.deepEqual([...failedReasonCells].sort(), observed.sort())
})

await t('T73b 的 18 个 key 各有一条专属 fixture：key 都在 REASON_MESSAGES 里，fixture 两两不同且都在语料里，且专属那一格在 fixture 里声明为 FAILED', () => {
  const entries = Object.entries(T73B_DEDICATED)
  assert.equal(entries.length, 18)
  assert.equal(new Set(entries.map(([, [id]]) => id)).size, 18)
  for (const [key, [id, checkId]] of entries) {
    assert.ok(key in REASON_MESSAGES, key)
    const fixture = FIXTURE_CORPUS.find((f) => f.id === id)
    assert.ok(fixture, `${id} 不在 FIXTURE_CORPUS 里`)
    assert.equal(fixture!.expectedAssertions.find((a) => a.check_id === checkId)?.assertion_status, 'FAILED', `${id}/${checkId}`)
  }
})

console.log('\nLead finding N3（round 2）：corpus-conformance 循环（第 40 行起）只比对 execution_status / assertion_status，不比对 reason —— 不在这里加宽那个共享循环（会重新评判已有的每一条 fixture），改为单独钉住两条新增 credential-gated 正例的 reason.key 与 params.scheme')

await t('credential-gated-handshake：discovery_handshake / protocol_revision / tools_list 的 reason 精确等于 { key: \'credential_required\', params: { scheme: \'bearer\' } }', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'credential-gated-handshake')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  for (const check_id of ['discovery_handshake', 'protocol_revision', 'tools_list']) {
    const a = result.assertions.find((x) => x.check_id === check_id)!
    assert.deepEqual(a.reason, { key: 'credential_required', params: { scheme: 'bearer' } }, `${check_id}: reason`)
  }
})

await t('credential-gated-tools-list：tools_list 的 reason 精确等于 { key: \'credential_required\', params: { scheme: \'bearer\' } }；discovery_handshake / protocol_revision 保留它们真实的 VERIFIED 结果，不带 credential_required reason', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'credential-gated-tools-list')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.deepEqual(toolsList.reason, { key: 'credential_required', params: { scheme: 'bearer' } })
  const handshake = result.assertions.find((a) => a.check_id === 'discovery_handshake')!
  assert.equal(handshake.assertion_status, 'VERIFIED')
  // Lead finding N9 (round 3): this file imports loose 'node:assert', whose
  // .equal is == not ===  — assert.equal(x, undefined) silently passes when
  // x is actually null (null == undefined is true), so it read as a strict
  // pin without being one. probe.ts's AssertionBuilder defaults an omitted
  // reason to null (not undefined — see the `reason = null` default
  // parameter), so null is the real, pinned value here; assert.strictEqual
  // makes that the actual claim instead of accidentally accepting either.
  assert.strictEqual(handshake.reason, null)
  const revision = result.assertions.find((a) => a.check_id === 'protocol_revision')!
  assert.equal(revision.assertion_status, 'VERIFIED')
  assert.strictEqual(revision.reason, null)
})

// ---- Codex PR#19 P2 (round 9): signed evidence must never
// be derived from a response the server itself marked 401. The corpus loop
// above only compares execution_status/assertion_status, so the part that
// actually matters here — that NO fingerprint was computed — has to be
// asserted directly, not inferred from the five tools-derived checks being
// SKIPPED. ----

await t('credential-gated-tools-list-with-tools-body：tools/list 是 401 + 合法 challenge，但 body 里带着结构完好的 tools 数组——tools_list 记 COMPLETED/UNVERIFIED/credential_required，且 toolSnapshot 完全不存在：没有 toolset 指纹、没有 schema 指纹、没有 tools 快照、没有 drift 事件', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'credential-gated-tools-list-with-tools-body')!
  const result = await runProbe(makeInput(fixture.createHandler()))

  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.equal(toolsList.execution_status, 'COMPLETED')
  assert.equal(toolsList.assertion_status, 'UNVERIFIED')
  assert.deepEqual(toolsList.reason, { key: 'credential_required', params: { scheme: 'bearer' } })

  // The load-bearing assertion of this whole round. strictEqual, not equal:
  // this file imports loose node:assert, where undefined == null (see the N9
  // note above), so assert.equal here would pass on either value and would
  // not actually pin absence.
  assert.strictEqual(result.toolSnapshot, undefined, 'no ToolSnapshot may be built from a response the server marked 401')
  assert.deepEqual(result.driftEvents, [], 'no drift may be derived from a fingerprint that must not exist')

  // ...and the two fingerprint checks themselves never ran, rather than
  // having run and produced something.
  for (const id of ['toolset_fingerprint', 'schema_fingerprint']) {
    const a = result.assertions.find((x) => x.check_id === id)!
    assert.equal(a.execution_status, 'SKIPPED', `${id} must be SKIPPED, not COMPLETED`)
    assert.equal(a.assertion_status, 'UNVERIFIED')
    assert.deepEqual(a.unverified_reason, { key: 'credential_required', params: { scheme: 'bearer' } })
  }
})

await t('对照组：同一个 handler、只把 tools/list 的 401 + challenge 换成 200（body 逐字节不变）时，指纹必须被算出来——证明上面那条钉的是"401 挡住了指纹"，而不是这个 body 恰好算不出指纹', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'credential-gated-tools-list-with-tools-body')!
  const gated = fixture.createHandler()
  const unGated: typeof gated = async (input, init) => {
    const res = await gated(input, init)
    if (res.status !== 401) return res
    const headers = new Headers(res.headers)
    headers.delete('www-authenticate')
    return new Response(await res.text(), { status: 200, headers })
  }
  const result = await runProbe(makeInput(unGated))
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.equal(toolsList.assertion_status, 'VERIFIED')
  assert.ok(result.toolSnapshot, 'the same body DOES produce a snapshot once the 401 challenge is gone')
  assert.ok(result.toolSnapshot.toolset_fingerprint, 'toolset fingerprint is computable from this body')
  assert.ok(result.toolSnapshot.schema_fingerprint, 'schema fingerprint is computable from this body')
})

// ---- Codex PR#19 (round 11): the corpus loop compares only execution_status
// and assertion_status, so the part that carries the Lead ruling on Codex
// 3919297516 — with two challenges present the FIRST one governs — has to be
// pinned separately. ----

await t('credential-challenge-list-ows-before-comma：WWW-Authenticate 是 `Basic , Bearer realm="mcp", resource_metadata="…"`（逗号前有 list OWS）——三条协议检查记 UNVERIFIED/credential_required，且 params.scheme 是第一条 challenge 的 basic，不是后面那条的 bearer', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'credential-challenge-list-ows-before-comma')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  for (const id of ['discovery_handshake', 'protocol_revision', 'tools_list']) {
    const a = result.assertions.find((x) => x.check_id === id)!
    assert.equal(a.execution_status, 'COMPLETED')
    assert.equal(a.assertion_status, 'UNVERIFIED')
    assert.deepEqual(a.reason, { key: 'credential_required', params: { scheme: 'basic' } }, `${id} must carry the FIRST challenge scheme`)
  }
  // and nothing was fingerprinted off a 401, same invariant as round 9
  assert.strictEqual(result.toolSnapshot, undefined)
})

await t('credential-challenge-htab-separator-not-exempted：scheme 与 realm 之间是 HTAB（不是 1*SP）——不豁免，三条协议检查记 FAILED，且没有任何 assertion 带 credential_required', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'credential-challenge-htab-separator-not-exempted')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  for (const id of ['discovery_handshake', 'protocol_revision', 'tools_list']) {
    assert.equal(result.assertions.find((x) => x.check_id === id)!.assertion_status, 'FAILED')
  }
  const gated = result.assertions.filter((a) => a.reason?.key === 'credential_required' || a.unverified_reason?.key === 'credential_required')
  assert.deepEqual(gated, [], 'a malformed 1*SP separator must not produce a credential_required anywhere in the run')
})

// ---- Codex PR#19 (round 18): the regex-level assertions in auth.test.ts show
// the quoted-string classes were over-wide; THIS one shows it mattered — the
// whole round comes out of runProbe on its ordinary FAILED path instead of
// being converted into UNVERIFIED / credential_required. ----

await t('credential-challenge-qdtext-control-char-not-exempted：realm 的 quoted-string 里夹了一个 %x01 控制字符——不豁免，三条协议检查记 FAILED，且整轮没有任何 assertion 带 credential_required', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'credential-challenge-qdtext-control-char-not-exempted')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  for (const id of ['discovery_handshake', 'protocol_revision', 'tools_list']) {
    assert.equal(result.assertions.find((x) => x.check_id === id)!.assertion_status, 'FAILED')
  }
  const gated = result.assertions.filter((a) => a.reason?.key === 'credential_required' || a.unverified_reason?.key === 'credential_required')
  assert.deepEqual(gated, [], 'a control character inside qdtext must not produce a credential_required anywhere in the run')
})

console.log('\nT6.9-A1：目标说「稍后再来」时，本轮对该目标的后续请求数必须是零——包括绝不回头再发一轮 legacy 握手')

/** 用一个自己计数的 fetchImpl 包住 fixture 的 handler：runProbe 整轮真正发出的
 *  出站请求次数。packages/checks 的生产代码里没有任何裸 fetch(（由
 *  no-direct-fetch.test.ts 结构性保证），且注入的 fetchImpl 只在 wire.ts 的
 *  sendRequest 里被调用一次，所以这个数字就是本轮的全部出网次数，不是某一层的
 *  局部计数。 */
async function runCountingRequests(fixtureId: string): Promise<{ result: ProbeResult; requests: number }> {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === fixtureId)!
  const handler = fixture.createHandler()
  let requests = 0
  const counting: ProbeInput['fetchImpl'] = async (input, init) => {
    requests++
    return handler(input, init)
  }
  const result = await runProbe(makeInput(counting))
  return { result, requests }
}

for (const fixtureId of ['rate-limited-429-no-retry-after', 'rate-limited-429-retry-after', 'rate-limited-503-with-retry-after']) {
  await t(`${fixtureId}：整轮恰好 1 次出站请求——第一次响应就中止，没有第二次`, async () => {
    const { result, requests } = await runCountingRequests(fixtureId)
    assert.equal(
      requests,
      1,
      '这正是本任务要修的行为：修复前 429 落进 performHandshake 的 4xx 通用分支，末尾 return performLegacyHandshake(...)，' +
        '于是对一台刚说「你太快了」的目标又发了一轮 initialize / notifications/initialized / tools/list / tools/call',
    )
    const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
    assert.equal(reachability.execution_status, 'ERROR')
    assert.equal(reachability.assertion_status, 'UNVERIFIED', '被限流绝不是 FAILED——「对方让我们晚点再来」不是「这个 server 坏了」')
  })
}

await t('三条限流 fixture 的 reachability.reason 逐字段精确等于期望（corpus-conformance 那圈循环只比对两个 status，不比对 reason——params 里的 status / retryAfterSeconds 只能在这里钉）', async () => {
  const expected: [string, { key: string; params: Record<string, number> }][] = [
    ['rate-limited-429-no-retry-after', { key: 'probe_rate_limited', params: { status: 429 } }],
    ['rate-limited-429-retry-after', { key: 'probe_rate_limited', params: { status: 429, retryAfterSeconds: 3600 } }],
    ['rate-limited-503-with-retry-after', { key: 'probe_rate_limited', params: { status: 503, retryAfterSeconds: 3600 } }],
  ]
  for (const [fixtureId, reason] of expected) {
    const fixture = FIXTURE_CORPUS.find((f) => f.id === fixtureId)!
    const result = await runProbe(makeInput(fixture.createHandler()))
    const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
    assert.deepEqual(reachability.reason, reason, `${fixtureId}: reachability.reason`)
    assert.deepEqual(reachability.unverified_reason, reason, `${fixtureId}: unverified_reason（UNVERIFIED 必须带原因的那一层冗余）`)
  }
})

await t('rateLimited 是 runProbe 返回值上一个独立的类型化字段，不需要任何人从 reason.params 里反读——429 无 Retry-After 时是 null，不是 0', async () => {
  const cases: [string, number | null][] = [
    ['rate-limited-429-no-retry-after', null],
    ['rate-limited-429-retry-after', 3600],
    ['rate-limited-503-with-retry-after', 3600],
  ]
  for (const [fixtureId, retryAfterSeconds] of cases) {
    const fixture = FIXTURE_CORPUS.find((f) => f.id === fixtureId)!
    const result = await runProbe(makeInput(fixture.createHandler()))
    assert.deepEqual(result.rateLimited, { retryAfterSeconds }, `${fixtureId}: rateLimited`)
  }
})

await t('反例（503 裁定不能被实现反）：503 不带 Retry-After 的目标必须跑完整轮——多次出站请求、reachability 是 COMPLETED/VERIFIED、runProbe 不产出 rateLimited 字段', async () => {
  const { result, requests } = await runCountingRequests('service-unavailable-503-no-retry-after-not-rate-limited')
  assert.ok(requests > 1, `不带 Retry-After 的 503 必须维持现状（继续走完既有流程），实际只发了 ${requests} 次请求`)
  const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
  assert.equal(reachability.execution_status, 'COMPLETED', '本轮没有被中止')
  assert.equal(reachability.assertion_status, 'VERIFIED')
  assert.equal(result.rateLimited, undefined, 'rateLimited 一旦出现，调度侧就会顺延 next_run_at——不带 Retry-After 的 503 不得触发它')
})

await t('反例对照：同一个 503，只多一个 Retry-After 头，两条路径的出站请求数与 reachability 必须相反（证明判据落在头上，不在状态码上）', async () => {
  const withHeader = await runCountingRequests('rate-limited-503-with-retry-after')
  const withoutHeader = await runCountingRequests('service-unavailable-503-no-retry-after-not-rate-limited')
  assert.equal(withHeader.requests, 1)
  assert.ok(withoutHeader.requests > 1)
  assert.equal(withHeader.result.assertions.find((a) => a.check_id === 'reachability')!.execution_status, 'ERROR')
  assert.equal(withoutHeader.result.assertions.find((a) => a.check_id === 'reachability')!.execution_status, 'COMPLETED')
})

console.log('\nN2：rateLimited 只由 RATE_LIMITED 一个 code 产出——其余每一种中止都不得触发它（否则「对方要求我们稍后再来」这句运维日志会对该目标为假，且调度侧会平白退避）')

await t('response-exceeds-budget（真实走完 wire.ts 的 MAX_BODY_BYTES 中止）：runProbe 不产出 rateLimited，中止理由是 probe_budget_exhausted_body 而不是 probe_rate_limited', async () => {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === 'response-exceeds-budget')!
  const result = await runProbe(makeInput(fixture.createHandler()))
  assert.equal(result.rateLimited, undefined, 'rateLimited 一旦出现，调用方就会打出限流日志并顺延下一次运行——一次超预算不该有这两个后果')
  assert.ok(!('rateLimited' in result), 'exactOptionalPropertyTypes：该键必须整个不存在，不是 present-with-undefined')
  // T6.9-F：中止理由的落点从 reachability 换到了没跑到的检查（这一轮的 reachability
  // 已经由握手判定为 VERIFIED），断言对象随之改。
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.equal(toolsList.reason?.key, 'probe_budget_exhausted_body')
  assert.notEqual(toolsList.reason?.key, 'probe_rate_limited')
  assert.equal(toolsList.reason?.params?.retryAfterSeconds, undefined, '预算中止的 params 里不得凭空出现一个 retryAfterSeconds')
})

await t('四种非 RATE_LIMITED 的 ProbeAborted 逐个验证：都不产出 rateLimited（把 probe.ts 的判据放宽成恒真，这条会四次全红）', async () => {
  for (const [code, details] of PROBE_ABORTED_CASES) {
    const fetchImpl: ProbeInput['fetchImpl'] = async () => { throw new ProbeAborted(code, '一段本地生成的中文诊断文本，不该出现在任何 reason 里', details) }
    const result = await runProbe(makeInput(fetchImpl))
    assert.equal(result.rateLimited, undefined, `${code}: 不得产出 rateLimited`)
    const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
    assert.equal(reachability.reason?.key, PROBE_ABORTED_KEY_BY_CODE[code], `${code}: reason key`)
  }
})

await t('非 ProbeAborted 的普通异常（fetchImpl 自己抛的网络错误）同样不产出 rateLimited', async () => {
  const fetchImpl: ProbeInput['fetchImpl'] = async () => { throw new Error('network unreachable') }
  const result = await runProbe(makeInput(fetchImpl))
  assert.equal(result.rateLimited, undefined)
  assert.equal(result.assertions.find((a) => a.check_id === 'reachability')!.reason?.key, 'probe_aborted')
})

// ---- T6.9-F ----

console.log('\nT6.9-F / F1：握手成功之后的预算中止不得回头把 reachability 改成 UNVERIFIED（生产上 8/12 个未认领目标结构性 0% 在线率的直接成因）')

/** 与 runCountingRequests 同一件事，但预算可调——F1 的红证需要一个"小到跑不完
 *  cascade"的预算，F2 的计数表需要 4 与 8 两列。 */
async function runWithBudget(fixtureId: string, maxRequests: number): Promise<{ result: ProbeResult; requests: number }> {
  const fixture = FIXTURE_CORPUS.find((f) => f.id === fixtureId)!
  const handler = fixture.createHandler()
  let requests = 0
  const counting: ProbeInput['fetchImpl'] = async (input, init) => {
    requests++
    return handler(input, init)
  }
  const input = makeInput(counting)
  const result = await runProbe({ ...input, budget: { ...DEFAULT_PROBE_BUDGET, maxRequests } })
  return { result, requests }
}

await t('F1 红证：legacy fixture + maxRequests=4（旧的未认领档）—— 握手拿到了完整响应，所以 reachability 是 COMPLETED/VERIFIED；跑不到的检查带的是 probe_budget_exhausted_requests {maxRequests:4}，不是通用的 probe_cascade_incomplete', async () => {
  // 这条在修复前必红两次：(1) 旧代码把 A('reachability', COMPLETED, VERIFIED)
  // 放在 try 块最后一句，legacy 路径第 5 次请求（tools/call）撞上 4 的预算就抛，
  // 于是 catch 把 reachability 记成 ERROR/UNVERIFIED；(2) 旧的 cascade 一律用
  // probe_cascade_incomplete，读者看不到"为什么没跑"。
  const { result, requests } = await runWithBudget('legacy-baseline-clean', 4)
  assert.equal(requests, 4, '预算 4 在 legacy 路径上恰好在第 5 次请求前用尽')

  const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
  assert.equal(reachability.execution_status, 'COMPLETED')
  assert.equal(reachability.assertion_status, 'VERIFIED')
  assert.equal(reachability.reason, null, '一条 VERIFIED 的可达性不该带中止理由——中止发生在它之后')

  // 握手确实成功了：这是"可达但没测完"与"根本没连上"的区别所在。
  for (const check_id of ['discovery_handshake', 'protocol_revision', 'tools_list']) {
    assert.equal(result.assertions.find((a) => a.check_id === check_id)!.assertion_status, 'VERIFIED', `${check_id}`)
  }

  // 中止之后才轮到的那些检查：带中止本身的原因与数值 params。
  const abortedByBudget = result.assertions.filter((a) => a.unverified_reason?.key === 'probe_budget_exhausted_requests')
  assert.deepEqual(
    abortedByBudget.map((a) => a.check_id).sort(),
    ['auth_metadata', 'error_taxonomy', 'redirect_policy'],
    '预算耗尽发生在 tools/call 之前，所以恰好是这三条没跑到',
  )
  for (const a of abortedByBudget) {
    assert.equal(a.execution_status, 'SKIPPED')
    assert.deepEqual(a.unverified_reason!.params, { maxRequests: 4 })
    // params 真的到得了渲染器：这几个 key 的渲染器对缺 param 是抛错，不是降级，
    // 所以只比对 key 的测试会绿、而报告页会 500。
    for (const locale of ['en', 'zh'] as const) {
      assert.ok(REASON_MESSAGES[a.unverified_reason!.key]![locale](a.unverified_reason!.params).includes('4'))
    }
  }
})

await t('F1 的另一半（不能只朝一个方向）：第一个请求就中止时，reachability 仍然是 ERROR/UNVERIFIED —— 守卫不得被写成"reachability 恒 VERIFIED"', async () => {
  // maxRequests=0：wire.ts 在发出 server/discover 之前就抛 MAX_REQUESTS，
  // performHandshake 从未返回，所以"endpoint 有没有应答"这一轮确实没有答案。
  const { result, requests } = await runWithBudget('legacy-baseline-clean', 0)
  assert.equal(requests, 0)
  const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
  assert.equal(reachability.execution_status, 'ERROR')
  assert.equal(reachability.assertion_status, 'UNVERIFIED')
  assert.equal(reachability.unverified_reason?.key, 'probe_budget_exhausted_requests')
  assert.deepEqual(reachability.unverified_reason?.params, { maxRequests: 0 })
})

console.log('\nT6.9-F / F2：四条路径的出站请求计数表——预算 4（旧的未认领档）与 8（用户 2026-09-09 拍定的两档同值）两列。表写进断言而不是注释：将来任何一次预算改动都会表现为一处计数差，而不是一次无声的行为漂移')

/** 每一行：[路径名, fixture id, 预算 4 下的实测请求数, 预算 4 下 cascade 是否跑完,
 *          预算 8 下的实测请求数, 预算 8 下 cascade 是否跑完]。
 *
 *  数字全部是在本仓库实测出来的，不是推算的。读法：
 *   · modern 路径 3 次（server/discover -> tools/list -> tools/call），4 就够；
 *   · legacy 路径 5 次（server/discover 4xx -> initialize -> notifications/
 *     initialized -> tools/list -> tools/call），4 差一次，这正是 F2 要修的；
 *   · legacy + 握手层凭据门也是 5 次：握手在 initialize 上就被 401 挡住，省掉了
 *     notifications/initialized，但 tools/call 的 401 challenge 让 auth_metadata
 *     多抓一次 resource_metadata 文档，正好补回来；
 *   · 第五行是**全语料最贵的一条路径，6 次**：legacy 握手完整成功（3）+
 *     tools/list（4）+ tools/call（5）+ tools/call 的 401 challenge 引出的
 *     resource_metadata 抓取（6）。
 *
 *  第五行的来历（round 2，不要把它退回成注释）：T6.9-F 第一轮实测全语料 38 条
 *  fixture 的最大值只有 5，6 只是读代码得出的上界，没有任何 fixture 走到那一格，
 *  于是「未认领预算取 8 还剩几次余量」这个论证挂在一个没被钉住的数字上。
 *  packages/fixtures 的 legacy-tools-call-credential-gated 就是为补这一格加的，
 *  **6 从此是实测值**。预算若被调到 6 以下，这一行会以「cascade 被截断」变红。
 *  于是 8 的最坏余量 = 8 − 6 = 2 次，也是实测出来的。 */
const REQUEST_COUNT_TABLE: [string, string, number, boolean, number, boolean][] = [
  ['modern open', 'modern-baseline-clean', 3, true, 3, true],
  ['legacy open', 'legacy-baseline-clean', 4, false, 5, true],
  ['modern gated', 'credential-gated-tools-list', 3, true, 3, true],
  ['legacy gated (handshake)', 'credential-gated-handshake', 4, false, 5, true],
  ['legacy gated (tools/call) — 全语料最贵', 'legacy-tools-call-credential-gated', 4, false, 6, true],
]

/** 未认领档如今的取值，两档同值（packages/ssrf-guard/src/budget.ts）。表里的 8
 *  从这里来，而不是又一处手写字面量——预算一旦再动，这张表整体跟着动。 */
const CURRENT_MAX_REQUESTS = createProbeBudget({ claimed: false }).maxRequests

/** "cascade 跑完了" = 没有任何一条 assertion 是因为预算/中止而没产出的。
 *  刻意不写成"没有 SKIPPED"：tls_certificate 永远 SKIPPED，凭据门与无基线也
 *  各自合法地产出 SKIPPED，那些都不是"没跑完"。 */
function cascadeCompleted(result: ProbeResult): boolean {
  const ABORT_KEYS = ['probe_budget_exhausted_requests', 'probe_budget_exhausted_duration', 'probe_budget_exhausted_redirects', 'probe_budget_exhausted_body', 'probe_rate_limited', 'probe_cascade_incomplete', 'probe_aborted']
  return !result.assertions.some((a) => a.unverified_reason !== null && ABORT_KEYS.includes(a.unverified_reason.key))
}

for (const [label, fixtureId, requestsAt4, completeAt4, requestsAt8, completeAt8] of REQUEST_COUNT_TABLE) {
  await t(`${label}（${fixtureId}）：预算 4 -> ${requestsAt4} 次请求 / cascade ${completeAt4 ? '跑完' : '被截断'}；预算 8 -> ${requestsAt8} 次请求 / cascade ${completeAt8 ? '跑完' : '被截断'}`, async () => {
    const at4 = await runWithBudget(fixtureId, 4)
    assert.equal(at4.requests, requestsAt4, `${label} @4：出站请求数`)
    assert.equal(cascadeCompleted(at4.result), completeAt4, `${label} @4：cascade 是否完整`)

    const at8 = await runWithBudget(fixtureId, 8)
    assert.equal(at8.requests, requestsAt8, `${label} @8：出站请求数`)
    assert.equal(cascadeCompleted(at8.result), completeAt8, `${label} @8：cascade 是否完整`)

    // 无论哪一档、哪条路径，reachability 都已判定——四条路径的握手都拿到了响应。
    const reachability = at4.result.assertions.find((a) => a.check_id === 'reachability')!
    assert.equal(reachability.assertion_status, 'VERIFIED', `${label} @4：reachability`)
    assert.equal(at8.result.assertions.find((a) => a.check_id === 'reachability')!.assertion_status, 'VERIFIED', `${label} @8：reachability`)
  })
}

await t('这张表有区分力（否则它是一张恒真的表）：legacy 三条在 4 与 8 下的请求数必须不同，modern 两条必须相同', () => {
  const legacy = REQUEST_COUNT_TABLE.filter(([label]) => label.startsWith('legacy'))
  const modern = REQUEST_COUNT_TABLE.filter(([label]) => label.startsWith('modern'))
  assert.equal(legacy.length, 3, 'round 2 加了第五行；这个数字写死是为了让"加了一行却忘了想清楚它属不属于这条断言"变红')
  assert.equal(modern.length, 2)
  for (const [label, , at4, complete4, at8] of legacy) {
    assert.notEqual(at4, at8, `${label}：两档若相同，这张表就没在描述 F2 修的那个差异`)
    assert.equal(complete4, false, `${label}：旧的未认领档必须真的跑不完——那是 F2 的全部理由`)
  }
  for (const [label, , at4, , at8] of modern) {
    assert.equal(at4, at8, `${label}：modern 路径在两档下本就一样，写成不一样说明表抄错了`)
  }
})

await t('表里的最大值 6 就是全语料的最大值，且它与当前预算的余量是实测的 2 —— "8 够用"这句话从此有凭据，不再靠读码', async () => {
  const tableMax = Math.max(...REQUEST_COUNT_TABLE.map(([, , , , at8]) => at8))
  assert.equal(tableMax, 6, '表里的最大值')

  // 不止"表里最大"，而是"全语料最大"：逐条 fixture 在一个远高于任何路径的预算下
  // 跑一遍数真实出站次数。没有这一圈，将来某条新 fixture 悄悄比 6 更贵，表还是绿的。
  let corpusMax = 0
  let corpusMaxId = ''
  for (const fixture of FIXTURE_CORPUS) {
    const { requests } = await runWithBudget(fixture.id, 32)
    if (requests > corpusMax) { corpusMax = requests; corpusMaxId = fixture.id }
  }
  assert.equal(corpusMax, tableMax, `全语料最贵的是 ${corpusMaxId}（${corpusMax} 次），而表里的最大值是 ${tableMax} —— 表必须覆盖最贵的那条路径`)
  assert.equal(corpusMaxId, 'legacy-tools-call-credential-gated', '最贵的那条必须是表里第五行钉住的那条')

  assert.equal(CURRENT_MAX_REQUESTS - corpusMax, 2, '当前预算对全语料最坏路径的余量：8 − 6 = 2 次。预算或最坏路径任一变化，这条都会红')
})

console.log('\nT6.9-F round 2：全语料最贵路径（legacy 握手全通 + tools/call 被凭据门挡住 + metadata 抓取）的判定语义，而不只是它的计数')

await t('legacy-tools-call-credential-gated @ 当前预算：6 次请求跑完整轮 —— reachability VERIFIED，被挡的 tools/call 得出的是 auth_metadata 的正常结论，而不是一次 cascade', async () => {
  const { result, requests } = await runWithBudget('legacy-tools-call-credential-gated', CURRENT_MAX_REQUESTS)
  assert.equal(requests, 6)
  assert.equal(cascadeCompleted(result), true, '预算 8 下这条路径必须跑完，不得有任何一条 check 因中止而没产出')

  const byId = (id: string) => result.assertions.find((a) => a.check_id === id)!
  assert.equal(byId('reachability').execution_status, 'COMPLETED')
  assert.equal(byId('reachability').assertion_status, 'VERIFIED')
  // tools/call 被挡不得污染前面已经真实验证过的握手与工具清单。
  for (const check_id of ['discovery_handshake', 'protocol_revision', 'tools_list', 'toolset_fingerprint', 'schema_fingerprint']) {
    assert.equal(byId(check_id).assertion_status, 'VERIFIED', check_id)
  }
  // 凭据门走到它的正常结论：challenge 合法、resource_metadata 文档取到且自洽。
  assert.equal(byId('auth_metadata').execution_status, 'COMPLETED')
  assert.equal(byId('auth_metadata').assertion_status, 'VERIFIED', 'challenge 合法且 metadata 文档自洽时，auth_metadata 是 VERIFIED，不是 UNVERIFIED')
  // 反向：一次 HTTP 层的 401 不是协议错误形状问题。
  assert.equal(byId('error_taxonomy').assertion_status, 'VERIFIED')
  // 而且这一整轮里没有任何一条对目标的指控。
  for (const a of result.assertions) {
    assert.notEqual(a.assertion_status, 'FAILED', `${a.check_id}`)
    assert.notEqual(a.assertion_status, 'OBSERVED_RISK', `${a.check_id}`)
  }
})

for (const maxRequests of [4, 5]) {
  await t(`legacy-tools-call-credential-gated @ maxRequests=${maxRequests}：必须中止，没跑到的检查带 probe_budget_exhausted_requests {maxRequests:${maxRequests}}，且该理由在两种语言下都真的渲染得出来`, async () => {
    const { result, requests } = await runWithBudget('legacy-tools-call-credential-gated', maxRequests)
    assert.equal(requests, maxRequests, '预算用尽即停')
    assert.equal(cascadeCompleted(result), false, `${maxRequests} 次预算跑不完这条 6 次的路径`)

    // 握手在中止之前就成功了，所以可达性仍然是已判定的。
    assert.equal(result.assertions.find((a) => a.check_id === 'reachability')!.assertion_status, 'VERIFIED')

    const aborted = result.assertions.filter((a) => a.unverified_reason?.key === 'probe_budget_exhausted_requests')
    assert.ok(aborted.length > 0, '没跑到的检查必须说出「为什么没跑」')
    // auth_metadata 是这条路径上最后一步，任何一档不足的预算都轮不到它。
    assert.ok(aborted.some((a) => a.check_id === 'auth_metadata'), 'auth_metadata 必须在没跑到的那一组里')
    for (const a of aborted) {
      assert.equal(a.execution_status, 'SKIPPED')
      assert.deepEqual(a.unverified_reason!.params, { maxRequests })
      for (const locale of ['en', 'zh'] as const) {
        // 只比 key 的断言会绿，而报告页会抛 —— 这里真的渲染一遍。
        const rendered = REASON_MESSAGES[a.unverified_reason!.key]![locale](a.unverified_reason!.params)
        assert.ok(rendered.includes(String(maxRequests)), `${a.check_id}/${locale}: 渲染结果里应当出现真实预算数值，实际是 ${rendered}`)
      }
    }
  })
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
