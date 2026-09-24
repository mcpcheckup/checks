import assert from 'node:assert'
import { runProbe } from './probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { modernBaselineClean } from '@mcpcheckup/fixtures'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { FetchLike, ProbeInput } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

function makeInput(fetchImpl: FetchLike): ProbeInput {
  let seq = 0
  return {
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: 'https://notes-mcp.example.com/mcp' },
    fetchImpl,
    budget: DEFAULT_PROBE_BUDGET,
    now: () => '2026-08-18T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  }
}

console.log('runProbe：生产 fetchImpl 适配层通过 onGuardSignal 回调（带外信道）报告 dnsAnswerChangedDuringProbe')

await t('onGuardSignal 一旦报告过一次 dnsAnswerChanged，disqualifiedFromPublication 被设置；不影响 redirect_policy（DNS 变化不是重定向）；不阻止已完成的连接（其它 check 不受影响）', async () => {
  const inner = modernBaselineClean.createHandler()
  let seenCalls = 0
  const fetchImpl: FetchLike = async (input, init, onGuardSignal) => {
    seenCalls++
    // 模拟生产适配层：只在第一次请求（discover）之后，通过 guardedFetch 自己的
    // DNS 重解析结果报告变化——不是从目标的响应里读任何东西。
    if (seenCalls === 1) onGuardSignal({ dnsAnswerChanged: true })
    return inner(input, init)
  }
  const result = await runProbe(makeInput(fetchImpl))
  assert.deepEqual(result.disqualifiedFromPublication, { key: 'disqualified_dns_rebind' })
  // 这也是唯一让 ProbeResult.dnsAnswerChangedObserved 变成 true 的路径——
  // 映射到 @mcpcheckup/attestation-schema 的 probe_dns_answer_changed（运行条件，不是 check）。
  assert.equal(result.dnsAnswerChangedObserved, true)
  // DNS 答案变化不是重定向：没有发生任何跨主机跳转，redirect_policy 仍是 VERIFIED。
  const redirectPolicy = result.assertions.find((a) => a.check_id === 'redirect_policy')!
  assert.equal(redirectPolicy.assertion_status, 'VERIFIED')
  // 连接本身没有被阻止——其余 check 依然正常完成，不是全部级联成 UNVERIFIED。
  const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
  assert.equal(reachability.assertion_status, 'VERIFIED')
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.equal(toolsList.assertion_status, 'VERIFIED')
})

await t('反例：onGuardSignal 从未报告过 dnsAnswerChanged 时，disqualifiedFromPublication 不存在，dnsAnswerChangedObserved 是明确的 false（不是 null——这是个 remote target，观察确实发生了，结论是"没变"）', async () => {
  const inner = modernBaselineClean.createHandler()
  const fetchImpl: FetchLike = async (input, init) => inner(input, init)
  const result = await runProbe(makeInput(fetchImpl))
  assert.equal(result.disqualifiedFromPublication, undefined)
  assert.equal(result.dnsAnswerChangedObserved, false)
})

await t('安全回归：目标在响应头里伪造 x-mcpcheckup-dns-answer-changed: true 完全不生效——这个信号现在只能通过 onGuardSignal 报告，目标控制的 Response 不再是任何信道', async () => {
  const inner = modernBaselineClean.createHandler()
  const fetchImpl: FetchLike = async (input, init) => {
    const res = await inner(input, init)
    const headers = new Headers(res.headers)
    headers.set('x-mcpcheckup-dns-answer-changed', 'true')
    return new Response(res.body, { status: res.status, headers })
  }
  const result = await runProbe(makeInput(fetchImpl))
  assert.equal(result.disqualifiedFromPublication, undefined, '目标伪造响应头不得触发 disqualifiedFromPublication')
  assert.equal(result.dnsAnswerChangedObserved, false, '目标伪造响应头也不得让 dnsAnswerChangedObserved 变成 true')
})

console.log('\nrunProbe：被截止时间中止的请求（TODO 458 R1 ⑤）')

// Budget small enough to cut the second request; the first stays well inside.
const SHORT_BUDGET = { ...DEFAULT_PROBE_BUDGET, maxDurationMs: 300 }
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** Request 2 outlives the budget; once it finally returns it reports a DNS
 *  change and hands back a response whose body read is counted. */
function lateSecondRequest(signalOnFirst: boolean) {
  const inner = modernBaselineClean.createHandler()
  const state = { calls: 0, lateSignalDelivered: false, lateBodyReads: 0 }
  const fetchImpl: FetchLike = async (input, init, onGuardSignal) => {
    state.calls++
    if (state.calls === 1) {
      if (signalOnFirst) onGuardSignal({ dnsAnswerChanged: true })
      return inner(input, init)
    }
    await sleep(600)
    onGuardSignal({ dnsAnswerChanged: true })
    state.lateSignalDelivered = true
    const res = await inner(input, init)
    return { status: res.status, headers: res.headers, text: () => { state.lateBodyReads++; return res.text() } } as unknown as Response
  }
  return { fetchImpl, state }
}

await t('中止之后报告的 DNS 变化不产生任何结果：disqualifiedFromPublication 不存在、dnsAnswerChangedObserved 为 false、那个迟到的响应一个字节都没读；中止照常记为 probe_budget_exhausted_duration', async () => {
  const { fetchImpl, state } = lateSecondRequest(false)
  const result = await runProbe({ ...makeInput(fetchImpl), budget: SHORT_BUDGET })
  await sleep(700) // 让迟到的那次调用跑完、把信号报出来
  assert.equal(state.lateSignalDelivered, true, '前提：迟到的信号确实被报告了')
  assert.equal(state.lateBodyReads, 0, '被中止的响应一个字节都不读')
  assert.equal(result.disqualifiedFromPublication, undefined)
  assert.equal(result.dnsAnswerChangedObserved, false)
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.deepEqual([toolsList.execution_status, toolsList.reason], ['SKIPPED', { key: 'probe_budget_exhausted_duration', params: { maxDurationMs: 300 } }])
  const reachability = result.assertions.find((a) => a.check_id === 'reachability')!
  assert.equal(reachability.assertion_status, 'VERIFIED', '第一个请求在预算内完成，reachability 已有答案')
})

await t('对照：在预算内完成的更早请求报告的 DNS 变化，即使本轮随后被截止时间中止，依然取消发布资格（被丢弃的只是中止之后的信号）', async () => {
  const { fetchImpl } = lateSecondRequest(true)
  const result = await runProbe({ ...makeInput(fetchImpl), budget: SHORT_BUDGET })
  assert.deepEqual(result.disqualifiedFromPublication, { key: 'disqualified_dns_rebind' })
  assert.equal(result.dnsAnswerChangedObserved, true)
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.equal(toolsList.reason?.key, 'probe_budget_exhausted_duration')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
