import assert from 'node:assert'
import { runProbe } from './probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { ProbeInput } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('runProbe：target.transport = stdio（当前实现范围之外，见 README）')

await t('stdio target：不调用 fetchImpl 一次，全部 15 条 check 都是 SKIPPED/UNVERIFIED，没有一条静默缺失', async () => {
  let calls = 0
  const input: ProbeInput = {
    target: { slug: 'example/local-tool', transport: 'stdio', packageRef: 'example-local-tool@1.0.0' },
    fetchImpl: async () => {
      calls++
      return new Response('unexpected call')
    },
    budget: DEFAULT_PROBE_BUDGET,
    now: () => '2026-08-18T00:00:00.000Z',
    newId: () => 'probe-1',
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  }
  const result = await runProbe(input)
  assert.equal(calls, 0, 'stdio target 不应该触发任何 fetchImpl 调用')
  assert.equal(result.assertions.length, CHECKS_REGISTRY.checks.length)
  // stdio 不做 DNS 解析，没有可观察的东西——null 表示"不适用"，不是 false（"适用但没变"）。
  assert.equal(result.dnsAnswerChangedObserved, null)
  // stdio 从不进入 performHandshake，没有握手可言，protocolRevisionDeclared 保持 null。
  assert.equal(result.protocolRevisionDeclared, null)
  for (const a of result.assertions) {
    assert.equal(a.execution_status, 'SKIPPED')
    assert.equal(a.assertion_status, 'UNVERIFIED')
    assert.ok(a.reason && typeof a.reason.key === 'string' && a.reason.key.length > 0)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
