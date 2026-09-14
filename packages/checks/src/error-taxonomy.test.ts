import assert from 'node:assert'
import { judgeErrorTaxonomy } from './error-taxonomy.ts'
import { performHandshake, performUnknownToolCall } from './protocol.ts'
import { createProbeContext } from './wire.ts'
import { modernBaselineClean, errorResponseNonconformantShape, noCredentialsUnverifiableAuth } from '@mcpcheckup/fixtures'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const BUDGET: ProbeBudget = { maxRedirects: 3, maxDurationMs: 10_000, maxBodyBytes: 2_097_152, maxRequests: 8 }
let seq = 0
const newId = () => `probe-${++seq}`
const ENDPOINT = 'https://notes-mcp.example.com/mcp'

async function callResultFor(fixture: { createHandler: () => import('@mcpcheckup/fixtures').FetchHandler }) {
  const fetchImpl = fixture.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: ENDPOINT, budget: BUDGET, ctx, newId })
  return performUnknownToolCall({ fetchImpl, budget: BUDGET, ctx, newId, handshake, toolName: '__mcpcheckup_probe_nonexistent_tool__' })
}

console.log('judgeErrorTaxonomy：针对真实 fixture handler')

await t('modern-baseline-clean：合法 JSON-RPC 错误响应 → VERIFIED', async () => {
  const callResult = await callResultFor(modernBaselineClean)
  const v = judgeErrorTaxonomy(callResult)
  assert.equal(v.status, 'VERIFIED')
})

await t('error-response-nonconformant-shape：纯文本 500 → OBSERVED_RISK', async () => {
  const callResult = await callResultFor(errorResponseNonconformantShape)
  const v = judgeErrorTaxonomy(callResult)
  assert.equal(v.status, 'OBSERVED_RISK')
  if (v.status !== 'OBSERVED_RISK') throw new Error('unreachable')
  assert.deepEqual(v.reason, { key: 'error_taxonomy_risk' })
})

await t('no-credentials-unverifiable-auth：裸 401 是 JSON-RPC 分发之前的合法拒绝，不算错误形状问题 → VERIFIED', async () => {
  const callResult = await callResultFor(noCredentialsUnverifiableAuth)
  const v = judgeErrorTaxonomy(callResult)
  assert.equal(v.status, 'VERIFIED')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
