import assert from 'node:assert'
import { runProbe } from './probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { computeToolsetFingerprint, computeSchemaFingerprint } from './fingerprint.ts'
import { modernBaselineClean } from '@mcpcheckup/fixtures'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { ProbeInput } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

function makeInput(overrides: Partial<ProbeInput> = {}): ProbeInput {
  let seq = 0
  return {
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: 'https://notes-mcp.example.com/mcp' },
    fetchImpl: modernBaselineClean.createHandler(),
    budget: DEFAULT_PROBE_BUDGET,
    now: () => '2026-08-18T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...overrides,
  }
}

console.log('runProbe：approvedBaseline 决定「有无基线」语义（CLAUDE.md 硬规则）')

await t('无 approvedBaseline：两条 *_unchanged_vs_approved 都是 SKIPPED/UNVERIFIED，不产出 driftEvents', async () => {
  const result = await runProbe(makeInput())
  const a = result.assertions.find((x) => x.check_id === 'toolset_unchanged_vs_approved')!
  const b = result.assertions.find((x) => x.check_id === 'schema_unchanged_vs_approved')!
  assert.equal(a.execution_status, 'SKIPPED')
  assert.equal(a.assertion_status, 'UNVERIFIED')
  assert.equal(b.execution_status, 'SKIPPED')
  assert.equal(b.assertion_status, 'UNVERIFIED')
  assert.equal(result.driftEvents.length, 0)
})

await t('有 approvedBaseline 且与当前指纹一致：两条都是 VERIFIED', async () => {
  const toolsetFp = await computeToolsetFingerprint(modernBaselineClean.tools!)
  const schemaFp = await computeSchemaFingerprint(modernBaselineClean.tools!)
  assert.equal(toolsetFp.status, 'VERIFIED')
  assert.equal(schemaFp.status, 'VERIFIED')
  const result = await runProbe(
    makeInput({
      approvedBaseline: {
        toolset_fingerprint: (toolsetFp as { fingerprint: string }).fingerprint,
        schema_fingerprint: (schemaFp as { fingerprint: string }).fingerprint,
      },
    }),
  )
  const a = result.assertions.find((x) => x.check_id === 'toolset_unchanged_vs_approved')!
  const b = result.assertions.find((x) => x.check_id === 'schema_unchanged_vs_approved')!
  assert.equal(a.assertion_status, 'VERIFIED')
  assert.equal(b.assertion_status, 'VERIFIED')
  assert.equal(result.driftEvents.length, 0)
})

await t('有 approvedBaseline 但与当前指纹不一致：FAILED，且产出对应的 DriftEvent（这是唯一能让这两条 check FAILED 的路径）', async () => {
  const result = await runProbe(
    makeInput({
      approvedBaseline: {
        toolset_fingerprint: 'sha256:' + '0'.repeat(64),
        schema_fingerprint: 'sha256:' + '1'.repeat(64),
      },
    }),
  )
  const a = result.assertions.find((x) => x.check_id === 'toolset_unchanged_vs_approved')!
  const b = result.assertions.find((x) => x.check_id === 'schema_unchanged_vs_approved')!
  assert.equal(a.assertion_status, 'FAILED')
  assert.equal(b.assertion_status, 'FAILED')
  assert.equal(result.driftEvents.length, 2)
  assert.ok(result.driftEvents.some((d) => d.check_id === 'toolset_unchanged_vs_approved' && d.previous_fingerprint === 'sha256:' + '0'.repeat(64)))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
