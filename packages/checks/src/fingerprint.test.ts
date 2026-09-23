import assert from 'node:assert'
import { computeToolsetFingerprint, computeSchemaFingerprint, buildToolSnapshot } from './fingerprint.ts'
import { modernBaselineClean, crossLayerHashMismatch, largeToolsetNestedSchemas } from '@mcpcheckup/fixtures'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('computeToolsetFingerprint / computeSchemaFingerprint：针对真实 fixture 工具集')

await t('modern-baseline-clean：两者都算得出，格式是 sha256:<64 hex>', async () => {
  const toolset = await computeToolsetFingerprint(modernBaselineClean.tools!)
  const schema = await computeSchemaFingerprint(modernBaselineClean.tools!)
  assert.equal(toolset.status, 'VERIFIED')
  assert.equal(schema.status, 'VERIFIED')
  assert.match((toolset as { fingerprint: string }).fingerprint, /^sha256:[0-9a-f]{64}$/)
  assert.match((schema as { fingerprint: string }).fingerprint, /^sha256:[0-9a-f]{64}$/)
})

await t('cross-layer-hash-mismatch：toolset 算得出（只需要 name），schema 算不出（有工具缺 inputSchema）→ FAILED', async () => {
  const toolset = await computeToolsetFingerprint(crossLayerHashMismatch.tools!)
  const schema = await computeSchemaFingerprint(crossLayerHashMismatch.tools!)
  assert.equal(toolset.status, 'VERIFIED')
  assert.equal(schema.status, 'FAILED')
  // T73b: the FAILED reason is a bounded catalog key now, not the raw
  // canonicalizer message (inputSchema missing ⇒ UNSUPPORTED_TYPE).
  assert.deepStrictEqual((schema as { reason: unknown }).reason, { key: 'fingerprint_canonicalize_failed' })
})

console.log('\nT73b：FAILED 的 reason 按错误类分类，只有两个 key、没有 params，错误原文（含第三方键名）一个字也不留')

await t('缺 name（TypeError，来自 requireToolName）→ 两个指纹都是 fingerprint_tool_missing_name', async () => {
  const tools = [{ name: 'ok', inputSchema: {} }, { inputSchema: {} }]
  assert.deepStrictEqual(await computeToolsetFingerprint(tools), { status: 'FAILED', reason: { key: 'fingerprint_tool_missing_name' } })
  assert.deepStrictEqual(await computeSchemaFingerprint(tools), { status: 'FAILED', reason: { key: 'fingerprint_tool_missing_name' } })
})

await t('name 不是字符串 / 工具不是对象 → fingerprint_tool_missing_name', async () => {
  for (const tools of [[{ name: 7, inputSchema: {} }], [null], ['a'], [[]]]) {
    assert.deepStrictEqual(await computeToolsetFingerprint(tools), { status: 'FAILED', reason: { key: 'fingerprint_tool_missing_name' } }, JSON.stringify(tools))
  }
})

await t('CanonicalizationError（孤立代理项 / 1e400 / NFC 重键）与 RangeError（极深嵌套）→ fingerprint_canonicalize_failed，且 reason 里不含第三方键名', async () => {
  let deep: unknown = {}
  for (let i = 0; i < 200_000; i++) deep = { d: deep }
  const cases: [string, unknown[]][] = [
    ['lone surrogate in name', [{ name: 'a\ud800', inputSchema: {} }]],
    ['non-finite number', [{ name: 'a', inputSchema: { max: Infinity } }]],
    ['NFC-duplicate keys', [{ name: 'a', inputSchema: { 'CANARYé': 1, 'CANARYé': 2 } }]],
    ['deep nesting', [{ name: 'a', inputSchema: deep }]],
  ]
  for (const [label, tools] of cases) {
    const schema = await computeSchemaFingerprint(tools)
    assert.deepStrictEqual(schema, { status: 'FAILED', reason: { key: 'fingerprint_canonicalize_failed' } }, label)
  }
  assert.deepStrictEqual(await computeToolsetFingerprint([{ name: 'a\ud800' }]), { status: 'FAILED', reason: { key: 'fingerprint_canonicalize_failed' } })
})

await t('large-toolset-nested-schemas：多层嵌套 + 8 个工具下两者依然稳定算得出', async () => {
  const toolset = await computeToolsetFingerprint(largeToolsetNestedSchemas.tools!)
  const schema = await computeSchemaFingerprint(largeToolsetNestedSchemas.tools!)
  assert.equal(toolset.status, 'VERIFIED')
  assert.equal(schema.status, 'VERIFIED')
})

await t('反例：同一份工具集重复计算得到相同指纹（确定性）', async () => {
  const a = await computeToolsetFingerprint(modernBaselineClean.tools!)
  const b = await computeToolsetFingerprint(modernBaselineClean.tools!)
  assert.equal((a as { fingerprint: string }).fingerprint, (b as { fingerprint: string }).fingerprint)
})

console.log('\nbuildToolSnapshot')

await t('modern-baseline-clean：每个工具都有 name/description/inputSchema/hash', async () => {
  const snap = await buildToolSnapshot(modernBaselineClean.tools!, '2026-08-18T00:00:00.000Z')
  assert.equal(snap.observed_at, '2026-08-18T00:00:00.000Z')
  assert.equal(snap.tools.length, 2)
  for (const entry of snap.tools) {
    assert.equal(typeof entry.name, 'string')
    assert.match(entry.hash!, /^sha256:[0-9a-f]{64}$/)
  }
  assert.match(snap.toolset_fingerprint!, /^sha256:[0-9a-f]{64}$/)
  assert.match(snap.schema_fingerprint!, /^sha256:[0-9a-f]{64}$/)
})

await t('cross-layer-hash-mismatch：缺 inputSchema 的那个工具 hash 为 null，其余工具的 hash 仍然算得出', async () => {
  const snap = await buildToolSnapshot(crossLayerHashMismatch.tools!, '2026-08-18T00:00:00.000Z')
  const archived = snap.tools.find((e) => e.name === 'archive_note')
  assert.equal(archived?.hash, null)
  const others = snap.tools.filter((e) => e.name !== 'archive_note')
  assert.ok(others.every((e) => e.hash !== null))
  assert.equal(snap.schema_fingerprint, null, '聚合 schema_fingerprint 在有工具算不出时也是 null')
  assert.match(snap.toolset_fingerprint!, /^sha256:[0-9a-f]{64}$/)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
