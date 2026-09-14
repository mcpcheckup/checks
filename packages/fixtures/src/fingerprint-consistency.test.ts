import assert from 'node:assert'
import { projectToolset, projectSchemas, digest } from '@mcpcheckup/canonicalizer'
import { FIXTURE_CORPUS } from './index.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('fingerprint-consistency：toolset_fingerprint / schema_fingerprint 的期望值不是手写猜的，是真的算出来的')
console.log('（复用 @mcpcheckup/canonicalizer 的 projectToolset / projectSchemas / digest —— 不在这里重新实现一遍投影逻辑）')

async function computable(fn: () => unknown): Promise<boolean> {
  try {
    const projected = fn()
    await digest(projected)
    return true
  } catch {
    return false
  }
}

for (const fixture of FIXTURE_CORPUS) {
  if (fixture.tools === undefined) continue

  const toolsetExpectation = fixture.expectedAssertions.find((a) => a.check_id === 'toolset_fingerprint')
  if (toolsetExpectation) {
    await t(`${fixture.id}: toolset_fingerprint 的期望 assertion_status 与真实 projectToolset+digest 的可计算性一致`, async () => {
      const ok = await computable(() => projectToolset(fixture.tools!))
      const expectedOk = toolsetExpectation.assertion_status === 'VERIFIED'
      assert.equal(ok, expectedOk, `${fixture.id}: projectToolset+digest 实际${ok ? '成功' : '失败'}，但声明的是 ${toolsetExpectation.assertion_status}`)
    })
  }

  const schemaExpectation = fixture.expectedAssertions.find((a) => a.check_id === 'schema_fingerprint')
  if (schemaExpectation) {
    await t(`${fixture.id}: schema_fingerprint 的期望 assertion_status 与真实 projectSchemas+digest 的可计算性一致`, async () => {
      const ok = await computable(() => projectSchemas(fixture.tools!))
      const expectedOk = schemaExpectation.assertion_status === 'VERIFIED'
      assert.equal(ok, expectedOk, `${fixture.id}: projectSchemas+digest 实际${ok ? '成功' : '失败'}，但声明的是 ${schemaExpectation.assertion_status}`)
    })
  }
}

// `await` 是必须的，不是风格：这条回调是 async，漏掉 await 时它的拒绝会在汇总行与
// process.exitCode 之后才被 catch 到——实测退出码 0、却打印了一行 FAIL，整套测试照样
// 绿。而它恰恰是**用来证明本文件不是恒真断言**的那条反例（守卫设计原则 #6，round 18e）。
await t('反例：这条测试确实会抓到不一致——用一份真的会让 projectSchemas 抛错的工具集手工验证', async () => {
  const brokenTools = [{ name: 'a' }] // 缺 inputSchema
  const ok = await computable(() => projectSchemas(brokenTools))
  assert.equal(ok, false, '这份工具集本该让 projectSchemas+digest 失败，如果它成功了说明这条一致性检查本身失去了区分力')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
