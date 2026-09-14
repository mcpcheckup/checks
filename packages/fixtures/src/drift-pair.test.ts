import assert from 'node:assert'
import { digest, projectToolset } from '@mcpcheckup/canonicalizer'
import { toolsetDriftRun1, toolsetDriftRun2 } from './index.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('drift-pair：toolset-drift-run-1 / toolset-drift-run-2 之间的跨 fixture 关系')
console.log('（drift_event 是跨两次 run 的产品概念，不是 checks.json 里的某个 check_id，所以单独用这份测试验证，不硬塞进 expectedAssertions）')

await t('两次观测的 toolset_fingerprint 真的不同（这才是"有变化"这件事本身要证明的）', async () => {
  const fp1 = await digest(projectToolset(toolsetDriftRun1.tools!))
  const fp2 = await digest(projectToolset(toolsetDriftRun2.tools!))
  assert.notEqual(fp1, fp2, 'run-2 新增了一个工具，指纹必须跟着变，否则这条 fixture 没有测试意义')
})

await t('两次观测各自的 toolset_unchanged_vs_approved 依然是 UNVERIFIED——变化本身不影响"有没有基线"这件事', () => {
  for (const fixture of [toolsetDriftRun1, toolsetDriftRun2]) {
    const a = fixture.expectedAssertions.find((x) => x.check_id === 'toolset_unchanged_vs_approved')
    assert.ok(a, `${fixture.id} 缺少 toolset_unchanged_vs_approved`)
    assert.equal(a!.assertion_status, 'UNVERIFIED')
    assert.notEqual(a!.assertion_status, 'FAILED', 'CLAUDE.md 硬规则：无基线时的变化绝不能被判 FAILED')
  }
})

await t('反例：把 run-1 的 tools 复制两份比对，指纹必须相同（证明上面那条"不同"的测试不是永远为真的空断言）', async () => {
  const fp1 = await digest(projectToolset(toolsetDriftRun1.tools!))
  const fp1Again = await digest(projectToolset([...toolsetDriftRun1.tools!]))
  assert.equal(fp1, fp1Again)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
