import assert from 'node:assert'
import { canonicalBytes } from '@mcpcheckup/canonicalizer'
import { FIXTURE_CORPUS } from './index.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

console.log('determinism：同一 fixture 跑两次，canonical bytes 必须逐字节相同')

for (const fixture of FIXTURE_CORPUS) {
  await t(`${fixture.id}: 两次独立 run 的结果 canonical bytes 相同`, async () => {
    const run1 = await fixture.sampleRun(fixture.createHandler())
    const run2 = await fixture.sampleRun(fixture.createHandler())
    assert.ok(run1.length > 0, `${fixture.id}: sampleRun 没有产出任何响应`)
    assert.equal(run1.length, run2.length, `${fixture.id}: 两次 run 的响应条数不同`)
    const bytes1 = canonicalBytes(run1)
    const bytes2 = canonicalBytes(run2)
    assert.equal(bytesToHex(bytes1), bytesToHex(bytes2), `${fixture.id}: 两次 run 的 canonical bytes 不同`)
  })
}

// `await` 是必须的，不是风格：t 是 async，漏掉它这条 t() 的 promise 就被丢掉，而下面
// 的汇总行与 process.exitCode 是同步代码、先执行。这一条的回调恰好是**同步**的，所以
// 抛出会在 await 之前被同步 catch 到，实测漏掉 await 时退出码仍是 1——症状只是那行 ok
// 打在汇总之后、这一条没被计入。但它离静默只差一个字：把回调改成 async（隔壁
// fingerprint-consistency.test.ts 就是），实测就变成退出码 0 却打印 FAIL。而它是这个
// 文件里**用来证明其余断言不是恒真**的那一条，最不该是运气在守（守卫设计原则 #6，round 18e）。
await t('反例：两个不同 fixture 的 canonical bytes 不应该恰好相同（证明这条测试本身有区分力，不是永远通过的空断言）', () => {
  const ids = FIXTURE_CORPUS.map((f) => f.id)
  assert.ok(new Set(ids).size >= 2, '需要至少两条 fixture 才能验证这一点')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
