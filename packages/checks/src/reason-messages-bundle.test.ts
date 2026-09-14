import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// 与本包其余 *.test.ts 同一个约定：计数 + 末尾一行 "N passed, M failed" +
// process.exitCode。round 18 之前这里是 fail-fast（catch 里 rethrow），于是这个
// 文件从不打印汇总行——任何按汇总行统计断言数的人都会**静默漏掉**这 1 条。
let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log(`  ok   ${name}`) }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${(e as Error).stack}`) }
}

async function main() {
  console.log('reason-messages: zero wire.ts/protocol.ts/probe.ts dependency (Workers bundle hygiene)')

  await t('reason-messages.ts has no import from ./wire.ts, ./protocol.ts, or ./probe.ts', () => {
    const src = readFileSync(fileURLToPath(new URL('./reason-messages.ts', import.meta.url)), 'utf8')
    const importLines = src.split('\n').filter((l) => /^\s*import\b/.test(l))
    for (const line of importLines) {
      assert.ok(!/['"]\.\/wire\.ts['"]/.test(line), `forbidden import: ${line}`)
      assert.ok(!/['"]\.\/protocol\.ts['"]/.test(line), `forbidden import: ${line}`)
      assert.ok(!/['"]\.\/probe\.ts['"]/.test(line), `forbidden import: ${line}`)
    }
    // reason-messages.ts as implemented in Step 3 has ZERO import statements
    // at all (pure data + pure functions) — this also asserts that, so a
    // future edit can't quietly add a dependency without this test noticing.
    assert.equal(importLines.length, 0, 'reason-messages.ts should have no imports at all — pure data/functions only')
  })

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exitCode = fail ? 1 : 0
}

main().catch((e) => { console.error(e); process.exit(1) })
