import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

// 这个文件测的是 property.test.ts 里 FC_SEED 的读取/校验/传递逻辑本身
// （见该文件顶部），不是 canonicalize/digest 的任何性质——所以放在一个独立
// 的 *.test.ts 里，用子进程调用 property.test.ts 自己的 FC_SEED_SELFTEST
// 分支（一个内联的、故意必败的性质，只在这个环境变量下才跑）。

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const propertyTestFile = fileURLToPath(new URL('./property.test.ts', import.meta.url))

function runPropertyTest(extraEnv: Record<string, string>) {
  return spawnSync(process.execPath, [propertyTestFile], {
    encoding: 'utf8',
    env: { ...process.env, ...extraEnv },
  })
}

console.log('property-seed: FC_SEED 的可复现性（子进程调用 property.test.ts 自身）')

await t('FC_SEED=N 时，内联必败性质的失败报告里含 seed: N（防 MS1：FC_SEED 被读取但没传给 fast-check）', () => {
  // 取一个落在 int32 范围内的种子——fast-check 的 readSeed 对落在这个范围内
  // 的种子原样保留，这样断言可以直接找字面量，不用重新实现它的种子变换。
  const seed = 123456789
  const result = runPropertyTest({ FC_SEED: String(seed), FC_SEED_SELFTEST: '1' })
  assert.equal(result.status, 0, `selftest subprocess should exit 0, got ${result.status}\nstderr:\n${result.stderr}`)
  assert.ok(
    result.stdout.includes(`seed: ${seed}`),
    `expected stdout to contain "seed: ${seed}", got:\n${result.stdout}`,
  )
})

await t('FC_SEED 不是安全整数时，大声失败，报错点名 FC_SEED 和坏值', () => {
  const badValue = 'not-a-seed'
  const result = runPropertyTest({ FC_SEED: badValue })
  assert.notEqual(result.status, 0, 'invalid FC_SEED should make the process exit non-zero')
  assert.ok(result.stderr.includes('FC_SEED'), `expected stderr to name FC_SEED, got:\n${result.stderr}`)
  assert.ok(
    result.stderr.includes(badValue),
    `expected stderr to include the bad value ${JSON.stringify(badValue)}, got:\n${result.stderr}`,
  )
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
