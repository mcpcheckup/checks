import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

// SHARD_INDEX / SHARD_COUNT 是模块级常量（解析即校验），所以只能靠子进程
// import differential-shard.ts 本身来观察它抛不抛——同一进程里 import 一次
// 就定型了，没法用不同环境变量重新触发解析。

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const shardModuleFile = fileURLToPath(new URL('./differential-shard.ts', import.meta.url))

function runWithEnv(overrides: Record<string, string | undefined>) {
  const env = { ...process.env }
  delete env.SHARD_INDEX
  delete env.SHARD_COUNT
  for (const [k, v] of Object.entries(overrides)) if (v !== undefined) env[k] = v
  return spawnSync(process.execPath, [shardModuleFile], { encoding: 'utf8', env })
}

console.log('differential-shard：SHARD_INDEX / SHARD_COUNT 环境变量校验（子进程，模块级常量）')

await t('两者都未设置：默认 index=0 count=1，不抛错', () => {
  const r = runWithEnv({})
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}\nstderr:\n${r.stderr}`)
})

await t('反例：合法的分片配置（index=1, count=2）不抛错', () => {
  const r = runWithEnv({ SHARD_INDEX: '1', SHARD_COUNT: '2' })
  assert.equal(r.status, 0, `expected exit 0, got ${r.status}\nstderr:\n${r.stderr}`)
})

await t('SHARD_COUNT=0：抛错，点名变量与原值', () => {
  const r = runWithEnv({ SHARD_COUNT: '0' })
  assert.notEqual(r.status, 0)
  assert.ok(r.stderr.includes('SHARD_COUNT') && r.stderr.includes('"0"'), `stderr:\n${r.stderr}`)
})

await t('SHARD_COUNT=abc：非数字，抛错，点名变量与原值', () => {
  const r = runWithEnv({ SHARD_COUNT: 'abc' })
  assert.notEqual(r.status, 0)
  assert.ok(r.stderr.includes('SHARD_COUNT') && r.stderr.includes('"abc"'), `stderr:\n${r.stderr}`)
})

await t('SHARD_INDEX=2, SHARD_COUNT=2：越界（index 必须 < count），抛错，点名变量与原值', () => {
  const r = runWithEnv({ SHARD_INDEX: '2', SHARD_COUNT: '2' })
  assert.notEqual(r.status, 0)
  assert.ok(r.stderr.includes('SHARD_INDEX') && r.stderr.includes('"2"'), `stderr:\n${r.stderr}`)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
