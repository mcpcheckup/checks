import assert from 'node:assert'
import { digest } from './digest.ts'
import { CanonicalizationError } from './errors.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('digest')

await t('返回 "sha256:" 前缀 + 64 位小写 hex', async () => {
  const d = await digest({ a: 1 })
  assert.match(d, /^sha256:[0-9a-f]{64}$/)
})

await t('已知向量：canonicalize(null) === "null"，其 SHA-256 是可独立核对的固定值', async () => {
  // echo -n 'null' | sha256sum
  const d = await digest(null)
  assert.equal(d, 'sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b')
})

await t('相同数据、不同键顺序 → 相同 digest', async () => {
  const a = await digest({ z: 1, a: 2 })
  const b = await digest({ a: 2, z: 1 })
  assert.equal(a, b)
})

await t('不同数据 → 不同 digest', async () => {
  const a = await digest({ a: 1 })
  const b = await digest({ a: 2 })
  assert.notEqual(a, b)
})

await t('canonicalize 会抛的错误原样透传（不吞掉、不包装成别的东西）', async () => {
  try {
    await digest(undefined)
    assert.fail('expected to throw')
  } catch (e) {
    assert.ok(e instanceof CanonicalizationError)
    assert.equal(e.code, 'UNSUPPORTED_TYPE')
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
