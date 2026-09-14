import assert from 'node:assert'
import { canonicalize, canonicalBytes } from './canonicalize.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('交叉一致性：同一份数据，键顺序打乱前后必须算出完全相同的字节')

function buildInOrder(keys: string[]): Record<string, unknown> {
  const obj: Record<string, unknown> = {}
  for (const k of keys) obj[k] = { key: k, nested: { value: k.length, list: [1, 2, k] } }
  return obj
}

t('顶层键顺序打乱 → canonicalize 结果字符串完全相同', () => {
  const forward = buildInOrder(['zebra', 'apple', 'mango', 'banana', '1', '10', '2'])
  const shuffled = buildInOrder(['10', 'banana', '2', 'zebra', '1', 'mango', 'apple'])
  assert.equal(canonicalize(forward), canonicalize(shuffled))
})

t('嵌套对象的键顺序打乱 → 结果相同', () => {
  const a = { outer: { z: 1, a: 2, m: { y: 1, b: 2 } } }
  const b = { outer: { a: 2, m: { b: 2, y: 1 }, z: 1 } }
  assert.equal(canonicalize(a), canonicalize(b))
})

t('canonicalBytes 同样具有这个性质（字节级）', () => {
  const forward = buildInOrder(['c', 'a', 'b'])
  const shuffled = buildInOrder(['b', 'c', 'a'])
  const bytesA = canonicalBytes(forward)
  const bytesB = canonicalBytes(shuffled)
  assert.deepEqual([...bytesA], [...bytesB])
})

t('插入顺序不影响结果，即便键是整数形式字符串（容易被 JS 对象枚举顺序坑）', () => {
  // JS 对普通对象的整数形字符串键有特殊枚举顺序（按数值升序排在最前面），
  // 但 RFC 8785 要求纯 UTF-16 码元字典序（"10" < "2"）。用两种不同插入顺序
  // 构造同一份逻辑数据，确认两者都被拉回同一个字典序结果，而不是抄了 JS 的默认枚举顺序。
  const objA: Record<string, number> = {}
  objA['2'] = 1
  objA['10'] = 2
  objA['d'] = 3

  const objB: Record<string, number> = {}
  objB['d'] = 3
  objB['10'] = 2
  objB['2'] = 1

  const result = canonicalize(objA)
  assert.equal(result, canonicalize(objB))
  assert.equal(result, '{"10":2,"2":1,"d":3}', '必须是字典序 "10"<"2"<"d"，不是数值序')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
