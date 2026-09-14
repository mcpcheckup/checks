import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import fc from 'fast-check'
import type { JsonValue } from 'fast-check'
import referenceCanonicalize from 'canonicalize'
import { canonicalize } from './canonicalize.ts'

// fast-check 只导出 JsonValue，不导出 JsonArray/JsonObject（虽然它内部这样拆分）；
// 这两个别名照抄它自己 lib/fast-check.d.ts 里的定义，只为了给下面的 letrec 一个精确类型。
type JsonArray = JsonValue[]
type JsonObject = { [key in string]?: JsonValue }

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// canonicalize（npm 包）是 RFC 8785 作者 Erdtman 本人的参考实现，只作为
// devDependency 对拍基准——见 README.md「与参考实现对拍」一节。
const ownPkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as {
  devDependencies: Record<string, string>
}
console.log('differential: 与参考实现逐字节对拍（canonicalize npm 包，RFC 8785 作者本人的实现）')
console.log(`参考实现声明版本范围：canonicalize@${ownPkg.devDependencies.canonicalize}（devDependency，见 package.json；运行时依赖仍为零）`)

// ---- 三个辅助函数刻意不引用 canonicalize.ts 的任何内部函数——这份差分测试
// 的可信度恰恰来自"判定逻辑与被测代码完全独立"，否则测的只是"这份代码与
// 它自己是否一致"，不是"这份代码与规范是否一致"。 ----

function isFullyNFC(value: unknown): boolean {
  if (typeof value === 'string') return value === value.normalize('NFC')
  if (value === null || typeof value !== 'object') return true
  if (Array.isArray(value)) return value.every(isFullyNFC)
  return Object.entries(value as Record<string, unknown>).every(
    ([k, v]) => k === k.normalize('NFC') && isFullyNFC(v),
  )
}

function deepNormalizeToNFC(value: unknown): unknown {
  if (typeof value === 'string') return value.normalize('NFC')
  if (value === null || typeof value !== 'object') return value
  if (Array.isArray(value)) return value.map(deepNormalizeToNFC)
  // Object.fromEntries (like object-literal spread, unlike plain `out[k] = v`
  // bracket assignment) creates real own properties via [[DefineOwnProperty]]
  // instead of going through [[Set]] — that matters here because a key that
  // NFC-normalizes to the literal string "__proto__" would otherwise hit the
  // inherited Object.prototype.__proto__ accessor and get silently dropped
  // (or worse, reassign the object's prototype) instead of becoming an own
  // property. fast-check's dictionaries deliberately generate "__proto__" as
  // a key precisely to catch this class of bug, and it did.
  const entries = Object.entries(value as Record<string, unknown>).map(
    ([k, v]) => [k.normalize('NFC'), deepNormalizeToNFC(v)] as const,
  )
  return Object.fromEntries(entries)
}

// 两个不同的原始键在 NFC 归一化后撞在一起，这条路径本来就该抛
// DUPLICATE_KEY_AFTER_NFC（canonicalize.test.ts 已经单独测过），跟这里要
// 验证的"分歧恰好等于 NFC"是两件不同的事；混进同一个断言只会让失败信息
// 变得含糊，所以生成阶段直接把这类样本筛掉（fc.pre）。
function hasNfcKeyCollision(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(hasNfcKeyCollision)
  const obj = value as Record<string, unknown>
  const seen = new Set<string>()
  for (const k of Object.keys(obj)) {
    const n = k.normalize('NFC')
    if (seen.has(n)) return true
    seen.add(n)
  }
  return Object.values(obj).some(hasNfcKeyCollision)
}

// ---- 生成器：嵌套对象/数组、Unicode（代理对 + 组合字符）、数字边界、空容器、深层嵌套 ----

const finiteNumber = fc.oneof(
  fc.double({ noNaN: true, noDefaultInfinity: true }),
  fc.constantFrom(
    -0, 0, 1, -1,
    1e21, -1e21, 1e-7, -1e-7, 1e-6, -1e-6,
    Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER,
    Number.MAX_VALUE, Number.MIN_VALUE, -Number.MIN_VALUE,
  ),
)

// 组合字符簇：基础字母 + 1~2 个组合附加符号——绝大多数不是 NFC 形式，专门
// 用来把"非 NFC 输入"的出现概率抬高，纯随机 grapheme 很难自然命中这条路径。
const COMBINING_MARKS = ['́', '̀', '̈', '̧', '̃', '̄']
const decomposedCluster = fc
  .tuple(
    fc.constantFrom(..."aeiouncyAEIOUNCY".split('')),
    fc.array(fc.constantFrom(...COMBINING_MARKS), { minLength: 1, maxLength: 2 }),
  )
  .map(([base, marks]) => base + marks.join(''))

const jsonString = fc.oneof(
  { weight: 3, arbitrary: fc.string({ unit: 'grapheme-composite', maxLength: 12 }) },
  { weight: 3, arbitrary: fc.string({ unit: decomposedCluster, minLength: 1, maxLength: 4 }) },
  // 'grapheme' 单元包含跨两个 UTF-16 码元的字符（如 emoji），覆盖"代理对"这个要求
  { weight: 2, arbitrary: fc.string({ unit: 'grapheme', maxLength: 12 }) },
)

const { jsonTree } = fc.letrec<{
  jsonTree: JsonValue
  primitive: JsonValue
  arrayValue: JsonArray
  objectValue: JsonObject
}>((tie) => ({
  jsonTree: fc.oneof(
    { depthSize: 'small', maxDepth: 4 },
    { weight: 4, arbitrary: tie('primitive') },
    { weight: 1, arbitrary: tie('arrayValue') },
    { weight: 1, arbitrary: tie('objectValue') },
  ),
  primitive: fc.oneof(fc.constant(null), fc.boolean(), finiteNumber, jsonString),
  arrayValue: fc.array(tie('jsonTree'), { maxLength: 5 }), // 包含空数组（maxLength 允许 0）
  objectValue: fc.dictionary(jsonString, tie('jsonTree'), { maxKeys: 5 }), // 包含空对象
}))

console.log('\ndifferential: 逐字节对拍')

t('随机 JSON：NFC 输入下与参考实现逐字节一致；非 NFC 输入下先证明二者不同，再证明我们的输出恰好等于「参考实现 ∘ NFC」', () => {
  let nfcCases = 0
  let divergentCases = 0
  fc.assert(
    fc.property(jsonTree, (value) => {
      fc.pre(!hasNfcKeyCollision(value))
      const ours = canonicalize(value)
      const theirs = referenceCanonicalize(value) as string
      if (isFullyNFC(value)) {
        nfcCases++
        assert.equal(
          ours, theirs,
          'NFC 输入下 nfc-jcs/v1 的第 1-2 步是空操作，输出必须与裸 JCS 参考实现逐字节相同',
        )
      } else {
        divergentCases++
        assert.notEqual(
          ours, theirs,
          '非 NFC 输入下二者必须不同——这正是 nfc-jcs/v1 存在的理由；若相等，说明 NFC 归一化步骤被误删了',
        )
        const expected = referenceCanonicalize(deepNormalizeToNFC(value)) as string
        assert.equal(
          ours, expected,
          '我们的分歧必须恰好等于"参考实现作用于 NFC 归一化后输入"的结果，不多不少',
        )
      }
    }),
    { numRuns: 5000 },
  )
  console.log(`       (${nfcCases} 组输入已是 NFC，${divergentCases} 组输入非 NFC；两条路径都被覆盖到)`)
  assert.ok(nfcCases > 0, '这批随机样本必须覆盖到"已是 NFC"这条路径，否则上面的相等断言从未真正跑过')
  assert.ok(divergentCases > 0, '这批随机样本必须覆盖到"非 NFC"这条路径，否则「分歧恰好等于 NFC」这条断言从未真正跑过')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
