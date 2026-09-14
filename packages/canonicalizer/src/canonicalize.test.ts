import assert from 'node:assert'
import { canonicalize, canonicalBytes, CANONICALIZATION_PROFILE } from './canonicalize.ts'
import { CanonicalizationError } from './errors.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}
function throwsCode(fn: () => void, code: string) {
  try {
    fn()
  } catch (e) {
    assert.ok(e instanceof CanonicalizationError, `expected CanonicalizationError, got ${(e as Error).constructor.name}`)
    assert.equal((e as CanonicalizationError).code, code)
    return
  }
  assert.fail('expected to throw, did not throw')
}

console.log('canonicalize: 方案标识')

t('CANONICALIZATION_PROFILE 是 nfc-jcs/v1，不是 "RFC 8785"（RFC 8785 §3.1 明确禁止规范化流程里做 Unicode 归一化）', () => {
  assert.equal(CANONICALIZATION_PROFILE, 'nfc-jcs/v1')
})

console.log('\ncanonicalize: 字面量')

t('null', () => assert.equal(canonicalize(null), 'null'))
t('true', () => assert.equal(canonicalize(true), 'true'))
t('false', () => assert.equal(canonicalize(false), 'false'))

console.log('\ncanonicalize: 数字')

t('0', () => assert.equal(canonicalize(0), '0'))
t('负零必须序列化成 0（正例）', () => assert.equal(canonicalize(-0), '0'))
t('普通整数', () => assert.equal(canonicalize(42), '42'))
t('普通小数', () => assert.equal(canonicalize(4.5), '4.5'))
t('1e21 → 指数记法', () => assert.equal(canonicalize(1e21), '1e+21'))
t('1e-7 → 指数记法', () => assert.equal(canonicalize(1e-7), '1e-7'))
t('1e-6 → 不是指数记法', () => assert.equal(canonicalize(1e-6), '0.000001'))
t('Number.MAX_SAFE_INTEGER → 不是指数记法', () => assert.equal(canonicalize(Number.MAX_SAFE_INTEGER), '9007199254740991'))
t('NaN → 抛错（反例）', () => throwsCode(() => canonicalize(NaN), 'NON_FINITE_NUMBER'))
t('Infinity → 抛错（反例）', () => throwsCode(() => canonicalize(Infinity), 'NON_FINITE_NUMBER'))
t('-Infinity → 抛错（反例）', () => throwsCode(() => canonicalize(-Infinity), 'NON_FINITE_NUMBER'))
t('bigint → UNSUPPORTED_TYPE（不静默转 number）', () => throwsCode(() => canonicalize(10n), 'UNSUPPORTED_TYPE'))

console.log('\ncanonicalize: 字符串转义')

t('普通字符串', () => assert.equal(canonicalize('hello'), '"hello"'))
t('双引号', () => assert.equal(canonicalize('"'), '"\\""'))
t('反斜杠', () => assert.equal(canonicalize('\\'), '"\\\\"'))
t('退格 \\b', () => assert.equal(canonicalize('\b'), '"\\b"'))
t('换页 \\f', () => assert.equal(canonicalize('\f'), '"\\f"'))
t('换行 \\n', () => assert.equal(canonicalize('\n'), '"\\n"'))
t('回车 \\r', () => assert.equal(canonicalize('\r'), '"\\r"'))
t('制表符 \\t', () => assert.equal(canonicalize('\t'), '"\\t"'))
t('其他控制字符 → \\u00xx 小写 hex（U+0001）', () => assert.equal(canonicalize('\x01'), '"\\u0001"'))
t('控制字符边界 U+001F', () => assert.equal(canonicalize('\x1f'), '"\\u001f"'))
t('斜杠 / 不转义（反例）', () => assert.equal(canonicalize('/'), '"/"'))
t('U+007F 不转义（反例）', () => assert.equal(canonicalize('\x7f'), '"\x7f"'))
t('U+0020 空格原样保留', () => assert.equal(canonicalize(' '), '" "'))

console.log('\ncanonicalize: 对象键排序')

t('基本字典序', () => assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}'))

t('keys.sort() 用 UTF-16 码元序，不是 localeCompare（正例：证明二者不同）', () => {
  // U+1F600 (😀)：代理对 [0xD83D, 0xDE00]，首个码元 0xD83D
  // U+FB1E (ﬞ)：单一 BMP 码元 0xFB1E
  // 0xD83D < 0xFB1E，所以按 UTF-16 码元序，U+1F600 排在 U+FB1E 前面。
  // 这两个键在本项目实际运行的 Node/ICU 环境下 localeCompare 给出相反顺序——
  // 已用独立脚本实测确认，不是凭理论假设推断的。
  const emoji = '\u{1F600}'
  const hebrewMark = 'ﬞ'

  const defaultOrder = [emoji, hebrewMark].sort()
  const localeOrder = [emoji, hebrewMark].sort((a, b) => a.localeCompare(b))
  assert.notDeepEqual(defaultOrder, localeOrder, '这组键若不能证明两种排法不同，测试本身就没有意义')
  assert.deepEqual(defaultOrder, [emoji, hebrewMark])

  const obj: Record<string, number> = {}
  obj[hebrewMark] = 2
  obj[emoji] = 1
  const result = canonicalize(obj)
  assert.equal(result, `{"${emoji}":1,"${hebrewMark}":2}`, 'canonicalize 必须按 UTF-16 码元序（keys.sort()），不能按 localeCompare')
})

console.log('\ncanonicalize: NFC 严格模式')

t('字符串值在序列化前被 NFC 归一化（正例）', () => {
  // 'e' + U+0301 (COMBINING ACUTE ACCENT) → NFC → U+00E9 (é)
  const decomposed = 'e' + '́'
  assert.equal(canonicalize(decomposed), '"é"')
})

t('对象键在排序前被 NFC 归一化（正例）', () => {
  const decomposedKey = 'e' + '́'
  const obj: Record<string, number> = {}
  obj[decomposedKey] = 1
  assert.equal(canonicalize(obj), '{"é":1}')
})

t('归一化后撞键 → DUPLICATE_KEY_AFTER_NFC，不静默覆盖（反例）', () => {
  const precomposed = 'é'          // é，单一码点
  const decomposed = 'e' + '́'     // e + 组合重音，两个码点
  assert.notEqual(precomposed, decomposed, '这两个键在归一化前必须是不同的 JS 字符串')
  const obj: Record<string, number> = {}
  obj[precomposed] = 1
  obj[decomposed] = 2
  throwsCode(() => canonicalize(obj), 'DUPLICATE_KEY_AFTER_NFC')
})

t('孤立代理（字符串值）→ LONE_SURROGATE（反例）', () => {
  const loneHigh = 'a' + String.fromCharCode(0xd800) + 'b'
  throwsCode(() => canonicalize(loneHigh), 'LONE_SURROGATE')
})

t('孤立代理（对象键）→ LONE_SURROGATE（反例）', () => {
  const loneLow = String.fromCharCode(0xdc00)
  const obj: Record<string, number> = {}
  obj[loneLow] = 1
  throwsCode(() => canonicalize(obj), 'LONE_SURROGATE')
})

t('合法代理对不受影响（正例，避免误伤 emoji）', () => {
  assert.equal(canonicalize('\u{1f600}'), '"\u{1f600}"')
})

console.log('\ncanonicalize: 类型拒绝')

t('undefined（顶层）→ UNSUPPORTED_TYPE（反例）', () => throwsCode(() => canonicalize(undefined), 'UNSUPPORTED_TYPE'))
t('undefined（对象属性值，不像 JSON.stringify 那样静默丢弃）→ UNSUPPORTED_TYPE（反例）', () =>
  throwsCode(() => canonicalize({ a: undefined }), 'UNSUPPORTED_TYPE'))
t('undefined（数组元素，不像 JSON.stringify 那样变成 null）→ UNSUPPORTED_TYPE（反例）', () =>
  throwsCode(() => canonicalize([undefined]), 'UNSUPPORTED_TYPE'))
t('函数 → UNSUPPORTED_TYPE（反例）', () => throwsCode(() => canonicalize(() => {}), 'UNSUPPORTED_TYPE'))
t('Symbol → UNSUPPORTED_TYPE（反例）', () => throwsCode(() => canonicalize(Symbol('x')), 'UNSUPPORTED_TYPE'))

console.log('\ncanonicalize: 结构规则')

t('不调用 toJSON（用 Date 证明：若调用了 toJSON 会得到 ISO 字符串，而不是 {}）', () => {
  const d = new Date(0)
  assert.equal(typeof d.toJSON, 'function')
  assert.equal(canonicalize(d), '{}')
})

t('不调用 toJSON（显式挂一个不可枚举的 toJSON，仍只序列化自身可枚举属性）', () => {
  const obj: Record<string, unknown> = { real: 1 }
  Object.defineProperty(obj, 'toJSON', { value: () => 'ignored', enumerable: false })
  assert.equal(canonicalize(obj), '{"real":1}')
})

t('数组顺序保持原样，不排序（反例：容易被误当成"到处排序"）', () => {
  assert.equal(canonicalize([3, 1, 2]), '[3,1,2]')
})

t('无多余空白', () => {
  assert.equal(canonicalize({ a: 1, b: [1, 2] }), '{"a":1,"b":[1,2]}')
})

t('循环引用 → CIRCULAR_REFERENCE（反例）', () => {
  const obj: Record<string, unknown> = {}
  obj.self = obj
  throwsCode(() => canonicalize(obj), 'CIRCULAR_REFERENCE')
})

t('数组内循环引用 → CIRCULAR_REFERENCE（反例）', () => {
  const arr: unknown[] = [1, 2]
  arr.push(arr)
  throwsCode(() => canonicalize(arr), 'CIRCULAR_REFERENCE')
})

t('共享但非循环的引用不应误报（正例：DAG 不是环）', () => {
  const shared = { x: 1 }
  assert.equal(canonicalize({ a: shared, b: shared }), '{"a":{"x":1},"b":{"x":1}}')
})

t('嵌套结构综合', () => {
  const value = {
    z: [1, { c: true, a: null }, 'x'],
    a: 1,
  }
  assert.equal(canonicalize(value), '{"a":1,"z":[1,{"a":null,"c":true},"x"]}')
})

console.log('\ncanonicalBytes')

t('返回 UTF-8 字节，解码后等于 canonicalize 的字符串', () => {
  const value = { greeting: '你好，世界 \u{1f600}' }
  const bytes = canonicalBytes(value)
  assert.ok(bytes instanceof Uint8Array)
  const decoded = new TextDecoder().decode(bytes)
  assert.equal(decoded, canonicalize(value))
})

t('多字节字符的字节长度符合 UTF-8 编码规则', () => {
  // U+20AC (€) 在 UTF-8 中是 3 字节
  const bytes = canonicalBytes('€')
  // 输出应为 "€"：引号(1) + € 的3字节 + 引号(1) = 5 字节
  assert.equal(bytes.length, 5)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
