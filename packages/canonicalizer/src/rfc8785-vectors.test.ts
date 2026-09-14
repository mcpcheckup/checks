import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { canonicalize, CANONICALIZATION_PROFILE } from './canonicalize.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const fixtureDir = new URL('../test/fixtures/rfc8785/', import.meta.url)
function readFixture(kind: 'input' | 'output', name: string): string {
  return readFileSync(new URL(`${kind}/${name}.json`, fixtureDir), 'utf8')
}

console.log('RFC 8785 官方测试向量（github.com/cyberphone/json-canonicalization/testdata）')
console.log('来源：直接从上游仓库下载，未做任何修改；见 test/fixtures/rfc8785/UPSTREAM_README.md')

// 这 4 组向量不含任何"归一化前不是 NFC"的字符串，所以 nfc-jcs/v1 第 1-2 步（NFC 归一化 +
// 撞键检测）是空操作（no-op）——canonicalize() 的输出必须和官方 output/*.json 逐字节相同，
// 因为剩下第 3 步就是严格的 RFC 8785。
const EXACT_MATCH_VECTORS = ['arrays', 'french', 'structures', 'values']

for (const name of EXACT_MATCH_VECTORS) {
  t(`${name}.json：与官方输出逐字节相同`, () => {
    const input = JSON.parse(readFixture('input', name))
    const expected = readFixture('output', name)
    assert.equal(canonicalize(input), expected)
  })
}

// unicode.json 和 weird.json 是官方测试向量里专门设计成"归一化前非 NFC"的两组——
// unicode.json 的字符串值是 "A" + U+0301（组合重音），官方 JCS 刻意不归一化，保留两个码点；
// weird.json 里有一个键 U+FB33，它的规范分解在 NFC 组合排除表里，分解后不会重新组合。
//
// RFC 8785 §3.1 明确要求："all components involved in a scheme depending on
// JCS MUST preserve Unicode string data 'as is'"——也就是说，会对字符串做归一化的方案，
// 根据定义就不是（纯）JCS。nfc-jcs/v1 的第 1-2 步（NFC 归一化 + 撞键检测）正是这样一处
// 有意的偏离，所以这两组向量在这里【不会】、也【不应该】匹配官方输出。这不是 bug，
// 是 nfc-jcs/v1 与裸 JCS 的设计意图之差——也是它不能自称"RFC 8785"、必须单独命名的原因。
// 下面每组各有两个测试：
//   1. 证明 nfc-jcs/v1 在第 1-2 步与裸 JCS 的差异，这是设计意图（如果哪天不小心把 NFC
//      步骤删了，这个反向断言会翻车，网住这个回归）；
//   2. 用不依赖 canonicalize.ts 本身的方式独立算出"NFC 之后再 JCS"应有的结果，
//      并断言 canonicalize() 产出这个值。所有非 ASCII 字符都用 String.fromCodePoint
//      按码点显式拼出来，不在源码里直接书写原始字形，避免任何编辑器/工具链在保存时
//      悄悄做归一化而污染测试本身。

t(`unicode.json：证明 ${CANONICALIZATION_PROFILE} 在第 1-2 步与裸 JCS 的差异，这是设计意图`, () => {
  const input = JSON.parse(readFixture('input', 'unicode'))
  const officialOutput = readFixture('output', 'unicode')
  const ours = canonicalize(input)
  assert.notEqual(ours, officialOutput, '如果这里相等了，说明 NFC 归一化步骤被误删了')
})

t('unicode.json：NFC 归一化后的独立预期值（"A"+U+0301 → U+00C5）', () => {
  const input = JSON.parse(readFixture('input', 'unicode'))
  const aRingAbove = String.fromCodePoint(0x00c5) // Å：'A' + COMBINING RING ABOVE 归一化后的单一码点
  const expected = `{"Unnormalized Unicode":"${aRingAbove}"}`
  assert.equal(canonicalize(input), expected)
})

t(`weird.json：证明 ${CANONICALIZATION_PROFILE} 在第 1-2 步与裸 JCS 的差异，这是设计意图`, () => {
  const input = JSON.parse(readFixture('input', 'weird'))
  const officialOutput = readFixture('output', 'weird')
  const ours = canonicalize(input)
  assert.notEqual(ours, officialOutput, '如果这里相等了，说明 NFC 归一化步骤被误删了')
})

t('weird.json：NFC 归一化后的独立预期值（U+FB33 分解为 U+05D3 U+05BC，键排序随之改变）', () => {
  const input = JSON.parse(readFixture('input', 'weird'))
  // U+FB33（HEBREW LETTER DALET WITH DAGESH）在组合排除表里，NFC 分解后不会重新组合，
  // 变成 U+05D3（DALET）+ U+05BC（DAGESH），首码元从 0xFB33 变成 0x05D3——
  // 排序位置从"官方输出里的最后一个键"移动到 U+00F6 (ö) 之后、U+20AC (€) 之前。
  // 下面这个预期值是用一份不依赖 canonicalize.ts 的独立脚本手工推导的
  // （NFC 用 String.prototype.normalize，排序用 UTF-16 码元字典序，转义规则
  //  照抄 RFC 8785 §3.2.2.2，三者都是与实现本身无关的、可独立验证的规则）。
  const controlKey = String.fromCodePoint(0x0080)
  const del = String.fromCodePoint(0x007f) // "Control" 后面那个不可转义、必须原样保留的 DEL
  const oDiaeresis = String.fromCodePoint(0x00f6) // ö
  const hebrewDecomposed = String.fromCodePoint(0x05d3, 0x05bc) // U+FB33 归一化后
  const euroSign = String.fromCodePoint(0x20ac) // €
  const faceWithTears = String.fromCodePoint(0x1f602) // 😂，代理对
  const expected =
    '{"\\n":"Newline","\\r":"Carriage Return","1":"One","</script>":"Browser Challenge",' +
    `"${controlKey}":"Control${del}","${oDiaeresis}":"Latin Small Letter O With Diaeresis",` +
    `"${hebrewDecomposed}":"Hebrew Letter Dalet With Dagesh","${euroSign}":"Euro Sign","${faceWithTears}":"Smiley"}`
  assert.equal(canonicalize(input), expected)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
