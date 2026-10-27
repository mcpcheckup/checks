// Suite 0.17.0 tool_description_hygiene: the zero-width context rule, pinned by
// explicit code points, and the narrowed injection_imperative patterns, pinned by
// the fixtures in hygiene-0170-fixtures.ts (suite-0170-differential.test.ts holds
// the whole corpus against frozen 0.16.0).
import assert from 'node:assert'
import { checkTool } from './hygiene.ts'
import { checkTool as checkTool0160 } from './frozen/suite-0.16.0/src/hygiene.ts'
import { KEPT, MUST_HIT, REMOVED, ZWJ, ZWNJ } from './hygiene-0170-fixtures.ts'
import type { HygieneFlag } from './hygiene.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).message) }
}

const cp = (...points: number[]) => String.fromCodePoint(...points)
const flagsOf = (check: typeof checkTool, description: string): HygieneFlag[] =>
  [...new Set(check({ name: 'a', description }).map((h) => h.flag))]
const zeroWidth = (description: string) => flagsOf(checkTool, description).includes('zero_width_chars')
const hex = (points: number[]) => points.map((p) => 'U+' + p.toString(16).toUpperCase().padStart(4, '0')).join(' ')

console.log('tool_description_hygiene, suite 0.17.0')

// One letter per listed script (a consonant from each block).
const SCRIPT_LETTERS: [string, number][] = [
  ['Arabic', 0x0645], ['Devanagari', 0x0915], ['Bengali', 0x0995], ['Gurmukhi', 0x0a15],
  ['Gujarati', 0x0a95], ['Oriya', 0x0b15], ['Tamil', 0x0b95], ['Telugu', 0x0c15],
  ['Kannada', 0x0c95], ['Malayalam', 0x0d15], ['Sinhala', 0x0d9a], ['Syriac', 0x0712],
  ['Thaana', 0x078c],
]

t('ZWNJ and ZWJ between two letters of each listed script do not count', () => {
  for (const [script, letter] of SCRIPT_LETTERS) {
    for (const joiner of [ZWNJ, ZWJ]) {
      const points = [letter, joiner, letter]
      assert.equal(zeroWidth(`Example ${cp(...points)} here.`), false, `${script}: ${hex(points)}`)
    }
  }
})

// Code points, and whether zero_width_chars is flagged. Each row is a whole
// description: "x " + the points + " y", so ASCII never touches the joiner.
const TABLE: [string, number[], boolean][] = [
  ['Persian ZWNJ', [0x0645, 0x06cc, ZWNJ, 0x062e], false],
  ['Arabic, a combining mark before the joiner is skipped', [0x0628, 0x064e, ZWNJ, 0x0627], false],
  ['Arabic, a combining mark after the joiner is skipped', [0x0628, ZWNJ, 0x064e, 0x0627], false],
  ['Devanagari half form (virama, ZWJ)', [0x0915, 0x094d, ZWJ, 0x0937], false],
  ['Devanagari, ZWNJ after virama', [0x0915, 0x094d, ZWNJ, 0x0937], false],
  ['emoji ZWJ sequence', [0x1f469, ZWJ, 0x1f4bb], false],
  ['emoji ZWJ sequence, FE0F skipped as a mark', [0x2764, 0xfe0f, ZWJ, 0x1f525], false],
  ['ZWNJ between two emoji (only ZWJ is exempt there)', [0x1f469, ZWNJ, 0x1f4bb], true],
  ['ZWJ after a skin-tone modifier (not Extended_Pictographic, not a mark)', [0x1f469, 0x1f3fd, ZWJ, 0x1f4bb], true],
  ['ZWNJ between Latin letters', [0x0061, ZWNJ, 0x0062], true],
  ['ZWJ between Latin letters', [0x0061, ZWJ, 0x0062], true],
  ['between two different listed scripts', [0x0645, ZWNJ, 0x0915], true],
  ['Arabic letter, then a digit', [0x0645, ZWNJ, 0x0031], true],
  ['Arabic letter, then an ellipsis (Common)', [0x0645, ZWNJ, 0x2026], true],
  ['a run of two between Arabic letters', [0x0645, ZWNJ, ZWNJ, 0x062e], true],
  ['ZWNJ then ZWJ between Devanagari letters', [0x0915, ZWNJ, ZWJ, 0x0937], true],
  ['an unassigned (Cn) neighbour after', [0x0645, ZWNJ, 0x0378], true],
  ['an unassigned (Cn) neighbour before', [0x0378, ZWNJ, 0x0645], true],
  ['an unassigned neighbour behind a combining mark', [0x0378, 0x064e, ZWNJ, 0x0645], true],
  // U+0378 is in no listed script, so the rows above would count even without the Cn
  // rule. U+1FC00 is reserved yet Extended_Pictographic: only the Cn rule makes this count.
  ['ZWJ between an emoji and an unassigned Extended_Pictographic code point', [0x1f469, ZWJ, 0x1fc00], true],
  ['next to a space', [0x0645, ZWNJ, 0x0020, 0x062e], true],
  ['U+200B between Arabic letters', [0x0645, 0x200b, 0x062e], true],
  ['U+200E (LRM) between Arabic letters', [0x0645, 0x200e, 0x062e], true],
  ['U+200F (RLM) between Arabic letters', [0x0645, 0x200f, 0x062e], true],
  ['U+2060 between Arabic letters', [0x0645, 0x2060, 0x062e], true],
  ['U+FEFF between Arabic letters', [0x0645, 0xfeff, 0x062e], true],
  ['U+180E between Arabic letters', [0x0645, 0x180e, 0x062e], true],
  ['U+FE0F alone is not scanned (unchanged)', [0x2764, 0xfe0f], false],
]

t('the code-point table', () => {
  assert.ok(/\p{Cn}/u.test(cp(0x0378)), 'U+0378 is assigned in this engine: pick another unassigned code point for the Cn rows')
  assert.ok(/\p{Cn}/u.test(cp(0x1fc00)) && /\p{Extended_Pictographic}/u.test(cp(0x1fc00)),
    'U+1FC00 is not both unassigned and Extended_Pictographic in this engine: pick another code point that is, or this row cannot catch a missing Cn rule')
  for (const [what, points, flagged] of TABLE) {
    assert.equal(zeroWidth(`x ${cp(...points)} y`), flagged, `${what}: ${hex(points)}`)
  }
})

t('a ZWNJ or ZWJ at either end of the text counts', () => {
  for (const joiner of [ZWNJ, ZWJ]) {
    assert.equal(zeroWidth(cp(joiner, 0x0645, 0x062e)), true, `${hex([joiner])} first`)
    assert.equal(zeroWidth(cp(0x0645, 0x062e, joiner)), true, `${hex([joiner])} last`)
    assert.equal(zeroWidth(cp(joiner)), true, `${hex([joiner])} alone`)
  }
})

t('every zero-width character is scanned, not only the first: a compliant ZWNJ before a ZWSP still reports the ZWSP, at its index', () => {
  const text = `x ${cp(0x0645, 0x06cc, ZWNJ, 0x062e)} and ${cp(0x200b)}`
  const hit = checkTool({ name: 'a', description: text }).find((h) => h.flag === 'zero_width_chars')
  assert.ok(hit)
  assert.equal(hit.at, text.indexOf(cp(0x200b)))
  assert.equal(hit.sample, JSON.stringify(cp(0x200b)))
})

t('the tool name is scanned with the same rule', () => {
  assert.equal(checkTool({ name: `a${cp(ZWJ)}b` }).some((h) => h.flag === 'zero_width_chars'), true)
  assert.equal(checkTool({ name: cp(0x0645, ZWNJ, 0x062e) }).some((h) => h.flag === 'zero_width_chars'), false)
})

t('every table row that suite 0.17.0 flags, frozen 0.16.0 flags too (the rule only narrows)', () => {
  for (const [what, points] of TABLE) {
    const text = `x ${cp(...points)} y`
    if (zeroWidth(text)) assert.ok(flagsOf(checkTool0160, text).includes('zero_width_chars'), what)
  }
})

t('must-hit: each reconstruction is flagged by 0.16.0 and 0.17.0 with exactly its pinned flags', () => {
  assert.deepStrictEqual(MUST_HIT.map((f) => f.id), ['288817', 'adv-01', 'adv-04', 'adv-08', 'adv-15'])
  for (const f of MUST_HIT) {
    assert.deepStrictEqual(flagsOf(checkTool0160, f.tool.description).sort(), [...f.flags].sort(), `${f.id} under 0.16.0`)
    assert.deepStrictEqual(flagsOf(checkTool, f.tool.description).sort(), [...f.flags].sort(), `${f.id} under 0.17.0`)
  }
})

t('removed: each false positive loses exactly its listed flags and keeps the rest', () => {
  for (const f of REMOVED) {
    const before = flagsOf(checkTool0160, f.tool.description)
    const after = flagsOf(checkTool, f.tool.description)
    assert.deepStrictEqual(before.filter((x) => !after.includes(x)).sort(), [...f.removed].sort(), `${f.id} (${f.class})`)
    assert.ok(after.every((x) => before.includes(x)), `${f.id} gained a flag`)
  }
})

t('kept: concealment, the assistant\'s own prompt, and the classes this suite does not narrow still hit exactly as before', () => {
  for (const f of KEPT) {
    assert.deepStrictEqual(flagsOf(checkTool0160, f.tool.description).sort(), [...f.flags].sort(), `${f.id} under 0.16.0`)
    assert.deepStrictEqual(flagsOf(checkTool, f.tool.description).sort(), [...f.flags].sort(), `${f.id} under 0.17.0`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
