import assert from 'node:assert'
import { diffToolsets, UNITEMIZABLE_REASONS } from './index.ts'
import type { ToolItem, ToolsetDiff, ToolsetSide, UnitemizableReason } from './index.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const S = { type: 'object', properties: { q: { type: 'string' } } }
const S2 = { type: 'object', properties: { q: { type: 'number' } } }

function tool(name: string, description: string | null = 'd', inputSchema: unknown = S, unstorable?: string[]): ToolItem {
  return unstorable === undefined ? { name, description, inputSchema } : { name, description, inputSchema, unstorable }
}
function side(items: ToolItem[], toolCount: number = items.length): ToolsetSide {
  return { items, toolCount }
}
function changedOf(r: ToolsetDiff) {
  assert.strictEqual(r.kind, 'changed', JSON.stringify(r))
  if (r.kind !== 'changed') throw new Error('unreachable')
  return r
}
function deepFreeze<T>(v: T): T {
  if (typeof v === 'object' && v !== null) {
    Object.freeze(v)
    for (const k of Object.keys(v)) deepFreeze((v as Record<string, unknown>)[k])
  }
  return v
}

console.log('diffToolsets: per-tool comparison')

t('added: a tool only in after, named as written in after', () => {
  const r = changedOf(diffToolsets(side([tool('a')]), side([tool('a'), tool('b')])))
  assert.deepStrictEqual(r, { kind: 'changed', added: ['b'], removed: [], descriptionChanged: [], schemaChanged: [] })
})

t('removed: a tool only in before', () => {
  const r = changedOf(diffToolsets(side([tool('a'), tool('b')]), side([tool('a')])))
  assert.deepStrictEqual(r, { kind: 'changed', added: [], removed: ['b'], descriptionChanged: [], schemaChanged: [] })
})

t('descriptionChanged: only the description differs; before/after are the raw strings; schemaChanged stays empty', () => {
  const r = changedOf(diffToolsets(side([tool('a', 'old')]), side([tool('a', 'new')])))
  assert.deepStrictEqual(r, {
    kind: 'changed', added: [], removed: [],
    descriptionChanged: [{ name: 'a', before: 'old', after: 'new' }],
    schemaChanged: [],
  })
})

t('schemaChanged: only the schema differs; only the name is reported; descriptionChanged stays empty', () => {
  const r = changedOf(diffToolsets(side([tool('a', 'd', S)]), side([tool('a', 'd', S2)])))
  assert.deepStrictEqual(r, { kind: 'changed', added: [], removed: [], descriptionChanged: [], schemaChanged: [{ name: 'a' }] })
})

t('one tool with both description and schema changed appears once in each list', () => {
  const r = changedOf(diffToolsets(side([tool('a', 'old', S)]), side([tool('a', 'new', S2)])))
  assert.deepStrictEqual(r.descriptionChanged, [{ name: 'a', before: 'old', after: 'new' }])
  assert.deepStrictEqual(r.schemaChanged, [{ name: 'a' }])
})

t('all four kinds at once do not leak into each other', () => {
  const before = side([tool('keep'), tool('gone'), tool('desc', 'x'), tool('sch', 'd', S)])
  const after = side([tool('keep'), tool('new'), tool('desc', 'y'), tool('sch', 'd', S2)])
  assert.deepStrictEqual(diffToolsets(before, after), {
    kind: 'changed',
    added: ['new'],
    removed: ['gone'],
    descriptionChanged: [{ name: 'desc', before: 'x', after: 'y' }],
    schemaChanged: [{ name: 'sch' }],
  })
})

t('unchanged: identical lists; empty against empty is unchanged too', () => {
  assert.deepStrictEqual(diffToolsets(side([tool('a'), tool('b')]), side([tool('a'), tool('b')])), { kind: 'unchanged' })
  assert.deepStrictEqual(diffToolsets(side([]), side([])), { kind: 'unchanged' })
})

t('only the order differs: unchanged, never a changed with four empty lists', () => {
  const r = diffToolsets(side([tool('a'), tool('b'), tool('c')]), side([tool('c'), tool('a'), tool('b')]))
  assert.deepStrictEqual(r, { kind: 'unchanged' })
})

t('object keys in a different order inside a schema: not a change', () => {
  const r = diffToolsets(
    side([tool('a', 'd', { type: 'object', required: ['q'] })]),
    side([tool('a', 'd', { required: ['q'], type: 'object' })]),
  )
  assert.deepStrictEqual(r, { kind: 'unchanged' })
})

console.log('\ndescription comparison')

t('descriptions that differ only in NFC form: unchanged', () => {
  const nfc = 'café'
  const nfd = 'café'
  assert.notStrictEqual(nfc, nfd)
  assert.deepStrictEqual(diffToolsets(side([tool('a', nfc)]), side([tool('a', nfd)])), { kind: 'unchanged' })
})

t('null and "" are different descriptions, in both directions, reported as given', () => {
  const r = changedOf(diffToolsets(side([tool('a', null)]), side([tool('a', '')])))
  assert.deepStrictEqual(r.descriptionChanged, [{ name: 'a', before: null, after: '' }])
  const back = changedOf(diffToolsets(side([tool('a', '')]), side([tool('a', null)])))
  assert.deepStrictEqual(back.descriptionChanged, [{ name: 'a', before: '', after: null }])
})

t('null against null: unchanged', () => {
  assert.deepStrictEqual(diffToolsets(side([tool('a', null)]), side([tool('a', null)])), { kind: 'unchanged' })
})

t('the description in the result is the raw string, not its NFC form', () => {
  const nfd = 'café'
  const r = changedOf(diffToolsets(side([tool('a', nfd)]), side([tool('a', 'other')])))
  assert.strictEqual(r.descriptionChanged[0]?.before, nfd)
})

console.log('\nmatching and names')

t('rename: one removed plus one added, no rename guessing', () => {
  const r = changedOf(diffToolsets(side([tool('old_name')]), side([tool('new_name')])))
  assert.deepStrictEqual(r, { kind: 'changed', added: ['new_name'], removed: ['old_name'], descriptionChanged: [], schemaChanged: [] })
})

t('names that differ only in NFC form are one tool; a change carries the name as written in after', () => {
  const nfc = 'café'
  const nfd = 'café'
  assert.deepStrictEqual(diffToolsets(side([tool(nfd)]), side([tool(nfc)])), { kind: 'unchanged' })
  const r = changedOf(diffToolsets(side([tool(nfd, 'x')]), side([tool(nfc, 'y')])))
  assert.strictEqual(r.descriptionChanged[0]?.name, nfc)
})

t('names that differ in case are different tools', () => {
  const r = changedOf(diffToolsets(side([tool('Tool')]), side([tool('tool')])))
  assert.deepStrictEqual([r.added, r.removed], [['tool'], ['Tool']])
})

console.log('\nordering and determinism')

// U+FF5E has a larger code point than U+1F600, but its UTF-16 code unit 0xFF5E is larger than the
// lead surrogate 0xD83D, so in UTF-16 order the emoji comes first.
const NAMES = ['b', 'B', 'a', '～', '\u{1f600}', 'é', 'ab', 'a_']
const UTF16_SORTED = ['B', 'a', 'a_', 'ab', 'b', 'é', '\u{1f600}', '～']

t('all four lists are sorted in UTF-16 code-unit order whatever the input order', () => {
  const before = side([
    ...NAMES.map((n) => tool('r' + n)), ...NAMES.map((n) => tool('d' + n, 'old')), ...NAMES.map((n) => tool('s' + n, 'd', S)),
  ])
  const after = side([
    ...NAMES.map((n) => tool('a' + n)), ...NAMES.map((n) => tool('d' + n, 'new')), ...NAMES.map((n) => tool('s' + n, 'd', S2)),
  ])
  const reversed = (s: ToolsetSide) => side([...s.items].reverse())
  const forward = changedOf(diffToolsets(before, after))
  const backward = changedOf(diffToolsets(reversed(before), reversed(after)))
  assert.deepStrictEqual(forward, backward)
  assert.deepStrictEqual(forward.added, UTF16_SORTED.map((n) => 'a' + n))
  assert.deepStrictEqual(forward.removed, UTF16_SORTED.map((n) => 'r' + n))
  assert.deepStrictEqual(forward.descriptionChanged.map((d) => d.name), UTF16_SORTED.map((n) => 'd' + n))
  assert.deepStrictEqual(forward.schemaChanged.map((d) => d.name), UTF16_SORTED.map((n) => 's' + n))
})

t('every input permutation of the same tools gives the identical output', () => {
  const before = [tool('c', 'x'), tool('a'), tool('b', 'd', S), tool('gone')]
  const after = [tool('c', 'y'), tool('a'), tool('b', 'd', S2), tool('new')]
  const expected = diffToolsets(side(before), side(after))
  const perms = <T,>(xs: T[]): T[][] => xs.length <= 1 ? [xs] : xs.flatMap((x, i) => perms([...xs.slice(0, i), ...xs.slice(i + 1)]).map((p) => [x, ...p]))
  for (const pb of perms(before)) for (const pa of perms(after)) {
    assert.deepStrictEqual(diffToolsets(side(pb), side(pa)), expected)
  }
})

t('the sort key is the NFC name, not a serialization of it: a control character is not escaped before comparing', () => {
  // A JSON serialization would spell '\u0001' with a backslash (0x5C) and sort it after '!' (0x21).
  const r = changedOf(diffToolsets(side([]), side([tool('!'), tool('\u0001')])))
  assert.deepStrictEqual(r.added, ['\u0001', '!'])
})

t('the sort key is the NFC name, not the raw name: an NFD name sorts where its NFC form would, and is still reported raw', () => {
  const nfd = 'éx' // its NFC form starts with U+00E9, which sorts after "f"; the raw form would sort before it
  const r = changedOf(diffToolsets(side([]), side([tool(nfd), tool('f')])))
  assert.deepStrictEqual(r.added, ['f', nfd])
})

t('deterministic: the same inputs twice give deeply equal results', () => {
  const b = side([tool('a', 'x'), tool('b')])
  const a = side([tool('a', 'y'), tool('c')])
  assert.deepStrictEqual(diffToolsets(b, a), diffToolsets(b, a))
})

t('inputs are not modified: deep-frozen inputs work and keep their content', () => {
  const b = deepFreeze(side([tool('b', 'x'), tool('a', 'x', S)]))
  const a = deepFreeze(side([tool('z'), tool('a', 'y', S2), tool('b', 'x')]))
  const snap = JSON.stringify([b, a])
  const r = changedOf(diffToolsets(b, a))
  assert.strictEqual(JSON.stringify([b, a]), snap)
  assert.deepStrictEqual(r.added, ['z'])
})

t('inputSchema undefined is the same as null; undefined against an object is a schema change', () => {
  const noSchema: ToolItem = { name: 'a', description: 'd', inputSchema: undefined }
  assert.deepStrictEqual(diffToolsets(side([noSchema]), side([tool('a', 'd', null)])), { kind: 'unchanged' })
  assert.deepStrictEqual(diffToolsets(side([noSchema]), side([noSchema])), { kind: 'unchanged' })
  const r = changedOf(diffToolsets(side([noSchema]), side([tool('a', 'd', S)])))
  assert.deepStrictEqual(r.schemaChanged, [{ name: 'a' }])
})

console.log('\nunitemizable: each of the four reasons alone')

const REASON_CASES: Record<UnitemizableReason, ToolsetSide> = {
  DUPLICATE_NAME: side([tool('a'), tool('a')]),
  UNSTORABLE_FIELDS: side([tool('a', 'd', S, ['inputSchema'])]),
  ITEM_COUNT_MISMATCH: side([tool('a')], 2),
  NOT_CANONICALIZABLE: side([tool('a', 'd', { n: 1e400 })]),
}
const CLEAN = side([tool('a')])

for (const reason of UNITEMIZABLE_REASONS) {
  t(`${reason}: on before only -> side=before`, () => {
    assert.deepStrictEqual(diffToolsets(REASON_CASES[reason], CLEAN), { kind: 'unitemizable', reason, side: 'before' })
  })
  t(`${reason}: on after only -> side=after`, () => {
    assert.deepStrictEqual(diffToolsets(CLEAN, REASON_CASES[reason]), { kind: 'unitemizable', reason, side: 'after' })
  })
  t(`${reason}: on both -> side=both`, () => {
    assert.deepStrictEqual(diffToolsets(REASON_CASES[reason], REASON_CASES[reason]), { kind: 'unitemizable', reason, side: 'both' })
  })
}

t('DUPLICATE_NAME: two names equal after NFC are duplicates', () => {
  const r = diffToolsets(side([tool('café'), tool('café')]), CLEAN)
  assert.deepStrictEqual(r, { kind: 'unitemizable', reason: 'DUPLICATE_NAME', side: 'before' })
})

t('UNSTORABLE_FIELDS: an empty array does not count; a non-empty one does', () => {
  assert.deepStrictEqual(diffToolsets(side([tool('a', 'd', S, [])]), side([tool('a', 'd', S, [])])), { kind: 'unchanged' })
  assert.strictEqual(diffToolsets(side([tool('a', 'd', S, ['x'])]), CLEAN).kind, 'unitemizable')
})

t('ITEM_COUNT_MISMATCH: a toolCount below the item count counts too', () => {
  assert.deepStrictEqual(diffToolsets(side([tool('a'), tool('b')], 1), CLEAN), { kind: 'unitemizable', reason: 'ITEM_COUNT_MISMATCH', side: 'before' })
})

console.log('\nNOT_CANONICALIZABLE: every canonicalize failure becomes a result, never a throw')

t('1e400 (a non-finite number) inside a schema', () => {
  const r = diffToolsets(side([tool('a', 'd', JSON.parse('{"n":1e400}') as unknown)]), CLEAN)
  assert.deepStrictEqual(r, { kind: 'unitemizable', reason: 'NOT_CANONICALIZABLE', side: 'before' })
})

t('a lone surrogate in the name, the description or the schema', () => {
  for (const bad of [tool('\ud800'), tool('a', '\udc00'), tool('a', 'd', { k: '\ud800' })]) {
    assert.deepStrictEqual(diffToolsets(side([bad]), side([bad])), { kind: 'unitemizable', reason: 'NOT_CANONICALIZABLE', side: 'both' })
  }
})

t('a circular reference, a bigint, a function: no throw, NOT_CANONICALIZABLE', () => {
  const cyc: Record<string, unknown> = {}
  cyc.self = cyc
  for (const schema of [cyc, 10n, () => 1]) {
    assert.deepStrictEqual(diffToolsets(side([tool('a', 'd', schema)]), CLEAN), { kind: 'unitemizable', reason: 'NOT_CANONICALIZABLE', side: 'before' })
  }
})

t('a getter that throws is turned into a result too', () => {
  const schema = { get boom(): unknown { throw new Error('boom') } }
  assert.deepStrictEqual(diffToolsets(side([tool('a', 'd', schema)]), CLEAN), { kind: 'unitemizable', reason: 'NOT_CANONICALIZABLE', side: 'before' })
})

t('a description that is neither a string nor null (for example undefined): NOT_CANONICALIZABLE', () => {
  const missing = { name: 'a', description: undefined, inputSchema: S } as unknown as ToolItem
  assert.deepStrictEqual(diffToolsets(side([missing]), CLEAN), { kind: 'unitemizable', reason: 'NOT_CANONICALIZABLE', side: 'before' })
})

console.log('\nseveral reasons at once: DUPLICATE_NAME > UNSTORABLE_FIELDS > ITEM_COUNT_MISMATCH > NOT_CANONICALIZABLE')

// Two reasons on the same side. Each side is built to hold exactly these two reasons.
const TWO_ON_ONE_SIDE: [UnitemizableReason, UnitemizableReason, ToolsetSide][] = [
  ['DUPLICATE_NAME', 'UNSTORABLE_FIELDS', side([tool('a', 'd', S, ['x']), tool('a')])],
  ['DUPLICATE_NAME', 'ITEM_COUNT_MISMATCH', side([tool('a'), tool('a')], 3)],
  ['DUPLICATE_NAME', 'NOT_CANONICALIZABLE', side([tool('a', 'd', { n: 1e400 }), tool('a')])],
  ['UNSTORABLE_FIELDS', 'ITEM_COUNT_MISMATCH', side([tool('a', 'd', S, ['x'])], 2)],
  ['UNSTORABLE_FIELDS', 'NOT_CANONICALIZABLE', side([tool('a', 'd', { n: 1e400 }, ['x'])])],
  ['ITEM_COUNT_MISMATCH', 'NOT_CANONICALIZABLE', side([tool('a', 'd', { n: 1e400 })], 2)],
]

for (const [high, low, both] of TWO_ON_ONE_SIDE) {
  t(`same side holds ${high} and ${low}: only ${high} is reported, on that side`, () => {
    assert.deepStrictEqual(diffToolsets(both, CLEAN), { kind: 'unitemizable', reason: high, side: 'before' })
    assert.deepStrictEqual(diffToolsets(CLEAN, both), { kind: 'unitemizable', reason: high, side: 'after' })
  })
  t(`different sides: ${high} on after, ${low} on before -> ${high}, side=after (side is where that reason holds)`, () => {
    assert.deepStrictEqual(diffToolsets(REASON_CASES[low], REASON_CASES[high]), { kind: 'unitemizable', reason: high, side: 'after' })
  })
  t(`different sides: ${high} on before, ${low} on after -> ${high}, side=before`, () => {
    assert.deepStrictEqual(diffToolsets(REASON_CASES[high], REASON_CASES[low]), { kind: 'unitemizable', reason: high, side: 'before' })
  })
}

t('a lower reason on both sides and a higher one on one side: the higher reason, naming only its own side', () => {
  const duplicateAndCountOnAfter = side([tool('a'), tool('a')], 3)
  assert.deepStrictEqual(diffToolsets(REASON_CASES.ITEM_COUNT_MISMATCH, duplicateAndCountOnAfter), { kind: 'unitemizable', reason: 'DUPLICATE_NAME', side: 'after' })
})

t('all four reasons on one side: DUPLICATE_NAME', () => {
  const all = side([tool('a', 'd', { n: 1e400 }, ['x']), tool('a')], 5)
  assert.deepStrictEqual(diffToolsets(all, CLEAN), { kind: 'unitemizable', reason: 'DUPLICATE_NAME', side: 'before' })
})

t('a duplicate name is still found when the descriptions or schemas cannot be canonicalized', () => {
  const r = diffToolsets(side([tool('a', 'd', { n: 1e400 }), tool('a', 'd', { n: 1e400 })]), CLEAN)
  assert.deepStrictEqual(r, { kind: 'unitemizable', reason: 'DUPLICATE_NAME', side: 'before' })
})

t('the reason list is frozen and its order is the priority', () => {
  assert.deepStrictEqual([...UNITEMIZABLE_REASONS], ['DUPLICATE_NAME', 'UNSTORABLE_FIELDS', 'ITEM_COUNT_MISMATCH', 'NOT_CANONICALIZABLE'])
  assert.ok(Object.isFrozen(UNITEMIZABLE_REASONS))
})

t('unitemizable wins over the per-tool comparison, even with obvious additions on the other side', () => {
  assert.strictEqual(diffToolsets(REASON_CASES.DUPLICATE_NAME, side([tool('z')])).kind, 'unitemizable')
})

console.log('\nprogramming errors: TypeError')

t('items not an array, toolCount not a number, name not a string, a side that is not an object: TypeError', () => {
  const bad: unknown[] = [
    { items: 'x', toolCount: 0 },
    { items: [], toolCount: '0' },
    { items: [{ name: 5, description: null, inputSchema: null }], toolCount: 1 },
    { items: [null], toolCount: 1 },
    { items: [{ name: 'a', description: null, inputSchema: null, unstorable: 'x' }], toolCount: 1 },
    null,
    undefined,
  ]
  for (const b of bad) {
    assert.throws(() => diffToolsets(b as ToolsetSide, CLEAN), TypeError)
    assert.throws(() => diffToolsets(CLEAN, b as ToolsetSide), TypeError)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
