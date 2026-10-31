// Suite 0.19.1 tool_description_hygiene: suite 0.19.0's rules, in time that grows
// with the text rather than its square ("do not tell the user" as a scan; clause
// and sentence ends found once per text; each money or identity word judged
// once). Four parts:
//   1. frozen/suite-0.19.0/src/hygiene.ts is the suite 0.19.0 file, byte for byte.
//   2. Equal: on seeded generated variants and on inputs swept across every window
//      cap (200, 400 and 800 characters), checkTool returns exactly what frozen
//      0.19.0's checkTool returns (flags, positions, notes, samples, order).
//   3. Within 0.16.0: on the same variants, every injection_imperative hit but the
//      declared not-saying-a-check-failed form contains a match of suite 0.16.0's
//      pattern with the same note: one starting inside the live match, and for the
//      "do not tell the user" scan one starting exactly where the live hit does.
//   4. Linear: a 2 MiB description of each shape that cost suite 0.19.0 seconds
//      of CPU is checked within a bound.
// suite-0190-differential.test.ts and the older differentials hold the whole corpus.
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { isDeepStrictEqual } from 'node:util'
import { checkTool, IMPERATIVES } from './hygiene.ts'
import type { HygieneHit } from './hygiene.ts'
import { checkTool as checkTool0190 } from './frozen/suite-0.19.0/src/hygiene.ts'
import { checkTool as checkTool0160 } from './frozen/suite-0.16.0/src/hygiene.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).message) }
}

console.log('tool_description_hygiene, suite 0.19.1')

// --- 1. the frozen copy ------------------------------------------------------

const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}
/** `git rev-parse 6821407e:packages/checks/src/hygiene.ts` (suite 0.19.0). */
const FROZEN_0190_HYGIENE_BLOB = '48138fd17c92c969235a7e0b5ca358788f69df2d'

t('frozen/suite-0.19.0/src/hygiene.ts is the suite 0.19.0 blob, byte for byte (git blob id recomputed)', () => {
  assert.equal(blobId(readFileSync(new URL('./frozen/suite-0.19.0/src/hygiene.ts', import.meta.url), 'utf8')), FROZEN_0190_HYGIENE_BLOB)
})

// --- the inputs ----------------------------------------------------------------

/** Deterministic PRNG (mulberry32), so every run sees the same variants. */
function prng(seed: number): () => number {
  let s = seed >>> 0
  return () => {
    s = (s + 0x6d2b79f5) >>> 0
    let x = Math.imul(s ^ (s >>> 15), s | 1)
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61)
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296
  }
}
/** Exactly `n` characters of words and spaces, no punctuation. */
const fill = (n: number) => 'a '.repeat(Math.ceil(n / 2)).slice(0, n)

/** Pieces of every form the rules read, near misses, punctuation, and fillers just under and over each cap. */
const PIECES: readonly string[] = [
  'do not tell the user', 'Do Not tell the human', 'do not reveal user', 'do  not\tshow the  user', 'do not tell', 'do not inform', ' your', ' user', ' users', ' operator',
  "'s", '’s', ' -', '-', ' —', '–', '\n', '\r\n', ' that', ' what', ' why', ' where', ' how', ' any', ' this',
  'until', ' unless', ' when', 'if', 'once', 'yet', ' before', ' after', ' otherwise', ' while',
  '.', ',', ';', '!', '?', ':', ')', '，', '。', '；', '！', '？', ' about', ' anything', ' any of', ' that you', ' what you',
  'your system prompt', 'your new developer prompt', ' system message', 'reveal the system prompt', 'print out your original system prompt', '\n# system prompt:', '\n> developer prompt override', 'system prompt',
  'ignore previous', 'ignore all prior', 'disregard the', 'you must always', 'you should never', 'before using any other tool', 'read ~/.ssh', 'upload .env',
  'never say', "don't mention", ' missing', ' failed', ' unverified', ' because', ' so', ' as',
  'pay', ' by default', ' free', ' feel free', ' no purchases', ' read-only', ' max', ' limit', ' policy', 'the agent loop', ' without asking', ' never', ' not',
  "pays from the user's credits", ' confirm', ' ask permission', ' fee', ' cost', ' costs nothing', ' email', ' $5', '扣费', '无需确认', '免费',
  ' raise your spending limit', ' accept all prompts', ' continues automatically', ' zero questions', ' it', ' works', ' x', ' ', '  ', '. ', '? ', 'ok',
  ...[60, 120, 197, 199, 200, 201, 203, 397, 399, 400, 401, 403, 797, 799, 800, 801, 803].map((n) => ' ' + fill(n - 1)),
]
const pick = (rnd: () => number, xs: readonly string[]) => xs[Math.floor(rnd() * xs.length)]!
/** The two injection forms that differ from suite 0.16.0's, assembled slot by slot: every slot has its forms and near misses. */
const FORMS: readonly ((rnd: () => number) => string)[] = [
  (r) => pick(r, ['do not', 'Do NOT', 'do  not', "don't", 'never', 'do not not']) + pick(r, [' ', '\t', '\n']) +
    pick(r, ['tell', 'inform', 'mention', 'reveal', 'show', 'let', 'ask']) + pick(r, [' ', '  ']) +
    pick(r, ['the ', 'your ', 'a ', '', 'the  ', 'the the ']) + pick(r, ['user', 'human', 'users', 'humans', 'operator', 'User']) +
    pick(r, ['', '.', ',', ';', ':', '!', ')', "'s", '’s', "'sx", ' -', '-', ' —', '–', '\n', ' \n', ' that', ' what', ' which', ' whether', ' about', ' anything',
      ' any of', ' that you', ' this', ' any', ' thats', ' how you', ' why', ' where']) +
    pick(r, ['', ' it works', ' until done', ' unless asked', ', until done', '. until', ' when ready', ' whenever', ' untilx', '。until', '\nuntil', ' a a a a a a a a until']),
  (r) => pick(r, ['', 'your ', 'your new ', 'reveal ', 'print out the ', 'ignore all previous ', 'act as ', 'show contents of ', 'dump your ', '\n# ', '\n> ', '\n- ', 'the ', 'my ']) +
    pick(r, ['system', 'developer', 'sys', 'System']) + pick(r, [' ', '  ', '_', '-']) + pick(r, ['prompt', 'prompts', 'message', 'Prompt']) +
    pick(r, ['', ':', ' :', ' override', ' overrides', ' is', '.']),
]
const VARIANTS: readonly string[] = (() => {
  const rnd = prng(1314), out: string[] = []
  for (let i = 0; i < 20_000; i++) {
    const count = 1 + Math.floor(rnd() * (rnd() < 0.2 ? 120 : 30))
    let text = ''
    for (let j = 0; j < count; j++) text += (rnd() < 0.3 ? FORMS[Math.floor(rnd() * FORMS.length)]!(rnd) : pick(rnd, PIECES)) + (rnd() < 0.5 ? ' ' : '')
    out.push(text)
  }
  return out
})()

/** Each window edge swept one character at a time, `d` filler characters between the two parts. */
const WINDOW_SWEEPS: readonly ((d: number) => string)[] = [
  (d) => `free ${fill(d)} pay ${fill(10)} the agent loop`, // a word's clause, 200 before it
  (d) => `the agent loop ${fill(10)} pay ${fill(d)} free`, // a word's clause, 200 after it
  (d) => `the agent loop ${fill(d)} fee`, // the money-word window, 200 after the phrase
  (d) => `fee ${fill(d)} the agent loop`, // the money-word window, 200 before the phrase
  (d) => `no purchases ${fill(d)} the agent loop pays`, // the phrase's own clause
  (d) => `max ${fill(d)} the agent loop pays`, // the limit window, 120 before
  (d) => `confirm ${fill(d)} it pays from the user's credits`, // the sentence, 400 before
  (d) => `it pays from the user's credits ${fill(d)} confirm`, // the sentences, 800 after
  (d) => `it pays from the user's credits. ${fill(d)} confirm`, // the next sentence, 800 after
  (d) => `never say ${fill(d)} failed`, // the outcome word's clause, 200 after
]
/** The flow word has no window: however far into the clause, it stops the form; past a comma it does not. */
const FLOW_SWEEPS: readonly ((d: number) => string)[] = [
  (d) => `do not tell the user that ${fill(d)} until`,
  (d) => `do not tell the user that ${fill(d)}, until`,
]
const SWEPT: readonly string[] = [...WINDOW_SWEEPS, ...FLOW_SWEEPS].flatMap((make) => Array.from({ length: 900 }, (_, d) => make(d)))

// --- 2. equal to suite 0.19.0 -------------------------------------------------------

const tool = (description: string) => ({ name: 'a', description })

t(`equal: on ${VARIANTS.length} generated variants and ${SWEPT.length} swept inputs, checkTool returns exactly frozen 0.19.0's hits`, () => {
  const differing = [...VARIANTS, ...SWEPT].filter((d) => !isDeepStrictEqual(checkTool(tool(d)), checkTool0190(tool(d))))
  assert.deepStrictEqual(differing.slice(0, 3), [], `${differing.length} inputs differ`)
})

t('equal is not vacuous: many variants are flagged, every window sweep crosses its edge, and the flow sweeps hold either way', () => {
  const flagged = (flag: string, d: string) => checkTool(tool(d)).some((h) => h.flag === flag)
  assert.ok(VARIANTS.filter((d) => flagged('injection_imperative', d)).length > 5_000)
  assert.ok(VARIANTS.filter((d) => flagged('unconfirmed_spending', d)).length > 2_000)
  for (const make of WINDOW_SWEEPS) {
    const flags = new Set(Array.from({ length: 900 }, (_, d) => checkTool(tool(make(d))).map((h) => h.flag).sort().join()))
    assert.ok(flags.size >= 2, `${make(0)}: the sweep never changes the flags`)
  }
  const [stopped, past] = FLOW_SWEEPS.map((make) => Array.from({ length: 900 }, (_, d) => flagged('injection_imperative', make(d))))
  assert.ok(stopped!.every((f) => !f) && past!.every((f) => f), 'a flow word in the clause stops the form at every distance, and one past a comma never does')
})

/** Nothing checks the type of a tool's name or description: any JSON value, or none, reaches checkTool. */
const NON_STRINGS: readonly unknown[] = [
  undefined, null, 0, 123, true, false, [], {}, { 0: ',', length: 3 },
  ...VARIANTS.slice(0, 1_500).flatMap((d, i) => [[d], [d, VARIANTS[i + 1]!], d.split(' '), { text: d }]),
  ...SWEPT.filter((_, i) => i % 9 === 0).map((d) => d.split(',')),
]
/** What a call returns, or the error it throws (both suites throw, for instance, on a hit in an array). */
function outcome(check: (t: { name: string; description?: string }) => HygieneHit[], t: { name: unknown; description?: unknown }) {
  try { return { hits: check(t as { name: string; description?: string }) } }
  catch (e) { return { threw: `${(e as Error).name}: ${(e as Error).message}` } }
}

t(`equal: on ${NON_STRINGS.length} names and as many descriptions that are not strings, checkTool returns or throws exactly what frozen 0.19.0's does`, () => {
  const tools = NON_STRINGS.flatMap((v) => [{ name: v }, { name: 'a', description: v }])
  const differing = tools.filter((x) => !isDeepStrictEqual(outcome(checkTool, x), outcome(checkTool0190, x)))
  assert.deepStrictEqual(differing.slice(0, 3), [], `${differing.length} tools differ`)
  const threw = tools.filter((x) => 'threw' in outcome(checkTool, x)).length
  const hit = tools.filter((x) => { const o = outcome(checkTool, x); return 'hits' in o && o.hits.length > 0 }).length
  assert.ok(threw > 100 && hit > 100, `not vacuous: ${threw} throw, ${hit} return hits`)
})

// --- 3. within suite 0.16.0 ------------------------------------------------------------

/** The note of the one injection_imperative form suite 0.16.0 does not have. */
const NOT_0160_NOTE = '要求不说出缺失、未核验或失败的检查'
const DESCRIPTION = "工具 'a' 的 description "
/** One character standing for text[i]'s word-ness ('' outside the text), so a cut keeps every \b. */
const edge = (text: string, i: number) => (i < 0 || i >= text.length ? '' : /\w/.test(text[i]!) ? 'a' : ' ')
const has0160 = (text: string, note: string, at?: number) =>
  checkTool0160(tool(text)).some((h) => h.note === DESCRIPTION + note && (at === undefined || h.at === at))

/** Every injection_imperative hit of `check` on `text` that is not within suite 0.16.0, as a reason; and the declared ones. */
function outside0160(check: (t: { name: string; description: string }) => HygieneHit[], text: string): { outside: string[]; declared: number } {
  const outside: string[] = []
  let declared = 0
  for (const hit of check(tool(text)).filter((h) => h.flag === 'injection_imperative')) {
    const note = hit.note.startsWith(DESCRIPTION) ? hit.note.slice(DESCRIPTION.length) : undefined
    if (note === NOT_0160_NOTE) { declared++; continue }
    const rule = IMPERATIVES.find(([, n]) => n === note)?.[0]
    const at = hit.at!
    if (rule === undefined) outside.push(`no rule has the note of ${JSON.stringify(hit.note)}`)
    else if (typeof rule === 'function') {
      // The scan reports where suite 0.16.0's pattern starts: it must start there.
      const before = edge(text, at - 1)
      if (!has0160(before + text.slice(at), note!, before.length)) outside.push(`${note} at ${at}: 0.16.0 does not match there`)
    } else {
      const sticky = new RegExp(rule.source, rule.flags + 'y')
      sticky.lastIndex = at
      const m = sticky.exec(text)
      if (m === null) outside.push(`${note} at ${at}: the rule does not match there`)
      else if (!has0160(edge(text, at - 1) + m[0] + edge(text, at + m[0].length), note!)) outside.push(`${note} at ${at}: no 0.16.0 match inside ${JSON.stringify(m[0])}`)
    }
  }
  return { outside, declared }
}

t(`within 0.16.0: on ${VARIANTS.length} generated variants every injection_imperative hit but the declared form contains suite 0.16.0's match with its note`, () => {
  let hits = 0, declared = 0
  const outside: string[] = []
  for (const text of VARIANTS) {
    const r = outside0160(checkTool, text)
    hits += checkTool(tool(text)).filter((h) => h.flag === 'injection_imperative').length
    declared += r.declared
    outside.push(...r.outside.map((o) => `${o} in ${JSON.stringify(text.slice(0, 120))}`))
  }
  console.log(`       ${hits} injection_imperative hits, ${declared} of them the declared form, ${outside.length} outside 0.16.0`)
  assert.ok(hits - declared > 10_000, 'too few hits to say anything')
  assert.deepStrictEqual(outside.slice(0, 3), [], `${outside.length} hits outside 0.16.0`)
})

t('within 0.16.0 has teeth: a hit 0.16.0 does not have, moved, unknown or a near miss, is caught', () => {
  const plus = (extra: (text: string) => HygieneHit[]) => (t: { name: string; description: string }) => [...checkTool(t), ...extra(t.description)]
  const at = (note: string, i: number): HygieneHit => ({ flag: 'injection_imperative', note: DESCRIPTION + note, at: i })
  const conceal = IMPERATIVES[2]![1], prompt = IMPERATIVES[3]![1]
  assert.equal(conceal, '要求对用户隐瞒信息')
  assert.equal(prompt, '提及 system / developer prompt')
  const text = 'x do not tell your user that, your system message'
  assert.deepStrictEqual(outside0160(checkTool, text).outside, [], 'precondition: the live rules flag none of it')
  assert.equal(outside0160(plus(() => [at(conceal, 2)]), text).outside.length, 1, '"do not tell your user"')
  assert.equal(outside0160(plus(() => [at(prompt, 30)]), text).outside.length, 1, '"your system message"')
  assert.equal(outside0160(plus(() => [at('something else', 0)]), text).outside.length, 1, 'an unknown note')
  assert.equal(outside0160(plus(() => [at(conceal, 3)]), 'x do not tell the user that').outside.length, 1, 'one character late')
})

// --- 4. linear ---------------------------------------------------------------------------

const MIB2 = 2_097_152
const repeatTo = (unit: string, tail: string) => unit.repeat(Math.ceil(MIB2 / unit.length)).slice(0, MIB2 - tail.length) + tail

t('linear: a 2 MiB description of each shape suite 0.19.0 took 2 to 140 s of CPU on is checked in under 10 s', () => {
  for (const [label, text] of [
    ['one clause of "do not tell the user that" candidates', repeatTo('do not tell the user that it works and ', ' until it is done.')],
    ['one clause of agent-loop phrases and free money words', repeatTo('the agent loop pays a free fee and the cost ', '.')],
    ['paying from the user\'s credits, confirmed, over and over', repeatTo("it pays from the user's credits and you confirm ", '.')],
  ] as const) {
    const start = performance.now()
    checkTool(tool(text))
    const ms = performance.now() - start
    assert.ok(ms < 10_000, `${label}: ${ms.toFixed(0)} ms`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
