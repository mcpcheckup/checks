import assert from 'node:assert'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { canonicalize } from './canonicalize.ts'
import { digest } from './digest.ts'
import { projectToolset, projectSchemas } from './projections.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('scripts/recompute-fingerprints.mjs ↔ the package (same fingerprints, every spec step pinned)')

// The script is the third-party recomputation: plain Node, written out step by step, importing nothing from
// this package. These tests are what makes "the script follows PROJECTION-v1.md" a checked claim: on every
// fixture it must give the package's own bytes, and with any one spec step changed it must not.
const SCRIPT_PATH = fileURLToPath(new URL('../scripts/recompute-fingerprints.mjs', import.meta.url))
const SCRIPT_SOURCE = readFileSync(SCRIPT_PATH, 'utf8')
const VECTORS_DIR = new URL('../test/vectors/projection-v1/', import.meta.url)
const RFC_INPUT_DIR = new URL('../test/fixtures/rfc8785/input/', import.meta.url)

interface Script {
  canonicalize(value: unknown): string
  toolsetFingerprint(tools: unknown[]): string
  schemaFingerprint(tools: unknown[]): string
  collectTools(texts: string[]): { tools: unknown[]; incomplete: boolean; why: string | null }
  MAX_PAGES: number
  MAX_TOOLS: number
}
async function load(path: string): Promise<Script> {
  return (await import(pathToFileURL(path).href)) as Script
}
const script = await load(SCRIPT_PATH)

/** Run `fn`; return its value, or the string 'threw' — so "both refuse" is comparable. */
function outcome<T>(fn: () => T): T | 'threw' {
  try { return fn() } catch { return 'threw' }
}
async function packageToolset(tools: unknown[]): Promise<string | 'threw'> {
  try { return await digest(projectToolset(tools)) } catch { return 'threw' }
}
async function packageSchema(tools: unknown[]): Promise<string | 'threw'> {
  try { return await digest(projectSchemas(tools)) } catch { return 'threw' }
}
async function assertSameAsPackage(s: Script, tools: unknown[], label: string) {
  assert.equal(outcome(() => s.toolsetFingerprint(tools)), await packageToolset(tools), `${label}: toolset_fingerprint`)
  assert.equal(outcome(() => s.schemaFingerprint(tools)), await packageSchema(tools), `${label}: schema_fingerprint`)
}

// ---- the recorded vectors ---------------------------------------------------------------------------------

interface Vector { input: { tools: unknown[] }; jcs: string; toolset_fingerprint: string; schema_fingerprint: string }
const vectorFiles = readdirSync(VECTORS_DIR).filter((f) => f.endsWith('.json')).sort()

await t('there are vectors to check (the loop below is not vacuous), including the real mcpcheckup/mcp capture', () => {
  assert.ok(vectorFiles.length >= 4, `expected at least 4 vector files, found ${vectorFiles.length}`)
  assert.ok(vectorFiles.includes('real-mcpcheckup-mcp.json'))
})

for (const file of vectorFiles) {
  const vector = JSON.parse(readFileSync(new URL(file, VECTORS_DIR), 'utf8')) as Vector
  await t(`${file}: the script reproduces the recorded canonical text and both recorded fingerprints`, () => {
    assert.equal(script.canonicalize(vector.input), vector.jcs)
    assert.equal(script.toolsetFingerprint(vector.input.tools), vector.toolset_fingerprint)
    assert.equal(script.schemaFingerprint(vector.input.tools), vector.schema_fingerprint)
  })
}

// ---- canonical text: the six RFC 8785 inputs, then random JSON ---------------------------------------------

for (const file of readdirSync(RFC_INPUT_DIR).filter((f) => f.endsWith('.json')).sort()) {
  await t(`rfc8785/${file}: the script's canonical text equals the package's`, () => {
    const value = JSON.parse(readFileSync(new URL(file, RFC_INPUT_DIR), 'utf8')) as unknown
    assert.equal(script.canonicalize(value), canonicalize(value))
  })
}

/** A small seeded generator (xorshift32): the same seed always gives the same values, so a failure replays. */
function rng(seed: number) {
  let s = seed >>> 0 || 1
  const next = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 0x100000000 }
  return { next, int: (n: number) => Math.floor(next() * n), pick: <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)]! }
}
const PIECES = ['a', 'B', 'z', '_', '-', '0', ' ', '"', '\\', '/', '\u0001', '\u001f', '\u007f', 'é', 'é', 'Å', 'Å', 'ﬞ', 'דּ', '\u{1F600}', '\u{10000}', ' ']
function genString(r: ReturnType<typeof rng>): string {
  let out = ''
  for (let i = r.int(5); i > 0; i--) out += r.pick(PIECES)
  return out
}
const NUMBERS = [0, -0, 1, -1, 1.5, 0.1, 1e21, 1e-7, 123456789012345680000, 5e-324, Number.MAX_SAFE_INTEGER, 2 ** 53 + 2]
function genValue(r: ReturnType<typeof rng>, depth: number): unknown {
  const kind = r.int(depth > 3 ? 4 : 7)
  if (kind === 0) return null
  if (kind === 1) return r.next() < 0.5
  if (kind === 2) return r.pick(NUMBERS)
  if (kind === 3) return genString(r)
  if (kind === 4 || kind === 5) return Array.from({ length: r.int(4) }, () => genValue(r, depth + 1))
  const obj: Record<string, unknown> = {}
  for (let i = r.int(4); i > 0; i--) obj[genString(r)] = genValue(r, depth + 1)
  return obj
}
function genTools(r: ReturnType<typeof rng>): unknown[] {
  return Array.from({ length: r.int(6) }, () => {
    const tool: Record<string, unknown> = { name: r.next() < 0.97 ? genString(r) : r.pick([1, null]) }
    if (r.next() < 0.9) tool.inputSchema = genValue(r, 0)
    if (r.next() < 0.5) tool.description = genString(r)
    return tool
  })
}

await t('2,000 seeded random JSON values: the script and the package give the same canonical text, or both refuse', () => {
  const r = rng(20261024)
  let refused = 0
  for (let i = 0; i < 2000; i++) {
    const value = genValue(r, 0)
    const expected = outcome(() => canonicalize(value))
    if (expected === 'threw') refused++
    assert.equal(outcome(() => script.canonicalize(value)), expected, `case ${i}: ${JSON.stringify(value)}`)
  }
  assert.ok(refused < 2000, 'the generator must produce values both implementations accept')
})

await t('2,000 seeded random tool lists: both fingerprints equal the package\'s, or both refuse', async () => {
  const r = rng(20261025)
  let accepted = 0
  for (let i = 0; i < 2000; i++) {
    const tools = genTools(r)
    await assertSameAsPackage(script, tools, `case ${i}: ${JSON.stringify(tools)}`)
    if (outcome(() => script.schemaFingerprint(tools)) !== 'threw') accepted++
  }
  assert.ok(accepted > 100, `only ${accepted} of 2000 lists were fingerprintable — the generator is not exercising the happy path`)
})

// ---- pages ---------------------------------------------------------------------------------------------------

const rpc = (tools: unknown[], nextCursor?: unknown) =>
  JSON.stringify({ jsonrpc: '2.0', id: 1, result: { tools, ...(nextCursor === undefined ? {} : { nextCursor }) } })

await t('pages are concatenated: the fingerprints of three pages equal those of the whole list, wherever the page boundaries fall and in whatever order the server sent the tools', async () => {
  const tools = JSON.parse(readFileSync(new URL('real-mcpcheckup-mcp.json', VECTORS_DIR), 'utf8')).input.tools as unknown[]
  assert.ok(tools.length >= 3)
  const pages = [tools.slice(0, 2), tools.slice(2, 3), tools.slice(3)]
  const texts = [rpc(pages[0]!, 'c1'), rpc(pages[1]!, 'c2'), rpc(pages[2]!)]
  const joined = script.collectTools(texts)
  assert.equal(joined.incomplete, false)
  await assertSameAsPackage(script, joined.tools, 'paged')
  assert.equal(script.toolsetFingerprint(joined.tools), await packageToolset(tools))
  assert.equal(script.schemaFingerprint(joined.tools), await packageSchema(tools))
  const resplit = script.collectTools([rpc([...tools].reverse().slice(0, 1), 'c1'), rpc([...tools].reverse().slice(1, 2), 'c2'), rpc([...tools].reverse().slice(2))])
  assert.equal(resplit.incomplete, false)
  assert.equal(script.toolsetFingerprint(resplit.tools), script.toolsetFingerprint(tools))
  assert.equal(script.schemaFingerprint(resplit.tools), script.schemaFingerprint(tools))
})

await t('a last page that still has a nextCursor makes the list incomplete — null, absent and any other value are told apart as the probe tells them apart', () => {
  const some = [{ name: 'a', inputSchema: {} }]
  assert.equal(script.collectTools([rpc(some, 'next')]).incomplete, true)
  assert.equal(script.collectTools([rpc(some, '')]).incomplete, true)
  assert.equal(script.collectTools([rpc(some, 7)]).incomplete, true)
  assert.equal(script.collectTools([rpc(some, null)]).incomplete, false)
  assert.equal(script.collectTools([rpc(some)]).incomplete, false)
  assert.equal(script.collectTools([rpc(some, 'c1'), rpc(some, 'c2')]).incomplete, true, 'the cursor on the LAST page is the one that counts')
})

// The probe reads at most 10 pages and 5,000 tools and records no fingerprint for a list it could not read to its end
// (PROJECTION-v1.md, "Which pages are covered"). The script has to refuse the same lists, or it prints a value where the
// probe records none. Whether these numbers are the probe's own is pinned where the probe can be imported: a parity
// test outside this package runs the probe and this script on the same pages.
const named = (count: number, from = 0) => Array.from({ length: count }, (_, i) => ({ name: `t${from + i}`, inputSchema: {} }))
/** `count` one-tool pages, each but the last naming the next one; the last names `lastCursor` when given. */
const chainOfPages = (count: number, lastCursor?: unknown) => Array.from({ length: count }, (_, i) => rpc(named(1, i), i < count - 1 ? `c${i + 1}` : lastCursor))

await t('the caps: exactly 10 pages is complete, an 11th is not; exactly 5,000 tools is complete, a 5,001st is not', () => {
  assert.equal(script.collectTools(chainOfPages(10)).incomplete, false, '10 pages, the last without a nextCursor')
  assert.equal(script.collectTools(chainOfPages(11)).incomplete, true, '11 pages')
  assert.equal(script.collectTools(chainOfPages(12)).incomplete, true, '12 pages')
  assert.equal(script.collectTools([rpc(named(5000))]).incomplete, false, '5,000 tools in one page')
  assert.equal(script.collectTools([rpc(named(5001))]).incomplete, true, '5,001 tools in one page')
  assert.equal(script.collectTools([rpc(named(2500), 'c1'), rpc(named(2500, 2500))]).incomplete, false, '2,500 + 2,500 tools')
  assert.equal(script.collectTools([rpc(named(2500), 'c1'), rpc(named(2501, 2500))]).incomplete, true, '2,500 + 2,501 tools')
  assert.equal(script.collectTools([rpc(named(4999), 'c1'), rpc(named(1, 4999))]).incomplete, false, '4,999 + 1 tools')
})

await t('the caps: where the probe stops asking for pages the list is incomplete, whatever pages follow', () => {
  assert.equal(script.collectTools(chainOfPages(10, 'c10')).incomplete, true, 'the 10th page still names a further page: the probe does not ask for an 11th')
  assert.equal(script.collectTools([rpc(named(5000), 'c1'), rpc(named(0))]).incomplete, true, '5,000 tools are in and a nextCursor is still present: the probe does not ask for the next page')
  assert.equal(script.collectTools([rpc(named(1), 7), rpc(named(1, 1))]).incomplete, true, 'a nextCursor that is not a string is not followed')
  assert.equal(script.collectTools([rpc(named(1), ''), rpc(named(1, 1))]).incomplete, false, 'an empty string is a string')
})

await t('the caps are named in the script and in PROJECTION-v1.md, and the document says the same numbers; the public script points at no file outside this package', () => {
  assert.ok(!/wiring[.]test|apps[/]/.test(SCRIPT_SOURCE), 'the script names no test or directory outside this package')
  assert.deepEqual([script.MAX_PAGES, script.MAX_TOOLS], [10, 5000])
  const doc = readFileSync(new URL('../PROJECTION-v1.md', import.meta.url), 'utf8').replace(/\s+/g, ' ')
  assert.ok(doc.includes(`reads at most ${script.MAX_PAGES} pages and at most ${script.MAX_TOOLS.toLocaleString('en-US')} tools`), 'PROJECTION-v1.md states the probe\'s caps')
})

await t('a page may be a JSON-RPC response, a bare result, a bare tools array, or an event-stream body; all give the same tools', () => {
  const tools = [{ name: 'a', inputSchema: { type: 'object' } }]
  const shapes = [
    rpc(tools),
    JSON.stringify({ tools }),
    JSON.stringify(tools),
    `event: message\ndata: ${rpc(tools)}\n\n`,
    `event: message\r\ndata: ${rpc(tools)}\r\n\r\n`,
    `: keep-alive\n\nevent: message\ndata: ${rpc(tools)}\n\n`,
  ]
  for (const text of shapes) assert.deepEqual(script.collectTools([text]).tools, tools, text)
})

await t('a page with no readable tools array is refused, not skipped', () => {
  for (const text of ['', 'not json', '{}', '{"result":{}}', '{"result":{"tools":"x"}}', '{"jsonrpc":"2.0","error":{"code":-32601,"message":"no"}}', 'data: nope\n\n']) {
    assert.throws(() => script.collectTools([text]), Error, JSON.stringify(text))
  }
})

// ---- the command line ----------------------------------------------------------------------------------------

function run(args: string[], input?: string) {
  const r = spawnSync(process.execPath, [SCRIPT_PATH, ...args], { encoding: 'utf8', ...(input === undefined ? {} : { input }) })
  return { code: r.status, out: r.stdout, err: r.stderr }
}
const tmp = mkdtempSync(join(tmpdir(), 'recompute-'))
const real = JSON.parse(readFileSync(new URL('real-mcpcheckup-mcp.json', VECTORS_DIR), 'utf8')) as Vector

await t('CLI: a file argument and stdin both print the two fingerprints, one per line, and exit 0', () => {
  const file = join(tmp, 'list.json')
  writeFileSync(file, rpc(real.input.tools))
  const expected = `toolset_fingerprint ${real.toolset_fingerprint}\nschema_fingerprint ${real.schema_fingerprint}\n`
  const byFile = run([file])
  assert.deepEqual([byFile.code, byFile.out], [0, expected], byFile.err)
  const byStdin = run([], rpc(real.input.tools))
  assert.deepEqual([byStdin.code, byStdin.out], [0, expected], byStdin.err)
  const byDash = run(['-'], rpc(real.input.tools))
  assert.deepEqual([byDash.code, byDash.out], [0, expected], byDash.err)
})

await t('CLI: several files are the pages of one list, in the order given', () => {
  const [a, b] = [join(tmp, 'p1.json'), join(tmp, 'p2.json')]
  writeFileSync(a, rpc(real.input.tools.slice(0, 3), 'page-2'))
  writeFileSync(b, rpc(real.input.tools.slice(3)))
  const r = run([a, b])
  assert.equal(r.code, 0, r.err)
  assert.equal(r.out, `toolset_fingerprint ${real.toolset_fingerprint}\nschema_fingerprint ${real.schema_fingerprint}\n`)
})

await t('CLI: a page given after one with no nextCursor contradicts itself — exit 2 and no fingerprint, not exit 3: the probe would have stopped at that page and fingerprinted what came before', () => {
  const [a, b] = [join(tmp, 'stray-1.json'), join(tmp, 'stray-2.json')]
  writeFileSync(a, rpc(named(2)))
  writeFileSync(b, rpc(named(2, 2)))
  const stray = run([a, b])
  assert.deepEqual([stray.code, stray.out], [2, ''], stray.err)
  assert.match(stray.err, /no nextCursor/)
  assert.equal(run([b, a]).code, 2, 'either order')
  writeFileSync(a, rpc(named(2), null))
  assert.equal(run([a, b]).code, 2, 'a nextCursor of null is no nextCursor')
  writeFileSync(a, rpc(named(2), 'c1'))
  assert.equal(run([a, b]).code, 0, 'the same two pages with the first naming the second are a list')
})

await t('a page given after one with no nextCursor is refused, not read: a missing cursor, a null one, a bare tools array, the middle of three pages, an 11th page after a 10th that names none', () => {
  const [one, two] = [named(1), named(1, 1)]
  for (const [what, texts] of [
    ['no cursor then a page', [rpc(one), rpc(two)]],
    ['null cursor then a page', [rpc(one, null), rpc(two)]],
    ['bare tools array then a page', [JSON.stringify(one), rpc(two)]],
    ['the middle of three', [rpc(one, 'c1'), rpc(two), rpc(named(1, 2))]],
    ['an 11th page after a 10th that names none', [...chainOfPages(10), rpc(named(1, 10))]],
  ] as Array<[string, string[]]>) assert.throws(() => script.collectTools(texts), /no nextCursor/, what)
})

await t('CLI: an incomplete list prints no fingerprint, says why on stderr and exits 3', () => {
  const r = run([], rpc(real.input.tools, 'more'))
  assert.equal(r.code, 3)
  assert.equal(r.out, '')
  assert.match(r.err, /nextCursor/)
})

await t('CLI: 5,001 tools, or 11 pages, print no fingerprint, say which cap on stderr and exit 3 — and exactly 5,000 tools or 10 pages are computed', () => {
  const tooMany = run([], rpc(named(5001)))
  assert.deepEqual([tooMany.code, tooMany.out], [3, ''])
  assert.match(tooMany.err, /5,?000 tools/)
  const files = Array.from({ length: 11 }, (_, i) => join(tmp, `cap-${i}.json`))
  chainOfPages(11).forEach((text, i) => writeFileSync(files[i]!, text))
  const tooManyPages = run(files)
  assert.deepEqual([tooManyPages.code, tooManyPages.out], [3, ''])
  assert.match(tooManyPages.err, /10 pages/)
  const tenFiles = Array.from({ length: 10 }, (_, i) => join(tmp, `cap10-${i}.json`))
  chainOfPages(10).forEach((text, i) => writeFileSync(tenFiles[i]!, text))
  assert.equal(run(tenFiles).code, 0, '10 pages, the last without a nextCursor')
  assert.equal(run([], rpc(named(5000))).code, 0, '5,000 tools')
})

await t('CLI: every way the projection or the canonicalization can refuse is exit 1 with FAILED on the line it concerns', () => {
  const refusals: Array<[string, string, string]> = [
    ['no string name', '{"tools":[{"name":7,"inputSchema":{}}]}', 'toolset_fingerprint FAILED'],
    ['no inputSchema', '{"tools":[{"name":"a"}]}', 'schema_fingerprint FAILED'],
    ['two keys that become one after NFC', '{"tools":[{"name":"a","inputSchema":{"\\u00e9":1,"e\\u0301":2}}]}', 'schema_fingerprint FAILED'],
    ['an unpaired surrogate', '{"tools":[{"name":"a\\ud800","inputSchema":{}}]}', 'toolset_fingerprint FAILED'],
    ['a number that is not finite', '{"tools":[{"name":"a","inputSchema":{"n":1e999}}]}', 'schema_fingerprint FAILED'],
  ]
  for (const [what, input, line] of refusals) {
    const r = run([], input)
    assert.equal(r.code, 1, `${what}: ${r.err}`)
    assert.ok(r.out.split('\n').some((l) => l.startsWith(line)), `${what}: ${r.out}`)
  }
})

await t('CLI: a tool without inputSchema leaves schema_fingerprint FAILED while toolset_fingerprint still prints; exit 1', async () => {
  const tools = [{ name: 'a', inputSchema: {} }, { name: 'b' }]
  const r = run([], rpc(tools))
  assert.equal(r.code, 1)
  assert.equal(r.out.split('\n')[0], `toolset_fingerprint ${await packageToolset(tools)}`)
  assert.match(r.out.split('\n')[1]!, /^schema_fingerprint FAILED /)
})

await t('CLI: a tool without a string name fails both fingerprints; unreadable input exits 2', () => {
  const bad = run([], rpc([{ name: 1 }]))
  assert.equal(bad.code, 1)
  assert.match(bad.out, /^toolset_fingerprint FAILED .*\nschema_fingerprint FAILED /)
  const unreadable = run([], 'not json')
  assert.equal(unreadable.code, 2)
  assert.equal(unreadable.out, '')
})

// ---- every spec step is pinned: change one in the script's own source and the match is lost -----------------------

// Each tool carries fields the projection must ignore (description, annotations). The rest is chosen so that every
// step below changes a fingerprint: capital vs small letters and an astral vs a BMP character (code-unit order, not
// locale order), a decomposed é that NFC rewrites, two names that sort one way as sent and the other after NFC, a
// control character, an unsorted key set, an array whose order matters, three tools called "dup".
const SENSITIVE: unknown[] = [
  { name: 'b_tool', description: 'd1', annotations: { readOnlyHint: true }, inputSchema: { type: 'object', properties: { zeta: { type: 'string', enum: ['b', 'a'], title: 'tab\u001fcafé' }, alpha: { type: 'number', minimum: -0, maximum: 1e21 } }, required: ['zeta'] } },
  { name: 'B_tool', description: 'd2', inputSchema: { type: 'object', properties: { n: { type: 'integer', default: 5 } } } },
  { name: 'café', description: 'd3', inputSchema: { type: 'object' } },
  { name: 'cafà', description: 'd4', inputSchema: { type: 'object' } },
  { name: '\u{1F600}', description: 'd5', inputSchema: {} },
  { name: 'ﬞ', description: 'd6', inputSchema: {} },
  { name: 'dup', description: 'd7', inputSchema: { type: 'object', properties: { z: {} } } },
  { name: 'dup', description: 'd8', inputSchema: { type: 'object', properties: { a: {} } } },
  { name: 'dup', description: 'd9', inputSchema: { type: 'object', properties: { a: {} } } },
]

interface Mutant { name: string; edits: [find: string, replace: string][]; tools?: unknown[]; paged?: true }
const MUTANTS: Mutant[] = [
  { name: 'no NFC step', edits: [["const out = s.normalize('NFC')", 'const out = s']] },
  { name: 'names sorted by locale instead of by UTF-16 code unit', edits: [['tools.map(toolName).sort()', 'tools.map(toolName).sort((a, b) => a.localeCompare(b))']] },
  { name: 'names sorted after NFC instead of as sent', edits: [['tools.map(toolName).sort()', 'tools.map((tool, index) => toolName(tool, index).normalize("NFC")).sort()']] },
  { name: 'duplicate names dropped from toolset_fingerprint', edits: [['tools.map(toolName).sort()', '[...new Set(tools.map(toolName))].sort()']] },
  { name: 'no tie-break between same-named tools', edits: [['a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0', '0']] },
  { name: 'tie-break in the opposite direction', edits: [['a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0', 'b.sortKey < a.sortKey ? -1 : b.sortKey > a.sortKey ? 1 : 0']] },
  { name: 'description added to the schema projection', edits: [['return { name, inputSchema, sortKey:', 'return { name, inputSchema, description: tool.description, sortKey:'], ['pairs.map(({ name, inputSchema }) => ({ name, inputSchema }))', 'pairs.map(({ name, inputSchema, description }) => ({ name, inputSchema, description }))']] },
  { name: 'object keys left in the order sent', edits: [['[...originalKey.keys()].sort()', '[...originalKey.keys()]']] },
  { name: 'array elements sorted', edits: [['value.map((item) => canonicalize(item))', '[...value].sort().map((item) => canonicalize(item))']] },
  { name: 'control characters escaped with uppercase hex', edits: [[".toString(16).padStart(4, '0')", ".toString(16).toUpperCase().padStart(4, '0')"]] },
  { name: 'numbers written some other way than ECMAScript writes them', edits: [['String(value)', 'value.toFixed(1)']] },
  { name: 'hash taken over UTF-16 instead of UTF-8', edits: [["canonicalize(value), 'utf8'", "canonicalize(value), 'utf16le'"]] },
  { name: 'no "sha256:" prefix', edits: [["'sha256:' + createHash", 'createHash']] },
  { name: 'a lone surrogate accepted', tools: [{ name: 'a\ud800', inputSchema: {} }], edits: [["throw new Error('a string holds an unpaired surrogate')", 'void 0']] },
  { name: 'two keys that collide after NFC accepted', tools: [{ name: 'a', inputSchema: { 'é': 1, 'é': 2 } }], edits: [["throw new Error('two keys of one object become the same after NFC')", 'void 0']] },
  { name: 'only the first page used', paged: true, edits: [['pages.flatMap((page) => page.tools)', 'pages[0].tools']] },
]

await t('control: the unchanged script matches the package on the sensitive fixture, and the fixture is fingerprintable', async () => {
  await assertSameAsPackage(script, SENSITIVE, 'sensitive fixture')
  assert.notEqual(outcome(() => script.toolsetFingerprint(SENSITIVE)), 'threw')
  assert.notEqual(outcome(() => script.schemaFingerprint(SENSITIVE)), 'threw')
})

const mutantDir = mkdtempSync(join(tmpdir(), 'recompute-mutants-'))
let mutantIndex = 0
for (const mutant of MUTANTS) {
  await t(`mutant: ${mutant.name} -> the fingerprints no longer match the package`, async () => {
    let source = SCRIPT_SOURCE
    for (const [find, replace] of mutant.edits) {
      assert.equal(source.split(find).length - 1, 1, `the text to change must occur exactly once in the script: ${find}`)
      source = source.replace(find, () => replace)
    }
    const path = join(mutantDir, `mutant-${mutantIndex++}.mjs`)
    writeFileSync(path, source)
    const mutated = await load(path)
    const tools = mutant.tools ?? SENSITIVE
    if (mutant.paged) {
      const texts = [rpc(tools.slice(0, 3), 'c1'), rpc(tools.slice(3, 6), 'c2'), rpc(tools.slice(6))]
      const joined = mutated.collectTools(texts).tools
      assert.notEqual(outcome(() => mutated.toolsetFingerprint(joined)), await packageToolset(tools))
      assert.notEqual(outcome(() => mutated.schemaFingerprint(joined)), await packageSchema(tools))
      return
    }
    const toolsetDiffers = outcome(() => mutated.toolsetFingerprint(tools)) !== (await packageToolset(tools))
    const schemaDiffers = outcome(() => mutated.schemaFingerprint(tools)) !== (await packageSchema(tools))
    assert.ok(toolsetDiffers || schemaDiffers, 'the change went unnoticed: both fingerprints still equal the package\'s')
  })
}
rmSync(mutantDir, { recursive: true, force: true })

rmSync(tmp, { recursive: true, force: true })

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
