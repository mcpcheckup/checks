// Recompute toolset_fingerprint and schema_fingerprint (toolset_projection_version "v1") from a server's
// tools/list answer. Plain Node, standard library only: this file imports nothing from the package whose
// output it reproduces, so a match is two independent implementations of PROJECTION-v1.md agreeing, not
// the package agreeing with itself. src/recompute-script.test.ts holds it to the package on every fixture
// and shows that each of sixteen changes to a single step below (no NFC, locale order, no tie-break, ...) breaks the match.
//
//   node recompute-fingerprints.mjs [page-file ...]     a file of '-' (or no file at all) reads stdin
//
// Each file is ONE tools/list answer, in page order: a JSON-RPC response, its bare result, a bare tools
// array, or an event-stream body carrying the response. Output, one line each:
//   toolset_fingerprint sha256:<64 hex>      or  toolset_fingerprint FAILED <why>
//   schema_fingerprint sha256:<64 hex>       or  schema_fingerprint FAILED <why>
// Exit 0 both computed; 1 one or both FAILED; 2 input unreadable, or a page given after one with no nextCursor
// (the probe would not have asked for it); 3 list incomplete: MCP Checkup records no
// fingerprint for a list it could not read to its end, so neither does this script. Incomplete is decided by
// the probe's own rules (PROJECTION-v1.md, "Which pages are covered"): more than 10 pages or 5,000 tools, a
// nextCursor still present once 10 pages or 5,000 tools are in, one that is not a string, or a last page
// that still has one.
import { createHash } from 'node:crypto'
import { readFileSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// ---- nfc-jcs/v1: NFC-normalize, then RFC 8785 (JCS) --------------------------------------------------

/** Step 1: Unicode Normalization Form C. A lone surrogate cannot be written as UTF-8, so it is refused. */
function nfc(s) {
  const out = s.normalize('NFC')
  for (const ch of out) {
    if (ch.length === 1 && ch.charCodeAt(0) >= 0xd800 && ch.charCodeAt(0) <= 0xdfff) throw new Error('a string holds an unpaired surrogate')
  }
  return out
}

const SHORT_ESCAPES = { '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t' }
/** Shortest JSON escaping: the seven short escapes, any other code unit below U+0020 as \u00xx (lowercase hex), all else as is. */
function quote(s) {
  return '"' + s.replace(/["\\\u0000-\u001f]/g, (c) => SHORT_ESCAPES[c] ?? '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')) + '"'
}

/** Steps 2 and 3: duplicate keys after NFC are refused; keys sorted by UTF-16 code unit; arrays keep their order; no whitespace. */
export function canonicalize(value) {
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('a number is not finite')
    return Object.is(value, -0) ? '0' : String(value) // ECMAScript's own number-to-string, as RFC 8785 says
  }
  if (typeof value === 'string') return quote(nfc(value))
  if (Array.isArray(value)) return '[' + value.map((item) => canonicalize(item)).join(',') + ']'
  if (typeof value === 'object') {
    const originalKey = new Map() // NFC form of a key -> the key as sent
    for (const key of Object.keys(value)) {
      const normalized = nfc(key)
      if (originalKey.has(normalized)) throw new Error('two keys of one object become the same after NFC')
      originalKey.set(normalized, key)
    }
    const members = [...originalKey.keys()].sort().map((key) => quote(key) + ':' + canonicalize(value[originalKey.get(key)]))
    return '{' + members.join(',') + '}'
  }
  throw new Error(`a value of type ${typeof value} has no JSON form`) // undefined, function, symbol, bigint
}

/** "sha256:" and the lowercase hex SHA-256 of the UTF-8 bytes of the canonical text. */
function fingerprint(value) {
  return 'sha256:' + createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')
}

// ---- the v1 projection -----------------------------------------------------------------------------------

function toolName(tool, index) {
  if (typeof tool !== 'object' || tool === null || typeof tool.name !== 'string') throw new Error(`the tool at index ${index} has no string "name"`)
  return tool.name
}

/** toolset_fingerprint input: every tool's name and nothing else, sorted by UTF-16 code unit, duplicates kept. */
export function projectToolset(tools) {
  return tools.map(toolName).sort()
}

/** schema_fingerprint input: {name, inputSchema} per tool, sorted by name, same-named tools by the canonical text of their inputSchema. */
export function projectSchemas(tools) {
  const pairs = tools.map((tool, index) => {
    const name = toolName(tool, index)
    const inputSchema = tool.inputSchema // as sent; a missing one stays undefined and makes the hash fail below
    return { name, inputSchema, sortKey: inputSchema === undefined ? '' : canonicalize(inputSchema) }
  })
  pairs.sort((a, b) => (a.name !== b.name ? (a.name < b.name ? -1 : 1) : a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0))
  return pairs.map(({ name, inputSchema }) => ({ name, inputSchema }))
}

export const toolsetFingerprint = (tools) => fingerprint(projectToolset(tools))
export const schemaFingerprint = (tools) => fingerprint(projectSchemas(tools))

// ---- reading pages ---------------------------------------------------------------------------------------

// The most the probe reads from one tools/list: its registry's budget.max_tools_list_pages and MAX_TOOLS_LISTED.
// This file imports nothing, so the numbers are written out here; a parity test outside this package runs the probe and this script on the same pages and fails if they drift.
export const MAX_PAGES = 10
export const MAX_TOOLS = 5000

/** The `data:` payloads of an event-stream body, one per blank-line-separated event, as a client reads them. */
function eventStreamPayloads(text) {
  return text
    .split(/\r?\n\r?\n/)
    .map((event) => event.split(/\r?\n/).filter((line) => line.startsWith('data:')).map((line) => line.slice(5).replace(/^ /, '')).join('\n'))
    .filter((payload) => payload.length > 0)
}

/** One page: its tools, and its nextCursor (undefined when the key is absent or null; any other value, "" included, names a further page). */
function readPage(text) {
  for (const candidate of [text, ...eventStreamPayloads(text)]) {
    let parsed
    try { parsed = JSON.parse(candidate) } catch { continue }
    if (Array.isArray(parsed)) return { tools: parsed, cursor: undefined }
    const result = parsed !== null && typeof parsed === 'object' && parsed.result !== null && typeof parsed.result === 'object' ? parsed.result : parsed
    if (result !== null && typeof result === 'object' && Array.isArray(result.tools)) {
      return { tools: result.tools, cursor: Object.hasOwn(result, 'nextCursor') && result.nextCursor !== null ? result.nextCursor : undefined }
    }
  }
  throw new Error('no tools array found')
}

/**
 * All pages' tools together, in the order given, and whether the probe would call the list incomplete (then `why` says
 * which rule applies, and no fingerprint may be printed; pages that contradict each other throw). The probe reads
 * page 1, then asks for the next page only while a nextCursor is present, it is a string, fewer than MAX_PAGES pages
 * and fewer than MAX_TOOLS tools are in;
 * a list longer than MAX_TOOLS is cut and called incomplete. Given every page of a list, that comes to: more than
 * MAX_PAGES pages, more than MAX_TOOLS tools, a nextCursor that is not a string, a nextCursor after MAX_TOOLS tools,
 * or one on the last page (which includes a 10th page that names an 11th).
 */
export function collectTools(texts) {
  const pages = texts.map(readPage)
  // The probe stops at the first page with no nextCursor and fingerprints what it has. A page given after one is a list
  // no run of it could have produced: the input contradicts itself, which is not the same as an incomplete list.
  const stray = pages.findIndex((page, index) => index > 0 && pages[index - 1].cursor === undefined)
  if (stray >= 0) throw new Error(`page ${stray + 1} is given after page ${stray}, which has no nextCursor (the probe would not have asked for it)`)
  const tools = pages.flatMap((page) => page.tools)
  let why = null
  if (pages.length === 0) why = 'no page was given'
  else if (pages.length > MAX_PAGES) why = `there are more than ${MAX_PAGES} pages`
  else if (tools.length > MAX_TOOLS) why = `there are more than ${MAX_TOOLS} tools`
  let seen = 0
  pages.forEach((page, index) => {
    seen += page.tools.length
    if (why !== null || page.cursor === undefined) return
    if (index === pages.length - 1) why = 'the last page still has a nextCursor'
    else if (typeof page.cursor !== 'string') why = 'a nextCursor that is not a string is not followed'
    else if (seen >= MAX_TOOLS) why = `a nextCursor is still present after ${MAX_TOOLS} tools`
  })
  return { tools, incomplete: why !== null, why, pages: pages.length }
}

// ---- command line ----------------------------------------------------------------------------------------

function main(args) {
  let list
  try {
    list = collectTools((args.length ? args : ['-']).map((arg) => readFileSync(arg === '-' ? 0 : arg, 'utf8')))
  } catch (error) {
    console.error(`cannot use this input: ${error.message}`)
    return 2
  }
  if (list.incomplete) {
    console.error(`not a list MCP Checkup records a fingerprint for (${list.why}): pass every page, in order, up to the probe's ${MAX_PAGES} pages and ${MAX_TOOLS} tools`)
    return 3
  }
  console.error(`${list.tools.length} tools from ${list.pages} page${list.pages === 1 ? '' : 's'}`)
  let code = 0
  for (const [label, compute] of [['toolset_fingerprint', toolsetFingerprint], ['schema_fingerprint', schemaFingerprint]]) {
    try {
      console.log(`${label} ${compute(list.tools)}`)
    } catch (error) {
      console.log(`${label} FAILED ${error.message}`)
      code = 1
    }
  }
  return code
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) process.exitCode = main(process.argv.slice(2))
