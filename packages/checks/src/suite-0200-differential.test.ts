/**
 * Suite 0.20.0 differential: the evidence that a metadata document that is a JSON
 * array now draws OBSERVED_RISK auth_metadata_not_json_object instead of VERIFIED,
 * and that no other input changes its verdict or its requests.
 *
 * Two parties, called the way auth.test.ts calls the frozen 0.7.1 one:
 *
 *   1. NEW: ./auth.ts, judgeAuthMetadata (the tools/call entry) and
 *      judgeAuthMetadataFromGate (the credential-gate entry).
 *   2. OLD: ./frozen/suite-0.18.0/src/auth.ts, called with that directory's own
 *      createProbeContext. It is byte for byte the auth.ts suite 0.19.3 shipped
 *      (auth.ts did not change from suite 0.14.0 to 0.19.3); the first test
 *      recomputes its git blob id, and the second proves the live file is that
 *      file plus the one guard line and its comment.
 *
 * Inputs: every body below, as the one metadata document the challenge points at,
 * with each challenge header, through both entries, plus the tools/call entry on a
 * status that carries no challenge. Invariant, for every input: the requests made
 * are identical, and so is the verdict object, EXCEPT where the body parses to a
 * JSON array, where it must be VERIFIED (old) and OBSERVED_RISK
 * auth_metadata_not_json_object (new), and nothing else may differ.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { judgeAuthMetadata, judgeAuthMetadataFromGate } from './auth.ts'
import { judgeAuthMetadata as oldJudgeAuthMetadata, judgeAuthMetadataFromGate as oldJudgeAuthMetadataFromGate } from './frozen/suite-0.18.0/src/auth.ts'
import { createProbeContext } from './wire.ts'
import { createProbeContext as oldCreateProbeContext } from './frozen/suite-0.18.0/src/wire.ts'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}
const readHere = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8').split('\r\n').join('\n')

/** `git rev-parse aaf7087a:packages/checks/src/auth.ts` — suite 0.19.3's auth.ts. */
const SUITE_0193_AUTH_BLOB = '15f777474121e48ec2eedf39fa915005ba268669'
const OLD_GUARD = "  if (typeof metadata !== 'object' || metadata === null) {\n"
const NEW_GUARD =
  "  // Suite 0.20.0: a JSON array is not a JSON object (typeof says 'object' for it), so it takes this branch too.\n" +
  "  if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {\n"

await t('the old side is suite 0.19.3\'s auth.ts: frozen/suite-0.18.0/src/auth.ts is the aaf7087a blob, git blob id recomputed', () => {
  assert.equal(blobId(readHere('./frozen/suite-0.18.0/src/auth.ts')), SUITE_0193_AUTH_BLOB)
})

await t('the live auth.ts is that file with exactly one change: the guard gains || Array.isArray(metadata), and a comment above it', () => {
  const old = readHere('./frozen/suite-0.18.0/src/auth.ts')
  assert.equal(old.split(OLD_GUARD).length, 2, 'the old guard occurs once')
  assert.equal(readHere('./auth.ts'), old.replace(OLD_GUARD, NEW_GUARD))
})

await t('packages/checks ships this change as suite 0.20.0 and registry 0.19.0, and has not gone back below them', () => {
  const parse = (v: string) => v.split('.').map(Number)
  const atLeast = (v: string, [maj, min]: [number, number]) => { const [a = NaN, b = NaN] = parse(v); return a > maj || (a === maj && b >= min) }
  assert.ok(atLeast((JSON.parse(readHere('../package.json')) as { version: string }).version, [0, 20]), 'suite_version')
  assert.ok(atLeast((JSON.parse(readHere('../checks.json')) as { registry_version: string }).registry_version, [0, 19]), 'registry_version')
})

const BUDGET: ProbeBudget = { maxRedirects: 3, maxDurationMs: 10_000, maxBodyBytes: 2_097_152, maxRequests: 8 }
const ENDPOINT = 'https://notes-mcp.example.com/mcp'
const META_URL = 'https://notes-mcp.example.com/.well-known/oauth-protected-resource'
const HEADERS: [string, string][] = [
  ['no scope', `Bearer realm="mcp", resource_metadata="${META_URL}"`],
  ['scope notes:read', `Bearer realm="mcp", resource_metadata="${META_URL}", scope="notes:read"`],
  ['scope notes:read notes:write', `Bearer realm="mcp", resource_metadata="${META_URL}", scope="notes:read notes:write"`],
]

/** Each body is served as the metadata document with HTTP 200 unless `status` says otherwise. */
const ARRAYS = [
  '[]', ' [ ] ', '\r\n[]\n', '[[]]', '[[[[[[[[[[]]]]]]]]]]', '[{}]', '[null]', '[0]', '["a"]', '[true,false]', '[1,2,3]',
  '[{"scopes_supported":["notes:read","notes:write"]}]', '[{"resource":"https://notes-mcp.example.com"},{"scopes_supported":[]}]',
  `[${Array.from({ length: 500 }, (_, i) => i).join(',')}]`,
]
const NOT_ARRAYS: [string, number][] = [
  // [body, status]
  ['{}', 200], ['{"a":1}', 200], ['{"resource":"https://notes-mcp.example.com"}', 200],
  ['{"scopes_supported":["notes:read","notes:write"]}', 200], ['{"scopes_supported":["notes:read"]}', 200], ['{"scopes_supported":[]}', 200],
  ['{"scopes_supported":"notes:read"}', 200], ['{"scopes_supported":null}', 200], ['{"scopes_supported":[1,"notes:read","notes:write"]}', 200],
  ['{"resource":["a","b"],"authorization_servers":[]}', 200], ['{"0":1,"length":1}', 200], ['{"__proto__":[]}', 200],
  ['null', 200], ['0', 200], ['-1.5e3', 200], ['"s"', 200], ['""', 200], ['true', 200], ['false', 200],
  ['', 200], ['{', 200], ['[1,', 200], ['[1,]', 200], ['nope', 200], ['[] []', 200],
  ['[]', 404], ['{}', 404], ['[]', 500], ['[]', 301],
]

type Verdict = { status: string; reason?: { key: string } }
interface Outcome { verdict: Verdict; calls: string[] }

const server = (status: number, body: string, calls: string[]) => async (input: RequestInfo | URL, init?: RequestInit) => {
  calls.push(`${init?.method ?? 'GET'} ${typeof input === 'string' ? input : input instanceof URL ? input.href : input.url}`)
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}

type Entry = 'tools/call 401' | 'gate 401' | 'tools/call 403'
const ENTRIES: Entry[] = ['tools/call 401', 'gate 401', 'tools/call 403']

async function run(side: 'new' | 'old', entry: Entry, header: string, status: number, body: string): Promise<Outcome> {
  const calls: string[] = []
  const ctx = (side === 'new' ? createProbeContext : oldCreateProbeContext)(Date.now())
  const base = { fetchImpl: server(status, body, calls), budget: BUDGET, ctx }
  const answer = entry === 'tools/call 403' ? 403 : 401
  const callResult = { status: answer, headers: new Headers({ 'www-authenticate': header }), bodyText: '', currentEndpoint: ENDPOINT }
  const verdict =
    entry === 'gate 401'
      ? await (side === 'new' ? judgeAuthMetadataFromGate : oldJudgeAuthMetadataFromGate)({ ...base, challenge: { scheme: 'bearer', status: 401, wwwAuthenticate: header } })
      : await (side === 'new' ? judgeAuthMetadata : oldJudgeAuthMetadata)({ ...base, callResult })
  return { verdict: verdict as Verdict, calls }
}

const isArrayBody = (body: string): boolean => { try { return Array.isArray(JSON.parse(body)) } catch { return false } }

let total = 0, differing = 0, expectedDiffering = 0

await t('every input: same requests and the same verdict object on both sides, except the JSON arrays served at 200 behind a 401 challenge that points at them', async () => {
  const inputs: [string, number][] = [...ARRAYS.map((b): [string, number] => [b, 200]), ...NOT_ARRAYS]
  for (const [body, status] of inputs) {
    for (const [headerName, header] of HEADERS) {
      for (const entry of ENTRIES) {
        const where = `${entry}, ${headerName}, HTTP ${status}, body ${JSON.stringify(body.length > 60 ? body.slice(0, 60) + '…' : body)}`
        const now = await run('new', entry, header, status, body)
        const old = await run('old', entry, header, status, body)
        total++
        assert.deepStrictEqual(now.calls, old.calls, `requests: ${where}`)
        const reachesBody = entry !== 'tools/call 403' && status === 200 && isArrayBody(body)
        if (reachesBody) {
          expectedDiffering++
          assert.deepStrictEqual(old.verdict, { status: 'VERIFIED' }, `old: ${where}`)
          assert.deepStrictEqual(now.verdict, { status: 'OBSERVED_RISK', reason: { key: 'auth_metadata_not_json_object' } }, `new: ${where}`)
          differing++
        } else {
          assert.deepStrictEqual(now.verdict, old.verdict, `verdict: ${where}`)
        }
      }
    }
  }
})

await t('coverage: the arrays are exactly the inputs that differ, and both kinds are exercised', () => {
  console.log(`       ${total} inputs, ${differing} differ (all JSON arrays); ${total - differing} identical`)
  assert.equal(total, (ARRAYS.length + NOT_ARRAYS.length) * HEADERS.length * ENTRIES.length)
  assert.equal(differing, expectedDiffering)
  assert.equal(differing, ARRAYS.length * HEADERS.length * 2, 'every array body, behind each header, through the two entries that reach the document')
  assert.ok(total - differing > differing, 'the unchanged inputs outnumber the changed ones')
  assert.ok(NOT_ARRAYS.filter(([b, s]) => s === 200 && !isArrayBody(b)).length > 20, 'a broad set of non-array bodies')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
