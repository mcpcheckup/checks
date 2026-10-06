/**
 * T96 differential (suite 0.10.0) — the evidence that letting a 2xx
 * server/discover answer fall back to the legacy initialize handshake changed
 * nothing but the runs it was meant to change.
 *
 * T96 rule: for the answer to server/discover, a 2xx and a
 * 4xx are read alike —
 *   - a 2xx carrying a usable discover result ⇒ modern (a 4xx never is);
 *   - a recognized modern JSON-RPC error (-32020 / -32021 / -32022) ⇒ FAILED
 *     handshake_discover_rejected { status, jsonrpc_error_code };
 *   - anything else ⇒ performLegacyHandshake.
 * 3xx and 5xx are untouched. Suite 0.9.0 read the body of a 200 only, never
 * fell back on one, and recorded every other 2xx as handshake_discover_http_error.
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.9.0 — ./frozen/suite-0.9.0/{probe,protocol,auth,error-taxonomy}.ts,
 *      byte for byte the suite 0.9.0 (16941d1) files apart from a four-line
 *      `// FROZEN:` header and `../../` import paths (the first test below
 *      recomputes each git blob id). auth.ts and error-taxonomy.ts are frozen
 *      too, only so that nothing the frozen probe.ts reaches reads the live
 *      protocol.ts. Everything else it reaches is shared with the live code
 *      and pinned by the second test (CLOSURE_090_BLOBS).
 *
 * Inputs:
 *   A. The T86b input set: the whole fixture corpus crossed with
 *      its budget / GuardSignals / baseline / GET-redirect variants (harness
 *      and variants verbatim from guard-error-classification-differential.test.ts,
 *      minus its throwAt).
 *   B. The T73 discover stage (statuses, content-types, corpus bodies and
 *      discover-specific bodies verbatim from failed-reasons-differential.test.ts),
 *      plus NEW_2XX and MORE_5XX statuses; the legacy stages pinned to a
 *      success, and — for PINNED_STATUSES — also to a modern-only server's
 *      -32601 answer to initialize and to a 401 credential gate on initialize.
 *
 * Each input's class is read off the frozen 0.9.0 run (never the
 * implementation's): the status of the one server/discover answer, and the
 * reason 0.9.0 gave discovery_handshake (for a 2xx other than 200, which
 * 0.9.0 never parsed, the reason 0.9.0 gives the same input with the discover
 * status set to 200):
 *   - no 2xx discover answer, or the handshake never returned ⇒ UNAFFECTED;
 *   - a 200 carrying a usable discover result ⇒ UNAFFECTED;
 *   - FALLBACK — 0.9.0 said handshake_discover_{not_jsonrpc,jsonrpc_error
 *     (unrecognized code),no_supported_versions}, at 200 or (read at 200) at
 *     another 2xx;
 *   - REJECTED — handshake_discover_jsonrpc_error with a recognized code;
 *   - MODERN — a usable discover result on a 2xx other than 200.
 * Input set B's class is also predicted from the script alone by the T73b
 * ORACLE's reading (verbatim), and must agree; input set A's affected fixtures
 * are listed by name (T96_AFFECTED_FIXTURES).
 *
 * Invariant, for every input:
 *   - UNAFFECTED ⇒ the two ProbeResults are identical (same own keys in the
 *     same order at every level, Object.is on every leaf) and so is the
 *     request sequence the target sees (method, URL, headers, body).
 *   - FALLBACK ⇒ the implementation's run is identical, ProbeResult and
 *     request sequence, to 0.9.0's run of the same input with only the
 *     discover answer's status replaced by 404 (a 4xx, which 0.9.0 already
 *     fell back on, and whose body is by class not a recognized modern
 *     error): discover, then initialize (+ ack), then the legacy judgment.
 *     Its first request is 0.9.0's discover request and, whenever it sends a
 *     second, that second one is initialize.
 *   - REJECTED ⇒ the request sequence is identical and so is the ProbeResult,
 *     except that discovery_handshake's reason is handshake_discover_rejected
 *     { status: <the 2xx>, jsonrpc_error_code: <the code> }.
 *   - MODERN ⇒ identical, ProbeResult and requests, to 0.9.0's run of the
 *     same input with only the discover status replaced by 200.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { posix } from 'node:path'
import ts from 'typescript'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { runProbe as frozen090RunProbe } from './frozen/suite-0.9.0/probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { ApprovedBaseline, GuardSignals, FetchLike, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// The frozen copies are what they say they are, and so is everything they reach.
// ---------------------------------------------------------------------------

/** `git rev-parse 16941d1:packages/checks/src/<name>.ts` (suite 0.9.0). */
const FROZEN_090_BLOBS: Record<string, string> = {
  'probe': '1c8c875c67a12946f86f9dd5688ac32d7dd04555',
  'protocol': 'e66f8fdddbd0e945bd30487e1b23a3d17aa56745',
  'auth': 'f8b78f074b997b38e39319d97ec93807f73a0c65',
  'error-taxonomy': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
}

/** The in-repo import closure of frozen/suite-0.9.0 outside that directory
 *  (importClosure090; imports read off the TypeScript AST), each file pinned
 *  to `git rev-parse 16941d1:<path>`, except checks.json, pinned to its
 *  no-baseline-reason-copy blob (registry_version 0.8.0; earlier pins were 0.7.0 and 0.6.0).
 *  That change cannot alter what the frozen files compute: they reach
 *  checks.json only through type-only imports (types.ts, registry.ts), erased
 *  at run time, and every run below passes the registry in as input to both
 *  sides. If this test goes red for any other file, freeze its 0.9.0 version
 *  into frozen/suite-0.9.0 first.
 *
 *  Suite 0.11.0 re-pins three files to their 0.11.0 blob (git hash-object
 *  <path> at that change): checks.json (registry_version 0.9.0, nothing
 *  else), wire.ts (a GET redirect hop to another
 *  host drops authorization / proxy-authorization / cookie) and ssrf-guard's
 *  guarded-fetch.ts (the followRedirects option, default unchanged). None
 *  changes what this differential computes: checks.json is reached type-only;
 *  both parties run the same live wire.ts (frozen/suite-0.9.0 imports it
 *  through ../../wire.ts), and the only GET either sends — auth.ts's metadata
 *  fetch — carries no headers, so no hop has anything to drop; and no run here
 *  calls guardedFetch (ssrf-guard is reached for its error classes). The
 *  0.11.0 change itself is carried by declined-host-differential.test.ts
 *  (live vs frozen 0.10.0). */
const CLOSURE_090_BLOBS: Record<string, string> = {
  'packages/attestation-schema/schema/attestation-payload-v0.1.json': 'afc710ab67f95d2559b87699dab7d46c2a10ed84',
  'packages/attestation-schema/schema/attestation-payload-v0.2.json': '66f835a57afb80ac24f8e9f56ef360fbb45993f4',
  'packages/attestation-schema/schema/attestation.schema.json': 'e530a30f249389a72c1370c6d114bc0bd81ad66a',
  'packages/attestation-schema/src/attestation.ts': '246bfcbdc3de280a1ff407a6ba62d52b85cc6995',
  'packages/attestation-schema/src/dsse.ts': 'abc02f6c5e793b80c06bd825f2da79c72dfb3c08',
  'packages/attestation-schema/src/generated-types.ts': '70654ab8e9b79bdca5bb5fba29f6263afc17705e',
  'packages/attestation-schema/src/index.ts': '04972eaf8326370bc4d881ddcdfd954e0e680e5b',
  'packages/attestation-schema/src/invariants.ts': '78c4296f187921cf90b19686fe95fbfc61abba8e',
  'packages/canonicalizer/src/canonicalize.ts': '45e467e746de5fa2ba40cae72af915eafdceb27b',
  'packages/canonicalizer/src/digest.ts': '037a30ced41ba496f49b4b0643c181dd60c3bc68',
  'packages/canonicalizer/src/errors.ts': 'cc3295b8b3e6f8c6c5f694137a418458956926a2',
  'packages/canonicalizer/src/index.ts': 'a5873c1742ec25f74ef3354490b46af9af097fe7',
  'packages/canonicalizer/src/projections.ts': 'd4fa9c9067ace15b893842696300b704980ef0ed',
  'packages/checks/checks.json': '04920465eb88986f76febbdec74b66238e3cd2ed', // suite 0.11.0 (registry_version 0.9.0 only; see above) — git hash-object packages/checks/checks.json
  'packages/checks/src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'packages/checks/src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'packages/checks/src/registry.ts': 'bcce9c9f3a032195548726da1c83985ae3e0b1f9',
  'packages/checks/src/types.ts': '59d38f860a3cd07989421fc2e6b97b60cabedd10',
  'packages/checks/src/wire.ts': '73314f32dec3befcb82edfa8afa70e05223d16b6', // suite 0.11.0 (see above) — git hash-object packages/checks/src/wire.ts
  'packages/ssrf-guard/src/audit.ts': 'c2f08ab05e4bdb6425c5feba789d19e0c7293073',
  'packages/ssrf-guard/src/budget.ts': 'c920ff71d6e0477fd22ef79c0077973227cbb74f',
  'packages/ssrf-guard/src/dns-wire.ts': '04357f1c08ee2d649a382d2640580903323af222',
  'packages/ssrf-guard/src/errors.ts': '958b4f9b63d9a5901b2097a2d564ef2afff79e57',
  'packages/ssrf-guard/src/guarded-fetch.ts': 'eda760ca7ffb210feb2a685ca0dd43d34a9ab86a', // suite 0.11.0 (see above) — git hash-object packages/ssrf-guard/src/guarded-fetch.ts
  'packages/ssrf-guard/src/index.ts': '9d301879dc35ac0a85a2cd5005d70f2e75406755',
  'packages/ssrf-guard/src/ip-policy.ts': 'b581241df1a369ee55e780b1450d1997ab2635db',
  'packages/ssrf-guard/src/rate-limit.ts': '20f0e9e542de6708411456c0a46d7fdad77e0773',
  'packages/ssrf-guard/src/resolve.ts': '8ba7ae7c4a97c0589fbb8da1166de89f36bdb5d0',
  'packages/ssrf-guard/src/response-view.ts': 'b1b0e3e040f6d6acf66700758323b6bfae223d96',
  'packages/ssrf-guard/src/url-target.ts': '46678f430c6534806c014b0265dc408c8fe29705',
}
const CLOSURE_090_THIRD_PARTY: string[] = []

const REPO_ROOT = new URL('../../../', import.meta.url)
const FROZEN_090_DIR = 'packages/checks/src/frozen/suite-0.9.0'
const readRepo = (path: string) => readFileSync(new URL(path, REPO_ROOT), 'utf8')
const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}

/** Verbatim from probe-tool-name-differential.test.ts. */
function importSpecifiers(path: string, text: string): string[] {
  const sf = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const out: string[] = []
  const literal = (node: ts.Node | undefined, what: string): void => {
    if (node === undefined || !ts.isStringLiteral(node)) {
      throw new Error(`${path}: ${what} whose module specifier is not a string literal (${node === undefined ? 'missing' : ts.SyntaxKind[node.kind]}) — the import closure cannot follow it`)
    }
    out.push(node.text)
  }
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) literal(node.moduleSpecifier, 'import declaration')
    else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) literal(node.moduleSpecifier, 'export … from')
    else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) literal(node.moduleReference.expression, 'import = require()')
    else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) literal(node.arguments[0], 'dynamic import()')
    else if (ts.isImportTypeNode(node)) literal(ts.isLiteralTypeNode(node.argument) ? node.argument.literal : node.argument, 'import() type')
    ts.forEachChild(node, visit)
  }
  visit(sf)
  for (const ref of sf.referencedFiles) out.push(ref.fileName.startsWith('.') ? ref.fileName : `./${ref.fileName}`)
  for (const ref of sf.typeReferenceDirectives) out.push(ref.fileName)
  return out
}

/** importClosure071 from probe-tool-name-differential.test.ts (via importClosure090 in
 *  guard-error-classification-differential.test.ts), verbatim but for the entry point. */
function importClosure090(): { files: string[]; thirdParty: string[] } {
  const packagesByName = new Map<string, string>()
  for (const dir of readdirSync(new URL('packages/', REPO_ROOT))) {
    const pj = new URL(`packages/${dir}/package.json`, REPO_ROOT)
    if (existsSync(pj)) packagesByName.set((JSON.parse(readFileSync(pj, 'utf8')) as { name: string }).name, `packages/${dir}`)
  }
  const seen = new Set<string>(), thirdParty = new Set<string>()
  const queue = [`${FROZEN_090_DIR}/probe.ts`]
  while (queue.length > 0) {
    const file = queue.shift()!
    if (seen.has(file)) continue
    seen.add(file)
    if (!file.endsWith('.ts')) continue // JSON leaf
    for (const spec of importSpecifiers(file, readRepo(file))) {
      if (spec.startsWith('.')) { queue.push(posix.normalize(posix.join(posix.dirname(file), spec))); continue }
      const segments = spec.split('/')
      const name = spec.startsWith('@') ? segments.slice(0, 2).join('/') : segments[0]!
      const subpath = spec.slice(name.length)
      const dir = name.startsWith('@mcpcheckup/') ? packagesByName.get(name) : undefined
      if (dir === undefined) { thirdParty.add(spec); continue }
      const target = (JSON.parse(readRepo(`${dir}/package.json`)) as { exports: Record<string, unknown> }).exports[subpath === '' ? '.' : `.${subpath}`]
      assert.equal(typeof target, 'string', `${spec}: exports entry is not a plain path`)
      queue.push(posix.normalize(posix.join(dir, target as string)))
    }
  }
  return { files: [...seen].filter((f) => !f.startsWith(`${FROZEN_090_DIR}/`)).sort(), thirdParty: [...thirdParty].sort() }
}

await t('the frozen suite-0.9.0 files are the 16941d1 blobs: header dropped, import paths restored, git blob id recomputed', () => {
  for (const [name, blob] of Object.entries(FROZEN_090_BLOBS)) {
    const lines = readRepo(`${FROZEN_090_DIR}/${name}.ts`).replace(/\r\n/g, '\n').split('\n')
    let header = 0
    while (lines[header]!.startsWith('// FROZEN:')) header++
    assert.equal(header, 4, `${name}: expected the four-line FROZEN header`)
    const restored = lines.slice(header).map((l) => (l.startsWith('import ') ? l.replace("from '../../", "from './") : l)).join('\n')
    assert.equal(blobId(restored), blob, `${name}.ts is not the 0.9.0 file`)
  }
})

await t('the in-repo import closure of frozen/suite-0.9.0 is exactly the pinned list, and every pinned file hashes to its pinned blob (git blob id recomputed)', () => {
  const closure = importClosure090()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_090_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_090_BLOBS)')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_090_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_090_BLOBS)) assert.equal(blobId(readRepo(path)), blob, `${path} changed: freeze its 0.9.0 version into frozen/suite-0.9.0 first`)
})

// ---------------------------------------------------------------------------
// Harness — runOnce, identical() and variants() from
// guard-error-classification-differential.test.ts, minus `throwAt`, plus the
// status of the server/discover answer and an optional replacement for it.
// ---------------------------------------------------------------------------

type Probe = typeof runProbe
type Handler = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

const ENDPOINT = 'https://notes-mcp.example.com/mcp'

interface Variant {
  budget: ProbeBudget
  approvedBaseline?: ApprovedBaseline
  /** 1-based request positions on which the transport reports GuardSignals. */
  signalOn?: { position: number; signals: GuardSignals }[]
  /** Every GET is answered with this many 302s before reaching the fixture. */
  getRedirects?: { hops: number; crossHost: boolean }
}

/** `discoverStatus`: the status of the answer to the (only) server/discover
 *  request, or undefined when none came back. */
interface Run { result: ProbeResult; requests: string[]; discoverStatus: number | undefined }

const isDiscover = (init?: RequestInit) => {
  if (typeof init?.body !== 'string') return false
  try { return (JSON.parse(init.body) as { method?: unknown }).method === 'server/discover' } catch { return false }
}

async function runOnce(probe: Probe, createHandler: () => Handler, v: Variant): Promise<Run> {
  const handler = createHandler()
  const requests: string[] = []
  let position = 0
  let redirectsServed = 0
  let discoverStatus: number | undefined
  const fetchImpl: FetchLike = async (input, init, onGuardSignal) => {
    position++
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = init?.method ?? 'GET'
    const headers: string[] = []
    new Headers(init?.headers).forEach((value, key) => { headers.push(`${key}: ${value}`) })
    requests.push(JSON.stringify([method, href, headers, typeof init?.body === 'string' ? init.body : null]))
    for (const s of v.signalOn ?? []) if (s.position === position) onGuardSignal(s.signals)
    if (method === 'GET' && v.getRedirects && redirectsServed < v.getRedirects.hops) {
      redirectsServed++
      const next = new URL(href)
      if (v.getRedirects.crossHost) next.hostname = `hop${redirectsServed}.example.net`
      next.searchParams.set('hop', String(redirectsServed))
      return new Response('', { status: 302, headers: { location: next.href } })
    }
    if (method === 'GET' && v.getRedirects) {
      // Hand the fixture the URL it was originally asked for.
      const original = new URL(href)
      original.searchParams.delete('hop')
      if (v.getRedirects.crossHost) original.hostname = new URL(ENDPOINT).hostname
      return handler(original.href, init)
    }
    const res = await handler(input, init)
    if (isDiscover(init)) discoverStatus = res.status
    return res
  }
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget: v.budget,
    now: () => '2026-09-30T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  return { result, requests, discoverStatus }
}

/** Identical own keys in identical order at every level, Object.is on every
 *  leaf — verbatim from probe-tool-name-differential.test.ts (T86). */
function identical(a: unknown, b: unknown): boolean {
  const stack: [unknown, unknown][] = [[a, b]]
  while (stack.length > 0) {
    const [x, y] = stack.pop()!
    if (x === null || y === null || typeof x !== 'object' || typeof y !== 'object') {
      if (!Object.is(x, y)) return false
      continue
    }
    if (Array.isArray(x) !== Array.isArray(y)) return false
    const kx = Object.keys(x), ky = Object.keys(y)
    if (kx.length !== ky.length || kx.some((k, i) => k !== ky[i])) return false
    for (const k of kx) stack.push([(x as Record<string, unknown>)[k], (y as Record<string, unknown>)[k]])
  }
  return true
}

function* variants(): Generator<[string, Variant]> {
  yield ['default', { budget: DEFAULT_PROBE_BUDGET }]
  for (let maxRequests = 0; maxRequests < DEFAULT_PROBE_BUDGET.maxRequests; maxRequests++) {
    yield [`maxRequests=${maxRequests}`, { budget: { ...DEFAULT_PROBE_BUDGET, maxRequests } }]
  }
  for (const maxBodyBytes of [0, 16, 200, 1024]) {
    yield [`maxBodyBytes=${maxBodyBytes}`, { budget: { ...DEFAULT_PROBE_BUDGET, maxBodyBytes } }]
  }
  yield ['baseline mismatch', { budget: DEFAULT_PROBE_BUDGET, approvedBaseline: { toolset_fingerprint: 'sha256:0', schema_fingerprint: 'sha256:0' } }]
  for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
    yield [`dns changed on request ${position}`, { budget: DEFAULT_PROBE_BUDGET, signalOn: [{ position, signals: { dnsAnswerChanged: true } }] }]
  }
  yield ['dns unchanged reported on every request', { budget: DEFAULT_PROBE_BUDGET, signalOn: Array.from({ length: 8 }, (_, i) => ({ position: i + 1, signals: { dnsAnswerChanged: false } })) }]
  for (const crossHost of [false, true]) {
    for (let hops = 1; hops <= DEFAULT_PROBE_BUDGET.maxRedirects + 1; hops++) {
      yield [`GET ${hops}×302 ${crossHost ? 'cross' : 'same'}-host`, { budget: DEFAULT_PROBE_BUDGET, getRedirects: { hops, crossHost } }]
      yield [`GET ${hops}×302 ${crossHost ? 'cross' : 'same'}-host, maxRedirects=1`, { budget: { ...DEFAULT_PROBE_BUDGET, maxRedirects: 1 }, getRedirects: { hops, crossHost } }]
    }
  }
}


// ---------------------------------------------------------------------------
// Classification and the one intended difference.
// ---------------------------------------------------------------------------

const RECOGNIZED = [-32020, -32021, -32022]
const is2xx = (s: number | undefined): s is number => s !== undefined && s >= 200 && s <= 299
const row = (r: ProbeResult, id: string) => r.assertions.find((a) => a.check_id === id)!

type Klass = 'UNAFFECTED' | 'FALLBACK' | 'REJECTED' | 'MODERN'
interface Classified { klass: Klass; sub: string; code?: number }

/** What 0.9.0's 200 branch made of a discover body: its handshake row. */
function read200(r: Run): Classified {
  const h = row(r.result, 'discovery_handshake')
  if (h.execution_status !== 'COMPLETED') throw new Error(`0.9.0 at 200: handshake did not return (${h.execution_status})`)
  if (h.assertion_status === 'VERIFIED') return { klass: 'MODERN', sub: 'discover result' }
  const key = h.reason?.key
  const code = h.reason?.params?.jsonrpc_error_code
  if (key === 'handshake_discover_jsonrpc_error' && typeof code === 'number' && RECOGNIZED.includes(code)) return { klass: 'REJECTED', sub: key, code }
  if (key === 'handshake_discover_not_jsonrpc' || key === 'handshake_discover_jsonrpc_error' || key === 'handshake_discover_no_supported_versions') return { klass: 'FALLBACK', sub: key }
  throw new Error(`0.9.0 at 200: unexpected discovery_handshake ${h.assertion_status} ${JSON.stringify(h.reason)}`)
}

/** `then` is 0.9.0's run; `at200` runs 0.9.0 on the same input with the
 *  discover status set to 200 (needed only for a 2xx other than 200). */
async function classify(then: Run, at200: () => Promise<Run>): Promise<Classified> {
  const s = then.discoverStatus
  if (!is2xx(s)) return { klass: 'UNAFFECTED', sub: s === undefined ? 'no discover answer' : `${Math.floor(s / 100)}xx` }
  if (row(then.result, 'discovery_handshake').execution_status !== 'COMPLETED') return { klass: 'UNAFFECTED', sub: '2xx, handshake never returned' }
  if (s === 200) {
    const c = read200(then)
    return c.klass === 'MODERN' ? { klass: 'UNAFFECTED', sub: '200 discover result' } : c
  }
  const h = row(then.result, 'discovery_handshake')
  assert.deepStrictEqual(h.reason, { key: 'handshake_discover_http_error', params: { status: s } }, `0.9.0 at ${s}`)
  const c = read200(await at200())
  return { ...c, sub: `${s}: ${c.sub}` }
}

/** The JSON-RPC method of one recorded request (see runOnce), or null. */
function methodOf(recorded: string): string | null {
  const body = (JSON.parse(recorded) as unknown[])[3]
  return typeof body === 'string' ? String((JSON.parse(body) as { method?: unknown }).method) : null
}

type Stats = Map<string, number>
const bump = (m: Stats, k: string) => m.set(k, (m.get(k) ?? 0) + 1)

/** Asserts the invariant for one input; returns its class. `serve(status)`
 *  builds the input's handler with the discover status replaced (or not). */
async function check(serve: (discoverStatus?: number) => () => Handler, v: Variant, stats: Stats): Promise<Classified> {
  const now = await runOnce(runProbe, serve(), v)
  const then = await runOnce(frozen090RunProbe, serve(), v)
  const c = await classify(then, () => runOnce(frozen090RunProbe, serve(200), v))
  bump(stats, `${c.klass} — ${c.sub}`)
  if (c.klass === 'UNAFFECTED') {
    assert.deepStrictEqual(now.requests, then.requests, 'unaffected: request sequence identical to 0.9.0')
    assert.ok(identical(now.result, then.result), 'unaffected: ProbeResult identical to 0.9.0')
    return c
  }
  if (c.klass === 'REJECTED') {
    assert.deepStrictEqual(now.requests, then.requests, 'rejected: request sequence identical to 0.9.0')
    const want = { ...then.result, assertions: then.result.assertions.map((a) => (a.check_id === 'discovery_handshake' ? { ...a, reason: { key: 'handshake_discover_rejected', params: { status: then.discoverStatus!, jsonrpc_error_code: c.code! } } } : a)) }
    assert.ok(identical(now.result, want), `rejected: ProbeResult is 0.9.0's with discovery_handshake reason handshake_discover_rejected {status:${then.discoverStatus}} and nothing else`)
    return c
  }
  const counterfactual = await runOnce(frozen090RunProbe, serve(c.klass === 'FALLBACK' ? 404 : 200), v)
  assert.deepStrictEqual(now.requests, counterfactual.requests, `${c.klass}: request sequence is 0.9.0's with discover answered ${c.klass === 'FALLBACK' ? 404 : 200}`)
  assert.ok(identical(now.result, counterfactual.result), `${c.klass}: ProbeResult is 0.9.0's with discover answered ${c.klass === 'FALLBACK' ? 404 : 200}`)
  assert.equal(now.requests[0], then.requests[0], `${c.klass}: the discover request itself is unchanged`)
  if (c.klass === 'FALLBACK') {
    if (now.requests.length > 1) assert.equal(methodOf(now.requests[1]!), 'initialize', 'fallback: the next request is initialize')
  } else {
    assert.ok(!now.requests.map(methodOf).includes('initialize'), 'modern: no initialize')
  }
  return c
}

// ---------------------------------------------------------------------------
// A. The fixture corpus × variants.
// ---------------------------------------------------------------------------

/** A Response like `res` but with `status`, same headers and body stream. */
const restatus = (res: Response, status: number) => new Response(res.body, { status, headers: res.headers })

function serveFixture(createHandler: () => Handler): (discoverStatus?: number) => () => Handler {
  return (discoverStatus) => () => {
    const handler = createHandler()
    return async (input, init) => {
      const res = await handler(input, init)
      return discoverStatus !== undefined && isDiscover(init) ? restatus(res, discoverStatus) : res
    }
  }
}

/** Every fixture T96 changes, by class, under the default variant. Written out
 *  here so that a fixture joining (or leaving) the affected set has to be
 *  looked at: the test below compares the observed set with this list. */
const T96_AFFECTED_FIXTURES: Record<string, Klass> = {
  'handshake-discover-jsonrpc-error': 'FALLBACK',
  'handshake-discover-not-jsonrpc': 'FALLBACK',
  'handshake-discover-no-supported-versions': 'FALLBACK',
  'handshake-discover-202-falls-back': 'FALLBACK',
  'handshake-discover-rejected-200': 'REJECTED',
}

const fixtureStats: Stats = new Map()
const affectedByVariant = new Map<string, string[]>()
for (const fixture of FIXTURE_CORPUS) {
  const affected: string[] = []
  await t(`${fixture.id}：T96 对冻结 0.9.0 的差分，全部变体（未受影响的逐字段相同；受影响的恰好多出回退）`, async () => {
    for (const [label, v] of variants()) {
      let c: Classified
      try {
        c = await check(serveFixture(fixture.createHandler), v, fixtureStats)
      } catch (e) {
        throw new Error(`[${label}] ${(e as Error).message}`)
      }
      if (c.klass !== 'UNAFFECTED') affected.push(`${label}: ${c.klass}`)
      if (label === 'default' && c.klass !== 'UNAFFECTED') assert.equal(T96_AFFECTED_FIXTURES[fixture.id], c.klass, `default variant: ${fixture.id} is ${c.klass}, not listed as such in T96_AFFECTED_FIXTURES`)
    }
  })
  if (affected.length > 0) affectedByVariant.set(fixture.id, affected)
}

console.log(`  fixture cells by class (${[...fixtureStats.values()].reduce((a, b) => a + b, 0)} runs):\n    ${[...fixtureStats.entries()].sort().map(([k, n]) => `${k}: ${n}`).join('\n    ')}`)
console.log(`  affected fixtures (${affectedByVariant.size}):\n    ${[...affectedByVariant.entries()].map(([id, cells]) => `${id}: ${cells.length} variant(s), ${[...new Set(cells.map((c) => c.split(': ')[1]))].join(' / ')}`).join('\n    ')}`)

await t('T96 在语料上的受影响 fixture 恰好是 T96_AFFECTED_FIXTURES（默认变体下各自的类别也一致），且每一类至少一条', () => {
  assert.deepStrictEqual([...affectedByVariant.keys()].sort(), Object.keys(T96_AFFECTED_FIXTURES).sort())
  for (const [id, klass] of Object.entries(T96_AFFECTED_FIXTURES)) assert.ok(affectedByVariant.get(id)!.includes(`default: ${klass}`), `${id}: default variant is not ${klass}`)
  assert.ok(Object.values(T96_AFFECTED_FIXTURES).includes('FALLBACK') && Object.values(T96_AFFECTED_FIXTURES).includes('REJECTED'))
})

// ---------------------------------------------------------------------------
// B. The T73 discover stage, with the legacy stages pinned.
// ---------------------------------------------------------------------------

const CANARY = 'CANARYq7Zx'
const VALID_CHALLENGE = 'Bearer realm="mcp"'

/** `challenge` labels a response the generator gave the known-valid
 *  WWW-Authenticate above — the ORACLE's only source for "is there a
 *  structurally valid challenge", so it never parses the header itself. */
interface Resp { status: number; headers: Headers; body: string; challenge: boolean }

function resp(status: number, ct: string | null, body: string, extra: { location?: string; challenge?: boolean } = {}): Resp {
  const headers = new Headers()
  if (ct !== null) headers.set('content-type', ct)
  if (extra.location !== undefined) headers.set('location', extra.location)
  if (extra.challenge) headers.set('www-authenticate', VALID_CHALLENGE)
  return { status, headers, body, challenge: !!extra.challenge }
}

/** Duck-typed on purpose: sendRequest reads only status, headers and text(),
 *  and a real Response refuses a body on 204 — which would silently drop
 *  (204 × body) cells out of the T73 corpus. */
function toResponse(r: Resp): Response {
  return { status: r.status, headers: r.headers, text: async () => r.body } as unknown as Response
}

interface Script { discover: Resp; initialize: Resp; ack: Resp; toolsList: Resp }


const TOOLS_CALL_REPLY = resp(200, 'application/json', '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool"}}')
const NOT_FOUND = resp(404, 'text/plain', 'Not Found')

function serveScript(s: Script): (discoverStatus?: number) => () => Handler {
  return (discoverStatus) => () => async (_input, init) => {
    const method = typeof init?.body === 'string' ? (JSON.parse(init.body) as { method?: unknown }).method : undefined
    const r =
      method === 'server/discover' ? (discoverStatus === undefined ? s.discover : { ...s.discover, status: discoverStatus })
      : method === 'initialize' ? s.initialize
      : method === 'notifications/initialized' ? s.ack
      : method === 'tools/list' ? s.toolsList
      : method === 'tools/call' ? TOOLS_CALL_REPLY
      : NOT_FOUND
    return toResponse(r)
  }
}

/** Line scanner: a line ends at LF, one CR right before it belongs to the
 *  terminator; a blank line ends an event; only `data:` lines count, one
 *  following space dropped; an event whose data is empty yields nothing. */
function oracleSseData(raw: string): string[] {
  const events: string[] = []
  let current: string[] = []
  const endEvent = () => {
    const payload = current.join('\n')
    if (payload !== '') events.push(payload)
    current = []
  }
  let start = 0
  for (let i = 0; i <= raw.length; i++) {
    if (i < raw.length && raw[i] !== '\n') continue
    let line = raw.slice(start, i)
    if (i < raw.length && line.endsWith('\r')) line = line.slice(0, -1)
    start = i + 1
    if (line === '') { endEvent(); continue }
    if (line.slice(0, 5) === 'data:') current.push(line[5] === ' ' ? line.slice(6) : line.slice(5))
  }
  endEvent()
  return events
}

const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)

type OMessage = { kind: 'result'; result: unknown } | { kind: 'error'; code: number } | null

/** The first candidate that is a JSON-RPC 2.0 message: jsonrpc exactly
 *  "2.0" and either a `result` member (which wins over an error), or an
 *  error object with a numeric code and a string message. */
function oracleRead(r: Resp): OMessage {
  const ct = r.headers.get('content-type')
  const texts = ct !== null && /text\/event-stream/i.test(ct) ? oracleSseData(r.body) : [r.body]
  for (const text of texts) {
    let v: unknown
    try { v = JSON.parse(text) } catch { continue }
    if (!isPlainObject(v) || v.jsonrpc !== '2.0') continue
    if (Object.prototype.hasOwnProperty.call(v, 'result')) return { kind: 'result', result: v.result }
    const e = v.error
    if (isPlainObject(e) && typeof e.code === 'number' && typeof e.message === 'string') return { kind: 'error', code: e.code }
  }
  return null
}

function oracleField(m: OMessage, field: string): unknown {
  if (m === null || m.kind !== 'result') return undefined
  const r = m.result
  return r !== null && typeof r === 'object' && !Array.isArray(r) ? (r as Record<string, unknown>)[field] : undefined
}

/** The class ORACLE predicts from the discover answer alone. */
function oracleClass(d: Resp): Klass {
  if (d.status < 200 || d.status > 299) return 'UNAFFECTED'
  const m = oracleRead(d)
  const sv = oracleField(m, 'supportedVersions')
  if (Array.isArray(sv) && typeof sv[0] === 'string') return d.status === 200 ? 'UNAFFECTED' : 'MODERN'
  if (m !== null && m.kind === 'error' && RECOGNIZED.includes(m.code)) return 'REJECTED'
  return 'FALLBACK'
}

const STATUSES = [200, 202, 204, 400, 401, 403, 404, 405, 406, 415, 429, 500, 503]
const REDIRECTS = [301, 302, 303, 307, 308]
const CONTENT_TYPES: (string | null)[] = [
  null,
  '',
  'application/json',
  'application/json; charset=utf-8',
  'APPLICATION/JSON',
  'text/event-stream',
  'Text/Event-Stream; charset=utf-8',
  'text/html; charset=UTF-8',
  'text/plain',
  'application/problem+json',
  'application/json, text/event-stream',
  '; charset=utf-8',
]

// The T73 corpus bodies, verbatim (error-taxonomy-differential.test.ts).
const ERR_OK = `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool ${CANARY}"}}`
const RES_ISERR = `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"${CANARY}"}],"isError":true}}`
const RES_OK = '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}'
const NOTIF = '{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}'
const CORPUS_BODIES: string[] = [
  '', ' ', '\n', '\r\n\r\n', '\t\t',
  `Internal Server Error ${CANARY}`,
  `<html><body><h1>Not Found</h1><p>${CANARY}</p></body></html>`,
  `﻿${ERR_OK}`, `﻿${RES_ISERR}`, ERR_OK, `  ${ERR_OK}\n`,
  '{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"m"}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":5}}',
  '{"jsonrpc":"2.0","id":1,"error":null}',
  '{"jsonrpc":"2.0","id":1,"error":[]}',
  `{"jsonrpc":"2.0","id":1,"error":"${CANARY}"}`,
  '{"jsonrpc":"2.0","id":1,"error":{"code":1.5}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":9007199254740993}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":1e400}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-0}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":-9007199254740991}}',
  '{"jsonrpc":"2.0","id":1,"error":{"code":1e300,"message":"m"}}',
  '{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32602,"message":"m"}}',
  RES_ISERR,
  '{"jsonrpc":"2.0","id":1,"result":{"isError":"true"}}',
  '{"jsonrpc":"2.0","id":1,"result":{"isError":1}}',
  '{"jsonrpc":"2.0","id":1,"result":{"isError":false}}',
  RES_OK,
  '{"jsonrpc":"2.0","id":1,"result":null}',
  '{"jsonrpc":"2.0","id":1,"result":[{"isError":true}]}',
  '{"jsonrpc":"1.0","id":1,"error":{"code":-32602,"message":"m"}}',
  '{"jsonrpc":2.0,"id":1,"error":{"code":-32602,"message":"m"}}',
  `{"error":"${CANARY}"}`,
  '{}',
  '{"jsonrpc":"2.0"}',
  `[${ERR_OK}]`,
  '42', 'null', 'true', `"${CANARY}"`,
  NOTIF,
  '{"jsonrpc":"2.0","id":1,"err',
  `event: message\ndata: ${ERR_OK}\n\n`,
  `event: message\ndata: ${RES_ISERR}\n\n`,
  `data:${RES_OK}\n\n`,
  `event: message\r\ndata: ${RES_ISERR}\r\n\r\n`,
  'data: {"jsonrpc":"2.0",\ndata: "id":1,\ndata: "result":{"isError":true}}\n\n',
  ': ping\n\n',
  `data: ${NOTIF}\n\ndata: ${RES_ISERR}\n\n`,
  `data: ${NOTIF}\n\ndata: ${ERR_OK}\n\n`,
  `data: ${NOTIF}\n\n`,
  `data: {"jsonrpc":"2.0","id":1,"error":{"code":-32000}}\n\ndata: ${RES_OK}\n\n`,
  `data: [1]\n\ndata: ${NOTIF}\n\n`,
  `data: hello ${CANARY}\n\n`,
  'data: 42\n\n',
  'data:\n\n',
  ` data: ${RES_OK}\n\n`,
  `data:  ${RES_ISERR}\n\n`,
  `data: ${RES_ISERR}`,
  `data: ${RES_OK}\r\r`,
  `\n\n\ndata: ${RES_ISERR}\n\n\n`,
  `data: ${NOTIF}\n\r\ndata: {"jsonrpc":"2.0","id":1,"error":{"code":7}}\r\n\n`,
]

const rpcResult = (result: string) => `{"jsonrpc":"2.0","id":1,"result":${result}}`
const rpcError = (code: string, message = `"m ${CANARY}"`) => `{"jsonrpc":"2.0","id":1,"error":{"code":${code},"message":${message}}}`
const sse = (json: string) => `event: message\ndata: ${json}\n\n`

const DISCOVER_BODIES: string[] = [
  rpcResult('{"supportedVersions":["2026-07-28"],"capabilities":{}}'),
  rpcResult(`{"supportedVersions":["${CANARY}-2026"]}`),
  rpcResult('{"supportedVersions":["2025-06-18","2026-07-28"]}'),
  rpcResult('{"supportedVersions":[""]}'),
  rpcResult('{"capabilities":{}}'),
  rpcResult('{"supportedVersions":[]}'),
  rpcResult('{"supportedVersions":[20260728]}'),
  rpcResult('{"supportedVersions":[null,"2026-07-28"]}'),
  rpcResult('{"supportedVersions":"2026-07-28"}'),
  rpcResult('{"supportedVersions":{"0":"2026-07-28"}}'),
  rpcResult('"2026-07-28"'),
  rpcError('-32020'), rpcError('-32021'), rpcError('-32022'),
  rpcError('-32601'), rpcError('-32000'), rpcError('-0'), rpcError('1.5'), rpcError('-32020.5'), rpcError('1e300'),
  '{"jsonrpc":"2.0","id":1,"error":{"code":-32020}}',
  sse(rpcResult('{"supportedVersions":["2026-07-28"]}')),
  sse(rpcError('-32022')),
  `data: ${NOTIF}\n\n${sse(rpcResult('{"supportedVersions":["2025-11-25"]}'))}`,
]

/** T96's new cells: every other 2xx the rule now reads (every 2xx is judged
 *  like 200), and two more 5xx
 *  it must leave alone. */
const NEW_2XX = [201, 203, 205, 206, 207, 226, 299]
const MORE_5XX = [502, 504]
/** The statuses the two extra legacy-stage pins run over. */
const PINNED_STATUSES = [200, 202, 204, 404]

const VALID_TOOLS = '[{"name":"search_notes","inputSchema":{"type":"object"}},{"name":"get_note","inputSchema":{"type":"object"}}]'
const LEGACY_OK = {
  initialize: resp(200, 'application/json', rpcResult('{"protocolVersion":"2025-06-18","capabilities":{}}')),
  ack: resp(202, null, ''),
  toolsList: resp(200, 'application/json', rpcResult(`{"tools":${VALID_TOOLS}}`)),
}
const PINS: [string, Omit<Script, 'discover'>, number[]][] = [
  ['legacy ok', LEGACY_OK, [...STATUSES, ...REDIRECTS, ...NEW_2XX, ...MORE_5XX]],
  ['initialize -32601', { ...LEGACY_OK, initialize: resp(200, 'application/json', rpcError('-32601')) }, PINNED_STATUSES],
  ['initialize 401 gate', { ...LEGACY_OK, initialize: resp(401, null, '', { challenge: true }) }, PINNED_STATUSES],
]

const scriptStats: Stats = new Map()
const scriptViolations: string[] = []
let scriptTotal = 0
for (const [pinLabel, pin, statuses] of PINS) {
  for (const status of statuses) {
    for (const ct of CONTENT_TYPES) {
      for (const [bi, body] of [...CORPUS_BODIES, ...DISCOVER_BODIES].entries()) {
        const s: Script = { discover: resp(status, ct, body), ...pin }
        const id = `${pinLabel} / ${status} / ${JSON.stringify(ct)} / body ${bi}`
        scriptTotal++
        try {
          const c = await check(serveScript(s), { budget: DEFAULT_PROBE_BUDGET }, scriptStats)
          const predicted = oracleClass(s.discover)
          if (c.klass !== predicted) scriptViolations.push(`${id}: class ${c.klass}, ORACLE says ${predicted}`)
        } catch (e) {
          scriptViolations.push(`${id}: ${(e as Error).message.split('\n')[0]}`)
        }
      }
    }
  }
}

console.log(`  scripted cells by class (${scriptTotal}):\n    ${[...scriptStats.entries()].sort().map(([k, n]) => `${k}: ${n}`).join('\n    ')}`)

await t(`T96 对冻结 0.9.0 的差分，T73 discover 语料（${scriptTotal} 格）：未受影响的逐字段相同；受影响的恰好多出回退 / 记 rejected / 判 modern，类别与 ORACLE 的预测一致`, () => {
  assert.deepStrictEqual(scriptViolations.slice(0, 20), [], `${scriptViolations.length} violation(s)`)
})

await t('T96 的 discover 语料不空泛：四类都出现，200 与 200 以外的 2xx 都有回退格', () => {
  const count = (prefix: string) => [...scriptStats.entries()].filter(([k]) => k.startsWith(prefix)).reduce((a, [, n]) => a + n, 0)
  for (const k of ['UNAFFECTED', 'FALLBACK', 'REJECTED', 'MODERN']) assert.ok(count(k) > 0, `no ${k} cell`)
  assert.ok(count('FALLBACK — handshake_discover_') > 0 && count('FALLBACK — 202: ') > 0, 'fallback cells at 200 and at another 2xx')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
