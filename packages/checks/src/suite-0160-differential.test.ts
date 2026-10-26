/**
 * Suite 0.16.0 differential: the evidence that suite 0.16.0 changed what it says
 * it changed and nothing else.
 *
 * Suite 0.16.0 (latency.ts, suite-0160-remap.ts): latency_profile is measured from
 * the times the FetchLike reports through GuardSignals.responseHeadersMs for the
 * run's POSTs. No request is added, and no other row, field or request changes.
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.15.0 — ./frozen/suite-0.15.0/, byte for byte the suite 0.15.0 files
 *      at df63a9fc (checks.json too: registry 0.14.0, the one suite 0.15.0 shipped
 *      with): probe.ts's whole in-package import closure under src/, and checks.json
 *      beside it, in the same relative layout as packages/checks itself, so not one
 *      import specifier had to be edited and there is no `// FROZEN:` header. The
 *      first test checks each git blob id; the third, that nothing the frozen copy
 *      reaches outside that directory has changed (CLOSURE_0150_BLOBS).
 *
 * Input sets A and B: those of suite-0150-differential.test.ts (the whole fixture
 * corpus × budget / GuardSignals / baseline / GET-redirect variants; and the corpus
 * with request p throwing OtherHostDeclined, an Error of our own, or an ssrf-guard
 * error), each run over two transports:
 *
 *   - UNTIMED, as every older differential's: the request sequence is identical,
 *     and the implementation's ProbeResult is 0.15.0's after latency0160Remap
 *     (latency_no_samples when no POST was answered, else unchanged).
 *   - TIMED: the same transport reporting a time for every call it answers (GETs
 *     too), as the production adapter does. The frozen run is given the same
 *     transport and ignores the times. The request sequence is identical, and the
 *     implementation's ProbeResult is 0.15.0's with exactly the latency_profile row
 *     replaced by this file's own oracle (LATENCY_ORACLE below): computed from the
 *     times the transport reported for the POSTs it answered, and from whether the
 *     frozen run stopped at a credential gate. Paged lists are included: 0.15.0
 *     already pages, so no input is set aside.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { posix } from 'node:path'
import ts from 'typescript'
import { DEFAULT_PROBE_BUDGET, SsrfBlocked } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import type { Assertion } from '@mcpcheckup/attestation-schema'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { latency0160Remap } from './suite-0160-remap.ts'
import { recordRequest } from './suite-0130-remap.ts'
import { runProbe as frozen0150RunProbe } from './frozen/suite-0.15.0/src/probe.ts'
import { OtherHostDeclined } from './other-host-declined.ts'
import { OtherHostDeclined as FrozenOtherHostDeclined } from './frozen/suite-0.15.0/src/other-host-declined.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { ApprovedBaseline, FetchLike, GuardSignals, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// The frozen copy is what it says it is, and so is everything it reaches.
// ---------------------------------------------------------------------------

const REPO_ROOT = new URL('../../../', import.meta.url)
const FROZEN_0150_DIR = 'packages/checks/src/frozen/suite-0.15.0'
const readRepo = (path: string) => readFileSync(new URL(path, REPO_ROOT), 'utf8')
const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}

/** Every file in frozen/suite-0.15.0, by its path below that directory, pinned to
 *  `git rev-parse df63a9fc:packages/checks/<path>` (suite 0.15.0, registry 0.14.0). */
const FROZEN_0150_BLOBS: Record<string, string> = {
  'checks.json': '484681d7a551d16b89d38691e21df7fc3c5b8616',
  'src/auth-observation.ts': '6edecacca2b159335d6371376e1265e1052e6400',
  'src/auth.ts': '15f777474121e48ec2eedf39fa915005ba268669',
  'src/error-taxonomy.ts': '0a18d6a872a077372ea44589879bdb9f390678b6',
  'src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'src/other-host-declined.ts': 'f8e53d6ca2700e837d265ed4e839c019941cdd67',
  'src/probe.ts': '253e90586e017e8626dfea5f4b9f617b4bc83baf',
  'src/protocol.ts': '0947e8d4f4c615092ae965e0dc947e33e786fee4',
  'src/registry.ts': '6f610be98235985b0a27d4cfac5ba805b6a3f51b',
  'src/types.ts': '07c166df01ce8ac12aa29735c2867319a46e01cd',
  'src/wire.ts': '7998024513b5a48ed887cef0a8df00f18b2e78ef',
}

/** The in-repo import closure of frozen/suite-0.15.0/src/probe.ts OUTSIDE that
 *  directory: only the three other workspace packages it imports by name, each file
 *  pinned to its blob at df63a9fc (unchanged by suite 0.16.0). No live
 *  packages/checks file is in this list, so the suite 0.16.0 edits cannot reach the
 *  frozen copy. If this test goes red for any file, the frozen run may no longer
 *  compute 0.15.0: freeze that file's 0.15.0 version first. */
const CLOSURE_0150_BLOBS: Record<string, string> = {
  'packages/attestation-schema/schema/attestation-payload-v0.1.json': 'afc710ab67f95d2559b87699dab7d46c2a10ed84',
  'packages/attestation-schema/schema/attestation-payload-v0.2.json': '66f835a57afb80ac24f8e9f56ef360fbb45993f4',
  'packages/attestation-schema/schema/attestation-payload-v0.3.json': 'e530a30f249389a72c1370c6d114bc0bd81ad66a',
  'packages/attestation-schema/schema/attestation.schema.json': 'c8a12527aad29cc7f26b68e8765bd4320cb18d3c',
  'packages/attestation-schema/src/attestation.ts': '1dff1543b9d4890f17221ac5825dfe4fb9ea50b6',
  'packages/attestation-schema/src/credential-shapes.ts': '4e1957c82d8797c7db68371a9770fac348a1fe8c',
  'packages/attestation-schema/src/dsse.ts': 'abc02f6c5e793b80c06bd825f2da79c72dfb3c08',
  'packages/attestation-schema/src/generated-types.ts': 'e255d176c73c5c30dd9ac07c0149f204be1b4df8',
  'packages/attestation-schema/src/index.ts': 'dbe2f24752372c7b49b622474665080aba39754d',
  'packages/attestation-schema/src/invariants.ts': '78c4296f187921cf90b19686fe95fbfc61abba8e',
  'packages/canonicalizer/src/canonicalize.ts': '45e467e746de5fa2ba40cae72af915eafdceb27b',
  'packages/canonicalizer/src/digest.ts': '037a30ced41ba496f49b4b0643c181dd60c3bc68',
  'packages/canonicalizer/src/errors.ts': 'cc3295b8b3e6f8c6c5f694137a418458956926a2',
  'packages/canonicalizer/src/index.ts': 'a5873c1742ec25f74ef3354490b46af9af097fe7',
  'packages/canonicalizer/src/projections.ts': 'd4fa9c9067ace15b893842696300b704980ef0ed',
  'packages/ssrf-guard/src/audit.ts': 'c2f08ab05e4bdb6425c5feba789d19e0c7293073',
  'packages/ssrf-guard/src/budget.ts': 'c920ff71d6e0477fd22ef79c0077973227cbb74f',
  'packages/ssrf-guard/src/dns-wire.ts': '04357f1c08ee2d649a382d2640580903323af222',
  'packages/ssrf-guard/src/errors.ts': '958b4f9b63d9a5901b2097a2d564ef2afff79e57',
  'packages/ssrf-guard/src/guarded-fetch.ts': 'eda760ca7ffb210feb2a685ca0dd43d34a9ab86a',
  'packages/ssrf-guard/src/index.ts': '9d301879dc35ac0a85a2cd5005d70f2e75406755',
  'packages/ssrf-guard/src/ip-policy.ts': 'c40a0ef0a1af6ea5721edebcdd3e0660831b411e',
  'packages/ssrf-guard/src/rate-limit.ts': '20f0e9e542de6708411456c0a46d7fdad77e0773',
  'packages/ssrf-guard/src/resolve.ts': '8ba7ae7c4a97c0589fbb8da1166de89f36bdb5d0',
  'packages/ssrf-guard/src/response-view.ts': 'b1b0e3e040f6d6acf66700758323b6bfae223d96',
  'packages/ssrf-guard/src/url-target.ts': 'c1d8f47ef7b0402b45bd9f555cd82fd0f0ec103a',
}
const CLOSURE_0150_THIRD_PARTY: string[] = []

/** Verbatim from suite-0150-differential.test.ts (from probe-tool-name-differential.test.ts, T86b R6). */
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

/** importClosure0140 from suite-0150-differential.test.ts, verbatim but for the entry point. */
function importClosure0150(): { files: string[]; inside: string[]; thirdParty: string[] } {
  const packagesByName = new Map<string, string>()
  for (const dir of readdirSync(new URL('packages/', REPO_ROOT))) {
    const pj = new URL(`packages/${dir}/package.json`, REPO_ROOT)
    if (existsSync(pj)) packagesByName.set((JSON.parse(readFileSync(pj, 'utf8')) as { name: string }).name, `packages/${dir}`)
  }
  const seen = new Set<string>(), thirdParty = new Set<string>()
  const queue = [`${FROZEN_0150_DIR}/src/probe.ts`]
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
  const all = [...seen]
  return {
    files: all.filter((f) => !f.startsWith(`${FROZEN_0150_DIR}/`)).sort(),
    inside: all.filter((f) => f.startsWith(`${FROZEN_0150_DIR}/`)).map((f) => f.slice(FROZEN_0150_DIR.length + 1)).sort(),
    thirdParty: [...thirdParty].sort(),
  }
}

/** Every file under `dir`, relative to it. */
function listFiles(dir: string, base = ''): string[] {
  const out: string[] = []
  for (const entry of readdirSync(new URL(`${dir}/${base}`, REPO_ROOT), { withFileTypes: true })) {
    const rel = base ? `${base}/${entry.name}` : entry.name
    if (entry.isDirectory()) out.push(...listFiles(dir, rel))
    else out.push(rel)
  }
  return out.sort()
}

await t('the frozen suite-0.15.0 files are the df63a9fc blobs, byte for byte (git blob id recomputed, nothing stripped or restored first)', () => {
  for (const [path, blob] of Object.entries(FROZEN_0150_BLOBS)) {
    assert.equal(blobId(readRepo(`${FROZEN_0150_DIR}/${path}`)), blob, `${path} is not the 0.15.0 file`)
  }
})

await t('frozen/suite-0.15.0 holds exactly the pinned files, and they are exactly what its probe.ts reaches inside it (nothing unpinned, nothing unreached)', () => {
  const pinned = Object.keys(FROZEN_0150_BLOBS).sort()
  assert.deepStrictEqual(listFiles(FROZEN_0150_DIR), pinned, 'a file in frozen/suite-0.15.0 is not pinned, or a pinned one is missing')
  assert.deepStrictEqual(importClosure0150().inside, pinned, 'the frozen probe.ts no longer reaches exactly the pinned files')
})

await t('the in-repo import closure of frozen/suite-0.15.0 outside it is exactly the pinned list (no live packages/checks file), and every pinned file hashes to its pinned blob (git blob id recomputed)', () => {
  const closure = importClosure0150()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_0150_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_0150_BLOBS)')
  assert.ok(!closure.files.some((f) => f.startsWith('packages/checks/')), 'the frozen copy reaches a live packages/checks file')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_0150_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_0150_BLOBS)) assert.equal(blobId(readRepo(path)), blob, `${path} changed: freeze its 0.15.0 version into frozen/suite-0.15.0 first`)
})

// ---------------------------------------------------------------------------
// Harness: suite-0150-differential.test.ts's, with an optional timing transport.
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
  /** Request number `position` throws `make()` instead of answering. */
  throwAt?: { position: number; make: () => unknown }
}

interface Run {
  result: ProbeResult
  requests: string[]
  threw: boolean
  /** A POST whose call resolved with a Response. */
  postAnswered: boolean
  /** The times reported for the POSTs the transport answered, in order (timed runs only). */
  postTimes: number[]
}

/** The time the timing transport reports for its `position`-th call: whole ms, varied. */
const timeFor = (position: number) => 5 + ((position * 37) % 90)

async function runOnce(probe: Probe, createHandler: () => Handler, v: Variant, timed: boolean): Promise<Run> {
  const handler = createHandler()
  const requests: string[] = []
  const postTimes: number[] = []
  let position = 0
  let redirectsServed = 0
  let threw = false
  let postAnswered = false
  const answer = async (input: RequestInfo | URL, init: RequestInit | undefined, href: string, method: string): Promise<Response> => {
    if (method === 'GET' && v.getRedirects && redirectsServed < v.getRedirects.hops) {
      redirectsServed++
      const next = new URL(href)
      if (v.getRedirects.crossHost) next.hostname = `hop${redirectsServed}.example.com`
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
    return handler(input, init)
  }
  const transport: FetchLike = async (input, init, onGuardSignal) => {
    position++
    const at = position
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    requests.push(recordRequest(input, init))
    if (v.throwAt && v.throwAt.position === at) { threw = true; throw v.throwAt.make() }
    for (const s of v.signalOn ?? []) if (s.position === at) onGuardSignal(s.signals)
    const response = await answer(input, init, href, method)
    if (timed) {
      onGuardSignal({ responseHeadersMs: timeFor(at) })
      if (method === 'POST') postTimes.push(timeFor(at))
    }
    if (method === 'POST') postAnswered = true
    return response
  }
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: transport,
    budget: v.budget,
    now: () => '2026-10-25T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  return { result, requests, threw, postAnswered, postTimes }
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

/** The suite 0.16.0 spec, computed here and not by latency.ts: for a frozen
 *  0.15.0 result and the times reported for the POSTs that were answered. Only a
 *  run whose handshake stopped at a credential gate withholds them: its
 *  discovery_handshake is COMPLETED/UNVERIFIED credential_required (the
 *  handshake-gated branch writes exactly that, and nothing else does). A gate on
 *  tools/list alone is measured. Nearest rank: the ⌈p·n/100⌉-th smallest. */
function LATENCY_ORACLE(old: ProbeResult, postTimes: number[], postAnswered: boolean): Pick<Assertion, 'execution_status' | 'assertion_status' | 'reason' | 'unverified_reason'> {
  const handshake = old.assertions.find((a) => a.check_id === 'discovery_handshake')!
  const gated = handshake.execution_status === 'COMPLETED' && handshake.assertion_status === 'UNVERIFIED' && handshake.reason?.key === 'credential_required'
  const skipped = (key: string) => ({ execution_status: 'SKIPPED' as const, assertion_status: 'UNVERIFIED' as const, reason: { key }, unverified_reason: { key } })
  if (postTimes.length === 0) return skipped(postAnswered ? 'latency_not_recorded' : 'latency_no_samples')
  if (gated) return skipped('latency_not_signed_auth_gated')
  const ascending = [...postTimes].sort((a, b) => a - b)
  const nth = (p: number) => ascending[Math.ceil((p * ascending.length) / 100) - 1]!
  return {
    execution_status: 'COMPLETED',
    assertion_status: 'VERIFIED',
    reason: { key: 'latency_measured', params: { p50_ms: nth(50), p95_ms: nth(95), n: ascending.length, timed_to: 'response_headers' } },
    unverified_reason: null,
  }
}

/** `old` with its latency_profile row's four verdict fields set to `row`, keys in their place. */
function withLatency(old: ProbeResult, row: ReturnType<typeof LATENCY_ORACLE>): ProbeResult {
  const out = structuredClone(old)
  const a = out.assertions.find((x) => x.check_id === 'latency_profile')!
  a.execution_status = row.execution_status
  a.assertion_status = row.assertion_status
  a.reason = row.reason
  a.unverified_reason = row.unverified_reason
  return out
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
      yield [`GET ${hops}×302 ${crossHost ? 'cross' : 'same'}-host, maxRedirects=0`, { budget: { ...DEFAULT_PROBE_BUDGET, maxRedirects: 0 }, getRedirects: { hops, crossHost } }]
    }
  }
}

/** [label, the error as the implementation receives it, the same error as the frozen 0.15.0 suite receives it]. */
const ERRORS: [string, () => unknown, () => unknown][] = [
  ['OtherHostDeclined', () => new OtherHostDeclined(), () => new FrozenOtherHostDeclined()],
  ['own Error (adapter argument check)', () => new TypeError('guarded-fetch-adapter: unsupported request body type'), () => new TypeError('guarded-fetch-adapter: unsupported request body type')],
  ['guard PRIVATE_USE', () => Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 }), () => Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 })],
]

// ---------------------------------------------------------------------------
// The invariant over A and B, untimed and timed.
// ---------------------------------------------------------------------------

let violations = 0
const failures: string[] = []
function violation(id: string, what: string) {
  violations++
  if (failures.length < 200) failures.push(`${id}: ${what}`)
}
const outcomes = { untimed: new Map<string, number>(), timed: new Map<string, number>() }
const nSeen = new Set<number>()
let toolsListGateMeasured = 0
let runs = 0

function compare(id: string, now: Run, old: Run, timed: boolean) {
  runs++
  if (!identical(now.requests, old.requests)) { violation(id, 'request sequence differs'); return }
  if (now.threw !== old.threw) { violation(id, 'one side reached the throwing request and the other did not'); return }
  let want: ProbeResult
  try {
    want = timed ? withLatency(old.result, LATENCY_ORACLE(old.result, old.postTimes, old.postAnswered)) : latency0160Remap(old.result, old.postAnswered)
  } catch (e) { violation(id, `remap refused: ${(e as Error).message}`); return }
  if (!identical(now.result, want)) {
    violation(id, `ProbeResult is not 0.15.0's with the latency row\n           new ${JSON.stringify(now.result.assertions.find((a) => a.check_id === 'latency_profile'))}\n           want ${JSON.stringify(want.assertions.find((a) => a.check_id === 'latency_profile'))}`)
    return
  }
  const row = now.result.assertions.find((a) => a.check_id === 'latency_profile')!
  const tally = timed ? outcomes.timed : outcomes.untimed
  tally.set(row.reason!.key, (tally.get(row.reason!.key) ?? 0) + 1)
  if (row.reason?.key === 'latency_measured') nSeen.add(row.reason.params!.n as number)
  const gatedOn = (check_id: string) => now.result.assertions.find((a) => a.check_id === check_id)!.reason?.key === 'credential_required'
  if (timed && row.reason?.key === 'latency_measured' && gatedOn('tools_list') && !gatedOn('discovery_handshake')) toolsListGateMeasured++
}

const started = Date.now()
let totalA = 0, totalB = 0
for (const timed of [false, true]) {
  for (const fixture of FIXTURE_CORPUS) {
    for (const [label, v] of variants()) {
      totalA++
      const id = `A ${timed ? 'timed' : 'untimed'} ${fixture.id} / ${label}`
      try {
        const now = await runOnce(runProbe, fixture.createHandler, v, timed)
        const old = await runOnce(frozen0150RunProbe as Probe, fixture.createHandler, v, timed)
        compare(id, now, old, timed)
      } catch (e) {
        violation(id, `threw ${(e as Error).message}`)
      }
    }
    for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
      for (const [label, make, makeFrozen] of ERRORS) {
        totalB++
        const id = `B ${timed ? 'timed' : 'untimed'} ${fixture.id} / ${label} @ request ${position}`
        try {
          const now = await runOnce(runProbe, fixture.createHandler, { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make } }, timed)
          const old = await runOnce(frozen0150RunProbe as Probe, fixture.createHandler, { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make: makeFrozen } }, timed)
          compare(id, now, old, timed)
        } catch (e) {
          violation(id, `threw ${(e as Error).message}`)
        }
      }
    }
  }
}

const show = (m: Map<string, number>) => [...m].sort().map(([k, n]) => `${k} ${n}`).join(', ')
console.log(`  A: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants × 2 transports = ${totalA}; B: ${FIXTURE_CORPUS.length} fixtures × ${DEFAULT_PROBE_BUDGET.maxRequests} positions × ${ERRORS.length} errors × 2 transports = ${totalB}; ${((Date.now() - started) / 1000).toFixed(1)}s`)
console.log(`  latency_profile, untimed: ${show(outcomes.untimed)}`)
console.log(`  latency_profile, timed: ${show(outcomes.timed)}; n seen: ${[...nSeen].sort((a, b) => a - b).join(', ')}; tools/list-only gate measured: ${toolsListGateMeasured}`)

await t(`A + B, 0.16.0 vs frozen 0.15.0, untimed and timed: the same requests, and 0.15.0's result with only the latency_profile row as specified: all ${totalA + totalB} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('A + B are not vacuous: untimed gives latency_not_recorded and latency_no_samples; timed gives all three of latency_measured, latency_not_signed_auth_gated and latency_no_samples, with n from 1 to at least 5 (a legacy handshake), and a tools/list-only gate measured', () => {
  assert.ok(FIXTURE_CORPUS.length >= 76, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  assert.equal(runs, totalA + totalB)
  assert.deepStrictEqual([...outcomes.untimed.keys()].sort(), ['latency_no_samples', 'latency_not_recorded'])
  assert.deepStrictEqual([...outcomes.timed.keys()].sort(), ['latency_measured', 'latency_no_samples', 'latency_not_signed_auth_gated'])
  assert.ok(nSeen.has(1) && Math.max(...nSeen) >= 5, `n seen: ${[...nSeen].join(',')}`)
  assert.ok(toolsListGateMeasured >= 1, `a tools/list-only gate, timed, measured: ${toolsListGateMeasured}`)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
