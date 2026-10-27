/**
 * Suite 0.14.0 differential (auth-gated signing) — the evidence that recording
 * the credential gate changed nothing but adding that record.
 *
 * Suite 0.14.0 adds ProbeResult.authObservation: on a run stopped at a
 * credential gate whose auth_metadata was judged from that gate's challenge,
 * the challenge reduced to what an 'auth_gated' attestation payload records
 * (auth-observation.ts). It sends no new request and changes no assertion.
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.13.0 — ./frozen/suite-0.13.0/, byte for byte the suite 0.13.0
 *      files at 9b577f6a (checks.json too: registry 0.12.0, the one suite
 *      0.13.0 shipped with): probe.ts's whole in-package import closure under
 *      src/, and checks.json beside it, in the same relative layout as
 *      packages/checks itself, so not one import specifier had to be edited and
 *      there is no `// FROZEN:` header. The first test checks each git blob id;
 *      the third, that nothing the frozen copy reaches outside that directory
 *      has changed (CLOSURE_0130_BLOBS).
 *
 * Inputs: input sets A and B of suite-0130-differential.test.ts, verbatim (the
 * whole fixture corpus × budget / GuardSignals / baseline / GET-redirect
 * variants; and the corpus with request p throwing OtherHostDeclined, an
 * Error of our own, or an ssrf-guard error). Both suites offer the same
 * revisions, so no request is translated.
 *
 * Invariant, for every input:
 *   - the request sequence the target sees is identical (method, URL, every
 *     header, body);
 *   - the implementation's ProbeResult without authObservation is 0.13.0's
 *     (same own keys in the same order at every level, Object.is on every
 *     leaf), and authObservation, when present, is its last own key;
 *   - authObservation is present exactly when tools_list carries the
 *     credential_required reason and auth_metadata COMPLETED (the gate's
 *     metadata request ran to an answer), and then: its scheme is that
 *     reason's scheme, and resource_metadata_body_digest is the sha256 of the
 *     body of the run's last request when that request is a GET answered 200
 *     (the metadata request, after any redirects), and null otherwise.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { posix } from 'node:path'
import ts from 'typescript'
import { DEFAULT_PROBE_BUDGET, SsrfBlocked } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { withoutAuthObservation } from './suite-0140-remap.ts'
import { pagedToolsList } from './suite-0150-remap.ts'
import { recordSuite0180, suite0180Remap } from './suite-0180-remap.ts'
import type { Suite0180Observed } from './suite-0180-remap.ts'
import { runProbe as frozen0130RunProbe } from './frozen/suite-0.13.0/src/probe.ts'
import { OtherHostDeclined } from './other-host-declined.ts'
import { OtherHostDeclined as FrozenOtherHostDeclined } from './frozen/suite-0.13.0/src/other-host-declined.ts'
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
const FROZEN_0130_DIR = 'packages/checks/src/frozen/suite-0.13.0'
const readRepo = (path: string) => readFileSync(new URL(path, REPO_ROOT), 'utf8')
const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}

/** Every file in frozen/suite-0.13.0, by its path below that directory, pinned
 *  to `git rev-parse 9b577f6a:packages/checks/<path>` (suite 0.13.0, registry
 *  0.12.0). Compared whole: no header is dropped and no import path is restored
 *  before hashing, because none was added or changed. */
const FROZEN_0130_BLOBS: Record<string, string> = {
  'checks.json': '0af81aa42257da37e6f1ef5c108b415ab72e4f9e',
  'src/auth.ts': '0f32e7b3f4d7b61f62e75ac68a942b85f338a50c',
  'src/error-taxonomy.ts': '0a18d6a872a077372ea44589879bdb9f390678b6',
  'src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'src/other-host-declined.ts': 'f8e53d6ca2700e837d265ed4e839c019941cdd67',
  'src/probe.ts': 'a3a237b5b96d2f0b8511ceae3552f9eaaa3a2170',
  'src/protocol.ts': '611aa368230de77b431d7a9c81e6abf3d7f3570a',
  'src/registry.ts': 'bcce9c9f3a032195548726da1c83985ae3e0b1f9',
  'src/types.ts': 'c68dd7f4033b66dba1562be3014b5946fe65b948',
  'src/wire.ts': '73314f32dec3befcb82edfa8afa70e05223d16b6',
}

/** The in-repo import closure of frozen/suite-0.13.0/src/probe.ts OUTSIDE that
 *  directory (importClosure0130; imports read off the TypeScript AST): only the
 *  three other workspace packages it imports by name. No live packages/checks
 *  file is in this list — the frozen copy reaches none, so the suite 0.14.0
 *  edits to probe.ts, auth.ts, types.ts and checks.json cannot reach it.
 *
 *  Each file is pinned to its blob in suite 0.14.0 (git hash-object <path>),
 *  which is the 9b577f6a blob for every one but the attestation-schema files
 *  0.14.0 itself changes (the v0.4 schema amendments, attestation.ts and
 *  index.ts's new exports, the regenerated types) and credential-shapes.ts,
 *  which it adds and index.ts re-exports. The frozen suite uses only
 *  assertUnverifiedHasReason and type Assertion from that package, both
 *  unchanged, so none of them can alter what it computes. If this test goes red
 *  for any file, the frozen run may no longer compute 0.13.0: freeze that
 *  file's 0.13.0 version first. */
const CLOSURE_0130_BLOBS: Record<string, string> = {
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
const CLOSURE_0130_THIRD_PARTY: string[] = []

/** Verbatim from probe-tool-name-differential.test.ts (T86b R6). */
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

/** importClosure0120 from suite-0130-differential.test.ts, verbatim but for
 *  the entry point. */
function importClosure0130(): { files: string[]; inside: string[]; thirdParty: string[] } {
  const packagesByName = new Map<string, string>()
  for (const dir of readdirSync(new URL('packages/', REPO_ROOT))) {
    const pj = new URL(`packages/${dir}/package.json`, REPO_ROOT)
    if (existsSync(pj)) packagesByName.set((JSON.parse(readFileSync(pj, 'utf8')) as { name: string }).name, `packages/${dir}`)
  }
  const seen = new Set<string>(), thirdParty = new Set<string>()
  const queue = [`${FROZEN_0130_DIR}/src/probe.ts`]
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
    files: all.filter((f) => !f.startsWith(`${FROZEN_0130_DIR}/`)).sort(),
    inside: all.filter((f) => f.startsWith(`${FROZEN_0130_DIR}/`)).map((f) => f.slice(FROZEN_0130_DIR.length + 1)).sort(),
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

await t('the frozen suite-0.13.0 files are the 9b577f6a blobs, byte for byte (git blob id recomputed, nothing stripped or restored first)', () => {
  for (const [path, blob] of Object.entries(FROZEN_0130_BLOBS)) {
    assert.equal(blobId(readRepo(`${FROZEN_0130_DIR}/${path}`)), blob, `${path} is not the 0.13.0 file`)
  }
})

await t('frozen/suite-0.13.0 holds exactly the pinned files, and they are exactly what its probe.ts reaches inside it (nothing unpinned, nothing unreached)', () => {
  const pinned = Object.keys(FROZEN_0130_BLOBS).sort()
  assert.deepStrictEqual(listFiles(FROZEN_0130_DIR), pinned, 'a file in frozen/suite-0.13.0 is not pinned, or a pinned one is missing')
  assert.deepStrictEqual(importClosure0130().inside, pinned, 'the frozen probe.ts no longer reaches exactly the pinned files')
})

await t('the in-repo import closure of frozen/suite-0.13.0 outside it is exactly the pinned list, and every pinned file hashes to its pinned blob (git blob id recomputed)', () => {
  const closure = importClosure0130()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_0130_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_0130_BLOBS)')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_0130_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_0130_BLOBS)) assert.equal(blobId(readRepo(path)), blob, `${path} changed: freeze its 0.13.0 version into frozen/suite-0.13.0 first`)
})

// ---------------------------------------------------------------------------
// Harness — runOnce / identical / variants / ERRORS from
// suite-0130-differential.test.ts, without the offer translation, and with
// the body of every 200 answer kept.
// ---------------------------------------------------------------------------

type Probe = typeof runProbe

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
  /** The last request's method, status and body bytes, as the target answered it (null if it threw). */
  last: { method: string; status: number; body: Uint8Array } | null
  /** Suites 0.15.0 to 0.18.0: what suite0180Remap reads off this run's transport. */
  observed: Suite0180Observed
}

async function runOnce(probe: Probe, createHandler: () => (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>, v: Variant): Promise<Run> {
  const handler = createHandler()
  const requests: string[] = []
  let position = 0
  let redirectsServed = 0
  let threw = false
  let last: Run['last'] = null
  const answered: Promise<void>[] = []
  const keep = (method: string, response: Response): Response => {
    const copy = response.clone()
    const entry = { method, status: response.status, body: new Uint8Array() }
    last = entry
    answered.push(copy.arrayBuffer().then((b) => { entry.body = new Uint8Array(b) }, () => {}))
    return response
  }
  const fetchImpl: FetchLike = async (input, init, onGuardSignal) => {
    position++
    last = null
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const method = init?.method ?? 'GET'
    const headers: string[] = []
    new Headers(init?.headers).forEach((value, key) => { headers.push(`${key}: ${value}`) })
    requests.push(JSON.stringify([method, href, headers, typeof init?.body === 'string' ? init.body : null]))
    if (v.throwAt && v.throwAt.position === position) { threw = true; throw v.throwAt.make() }
    for (const s of v.signalOn ?? []) if (s.position === position) onGuardSignal(s.signals)
    if (method === 'GET' && v.getRedirects && redirectsServed < v.getRedirects.hops) {
      redirectsServed++
      const next = new URL(href)
      if (v.getRedirects.crossHost) next.hostname = `hop${redirectsServed}.example.net`
      next.searchParams.set('hop', String(redirectsServed))
      return keep(method, new Response('', { status: 302, headers: { location: next.href } }))
    }
    if (method === 'GET' && v.getRedirects) {
      // Hand the fixture the URL it was originally asked for.
      const original = new URL(href)
      original.searchParams.delete('hop')
      if (v.getRedirects.crossHost) original.hostname = new URL(ENDPOINT).hostname
      return keep(method, await handler(original.href, init))
    }
    return keep(method, await handler(input, init))
  }
  const recorder = recordSuite0180(fetchImpl)
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: recorder.fetchImpl,
    budget: v.budget,
    now: () => '2026-10-20T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  await Promise.all(answered)
  return { result, requests, threw, last, observed: recorder.observed() }
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

/** [label, the error as the implementation receives it, the same error as the frozen 0.13.0 suite receives it]:
 *  OtherHostDeclined is recognised by class, and each suite has its own class. */
const ERRORS: [string, () => unknown, () => unknown][] = [
  ['OtherHostDeclined', () => new OtherHostDeclined(), () => new FrozenOtherHostDeclined()],
  ['own Error (adapter argument check)', () => new TypeError('guarded-fetch-adapter: unsupported request body type'), () => new TypeError('guarded-fetch-adapter: unsupported request body type')],
  ['guard PRIVATE_USE', () => Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 }), () => Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 })],
]

// ---------------------------------------------------------------------------
// The invariant.
// ---------------------------------------------------------------------------

let violations = 0
const failures: string[] = []
function violation(id: string, what: string) {
  violations++
  if (failures.length < 200) failures.push(`${id}: ${what}`)
}
const started = Date.now()

const sha256Ref = (bytes: Uint8Array) => 'sha256:' + createHash('sha256').update(bytes).digest('hex')

/** What the inputs reached, counted so the test below can say the input set is not vacuous. */
const seen = { paged: 0, runs: 0, observed: 0, gatedNotObserved: 0, digest: 0, noDigest: 0, url: 0, withheld: 0, thrown: new Map<string, number>(), notReached: 0 }

/** Both runs of one input, compared. */
function compare(id: string, now: Run, old: Run) {
  // Suite 0.15.0: a run whose tools/list paged is set aside (counted below); suite-0150-differential.test.ts proves it.
  if (pagedToolsList(now.requests)) { seen.paged++; return }
  seen.runs++
  if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
  if (!identical(withoutAuthObservation(now.result), suite0180Remap(old.result, old.observed))) {
    violation(id, `ProbeResult without authObservation is not 0.13.0's\n           new ${JSON.stringify(now.result).slice(0, 400)}\n           old ${JSON.stringify(old.result).slice(0, 400)}`)
  }
  const keys = Object.keys(now.result)
  if ('authObservation' in now.result && keys[keys.length - 1] !== 'authObservation') violation(id, 'authObservation is not the last own key')

  const row = (checkId: string) => now.result.assertions.find((a) => a.check_id === checkId)
  const gateReason = row('tools_list')?.reason
  const gated = gateReason?.key === 'credential_required' && row('auth_metadata')?.execution_status === 'COMPLETED'
  const observation = now.result.authObservation
  if (gated !== (observation !== undefined)) {
    violation(id, `authObservation ${observation ? 'present' : 'absent'} on a run that ${gated ? 'is' : 'is not'} gated with auth_metadata COMPLETED`)
    return
  }
  if (!observation) {
    if (gateReason?.key === 'credential_required') seen.gatedNotObserved++
    return
  }
  seen.observed++
  if (observation.scheme !== gateReason!.params!.scheme) violation(id, `scheme ${observation.scheme} is not the reason's ${String(gateReason!.params!.scheme)}`)
  const want = now.last && now.last.method === 'GET' && now.last.status === 200 ? sha256Ref(now.last.body) : null
  if (observation.resource_metadata_body_digest !== want) violation(id, `digest ${observation.resource_metadata_body_digest}, expected ${want}`)
  if (want === null) seen.noDigest++
  else seen.digest++
  if (observation.resource_metadata_url !== null) seen.url++
  if (observation.resource_metadata_url_withheld) seen.withheld++
}

let totalA = 0, totalB = 0

for (const fixture of FIXTURE_CORPUS) {
  for (const [label, v] of variants()) {
    totalA++
    const id = `A ${fixture.id} / ${label}`
    try {
      const now = await runOnce(runProbe, fixture.createHandler, v)
      const old = await runOnce(frozen0130RunProbe, fixture.createHandler, v)
      compare(id, now, old)
    } catch (e) {
      violation(id, `threw ${(e as Error).message}`)
    }
  }
}

for (const fixture of FIXTURE_CORPUS) {
  for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
    for (const [label, make, makeFrozen] of ERRORS) {
      totalB++
      const id = `B ${fixture.id} / ${label} @ request ${position}`
      try {
        const now = await runOnce(runProbe, fixture.createHandler, { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make } })
        const old = await runOnce(frozen0130RunProbe, fixture.createHandler, { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make: makeFrozen } })
        if (!pagedToolsList(now.requests) && now.threw !== old.threw) violation(id, 'one side reached the throwing request and the other did not')
        if (!now.threw) seen.notReached++
        else seen.thrown.set(label, (seen.thrown.get(label) ?? 0) + 1)
        compare(id, now, old)
      } catch (e) {
        violation(id, `threw ${(e as Error).message}`)
      }
    }
  }
}

console.log(`  A: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants = ${totalA}`)
console.log(`  B: ${FIXTURE_CORPUS.length} fixtures × ${DEFAULT_PROBE_BUDGET.maxRequests} positions × ${ERRORS.length} errors = ${totalB} (request reached: ${totalB - seen.notReached}; not reached: ${seen.notReached})`)
console.log(`  set aside, tools/list paged (suite 0.15.0): ${seen.paged}`)
console.log(`  authObservation recorded: ${seen.observed} (body digest ${seen.digest}, none ${seen.noDigest}; url recorded ${seen.url}, withheld ${seen.withheld}); credential_required without it: ${seen.gatedNotObserved}`)
console.log(`  ${((Date.now() - started) / 1000).toFixed(1)}s`)

await t(`0.14.0 vs frozen 0.13.0: the same requests, 0.13.0's result plus authObservation and nothing else, and authObservation exactly on the gated runs whose auth_metadata completed: all ${totalA + totalB} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: every error is thrown, and authObservation is recorded with and without a body digest, and is also absent on some credential_required run', () => {
  assert.ok(FIXTURE_CORPUS.length >= 76, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const [label] of ERRORS) assert.ok((seen.thrown.get(label) ?? 0) > 0, `${label} never thrown`)
  assert.ok(seen.notReached > 0)
  assert.ok(seen.digest > 0, 'no recorded authObservation carries a body digest')
  assert.ok(seen.noDigest > 0, 'every recorded authObservation carries a body digest')
  assert.ok(seen.url > 0, 'no recorded authObservation carries a URL')
  assert.ok(seen.gatedNotObserved > 0, 'no credential_required run went without authObservation (an auth_metadata that did not complete)')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
