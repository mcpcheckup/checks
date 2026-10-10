/**
 * Suite 0.11.0 differential — the evidence that this package's half of the
 * change (OtherHostDeclined and its reason; credential headers dropped on a
 * cross-host GET hop) changed nothing but the reason that error gets.
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.10.0 — ./frozen/suite-0.10.0/, byte for byte the suite 0.10.0
 *      files (ec8ce3b3): probe.ts's whole in-package import closure under
 *      src/, and checks.json beside it, in the same relative layout as
 *      packages/checks itself, so not one import specifier had to be edited
 *      and there is no `// FROZEN:` header. The first test checks each git
 *      blob id; the second, that nothing the frozen copy reaches outside that
 *      directory has changed (CLOSURE_0100_BLOBS). The frozen run therefore
 *      uses its own 0.10.0 wire.ts, not the live one.
 *
 * Inputs:
 *   A. The whole fixture corpus crossed with the budget / GuardSignals /
 *      baseline / GET-redirect variants guard-error-classification-
 *      differential.test.ts uses (same-host and cross-host chains up to one
 *      hop past the redirect budget). No fetchImpl here throws, and no
 *      request carries a credential header.
 *   B. The corpus again, with request number p (p = 1 … maxRequests) throwing
 *      one error instead of answering: OtherHostDeclined, a plain Error of our
 *      own, and one ssrf-guard error.
 *
 * Invariant:
 *   - A, and B for the plain Error and the guard error (or whenever the run
 *     never reaches request p): the two ProbeResults are identical (same own
 *     keys in the same order at every level, Object.is on every leaf), and so
 *     is the request sequence (method, URL, every header, body).
 *   - B for OtherHostDeclined: the request sequences are identical, and the
 *     implementation's ProbeResult is 0.10.0's with exactly this remap and
 *     nothing else — every row 0.10.0's catch wrote as `probe_aborted
 *     { message }` (reachability, when the error landed before the handshake
 *     settled it) or `probe_cascade_incomplete` (the rows that never ran)
 *     carries `probe_declined_other_host` instead, in both `reason` and
 *     `unverified_reason`.
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
import { runProbe as frozen0100RunProbe } from './frozen/suite-0.10.0/src/probe.ts'
import { OtherHostDeclined } from './other-host-declined.ts'
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
const FROZEN_0100_DIR = 'packages/checks/src/frozen/suite-0.10.0'
const readRepo = (path: string) => readFileSync(new URL(path, REPO_ROOT), 'utf8')
const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}

/** Every file in frozen/suite-0.10.0, by its path below that directory, pinned
 *  to `git rev-parse ec8ce3b3:packages/checks/<path>` (suite 0.10.0). Compared
 *  whole: no header is dropped and no import path is restored before hashing,
 *  because none was added or changed. */
const FROZEN_0100_BLOBS: Record<string, string> = {
  'checks.json': '64ecf38d8c667af4058dbb62c441230f2bc5e880',
  'src/auth.ts': 'f8b78f074b997b38e39319d97ec93807f73a0c65',
  'src/error-taxonomy.ts': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
  'src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'src/probe.ts': '3ef758e4bc89e6779d315edc802e30eedd5ad360',
  'src/protocol.ts': '2d39fd28a93a21000b6cc008336971bd1080d030',
  'src/registry.ts': 'bcce9c9f3a032195548726da1c83985ae3e0b1f9',
  'src/types.ts': '59d38f860a3cd07989421fc2e6b97b60cabedd10',
  'src/wire.ts': 'c0ab8b30a92e22457c20acb21bc166b6c1336e56',
}

/** The in-repo import closure of frozen/suite-0.10.0/src/probe.ts OUTSIDE that
 *  directory (importClosure0100; imports read off the TypeScript AST): only the
 *  three other workspace packages it imports by name, each file pinned to
 *  `git rev-parse ec8ce3b3:<path>` except ssrf-guard's guarded-fetch.ts, which
 *  this same change edits (the followRedirects option, default unchanged) and
 *  is pinned to its 0.11.0 blob (git hash-object at that change). That edit
 *  cannot alter what the frozen files compute: they reach ssrf-guard for its
 *  error classes and the ProbeBudget type, and nothing below calls
 *  guardedFetch. No live packages/checks file is in this list — the frozen copy
 *  reaches none. If this test goes red for any file, the frozen run no longer
 *  computes 0.10.0: freeze that file's 0.10.0 version first.
 *
 *  The special-purpose address change re-pins two ssrf-guard files to their
 *  blob at that change (git hash-object <path>): ip-policy.ts (the IANA
 *  special-purpose address tables) and url-target.ts (host name rules, before
 *  any lookup). Neither can alter what the frozen files compute: they reach
 *  ssrf-guard only for its error classes and the ProbeBudget type, and nothing
 *  they run calls guardedFetch, classifyIp or parseGuardedTarget. */
const CLOSURE_0100_BLOBS: Record<string, string> = {
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
  'packages/ssrf-guard/src/audit.ts': 'c2f08ab05e4bdb6425c5feba789d19e0c7293073',
  'packages/ssrf-guard/src/budget.ts': 'c920ff71d6e0477fd22ef79c0077973227cbb74f',
  'packages/ssrf-guard/src/dns-wire.ts': '04357f1c08ee2d649a382d2640580903323af222',
  'packages/ssrf-guard/src/errors.ts': '958b4f9b63d9a5901b2097a2d564ef2afff79e57',
  'packages/ssrf-guard/src/guarded-fetch.ts': 'eda760ca7ffb210feb2a685ca0dd43d34a9ab86a', // suite 0.11.0 (followRedirects; see above) — git hash-object packages/ssrf-guard/src/guarded-fetch.ts
  'packages/ssrf-guard/src/index.ts': '9d301879dc35ac0a85a2cd5005d70f2e75406755',
  'packages/ssrf-guard/src/ip-policy.ts': 'c40a0ef0a1af6ea5721edebcdd3e0660831b411e', // special-purpose address change (see above) — git hash-object packages/ssrf-guard/src/ip-policy.ts
  'packages/ssrf-guard/src/rate-limit.ts': '20f0e9e542de6708411456c0a46d7fdad77e0773',
  'packages/ssrf-guard/src/resolve.ts': '8ba7ae7c4a97c0589fbb8da1166de89f36bdb5d0',
  'packages/ssrf-guard/src/response-view.ts': 'b1b0e3e040f6d6acf66700758323b6bfae223d96',
  'packages/ssrf-guard/src/url-target.ts': 'c1d8f47ef7b0402b45bd9f555cd82fd0f0ec103a', // special-purpose address change (see above) — git hash-object packages/ssrf-guard/src/url-target.ts
}
const CLOSURE_0100_THIRD_PARTY: string[] = []

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

/** importClosure080 from guard-error-classification-differential.test.ts,
 *  verbatim but for the entry point; `inside` is every file reached inside
 *  the frozen directory, so the test below can hold it against the pinned
 *  file list too. */
function importClosure0100(): { files: string[]; inside: string[]; thirdParty: string[] } {
  const packagesByName = new Map<string, string>()
  for (const dir of readdirSync(new URL('packages/', REPO_ROOT))) {
    const pj = new URL(`packages/${dir}/package.json`, REPO_ROOT)
    if (existsSync(pj)) packagesByName.set((JSON.parse(readFileSync(pj, 'utf8')) as { name: string }).name, `packages/${dir}`)
  }
  const seen = new Set<string>(), thirdParty = new Set<string>()
  const queue = [`${FROZEN_0100_DIR}/src/probe.ts`]
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
    files: all.filter((f) => !f.startsWith(`${FROZEN_0100_DIR}/`)).sort(),
    inside: all.filter((f) => f.startsWith(`${FROZEN_0100_DIR}/`)).map((f) => f.slice(FROZEN_0100_DIR.length + 1)).sort(),
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

await t('the frozen suite-0.10.0 files are the ec8ce3b3 blobs, byte for byte (git blob id recomputed, nothing stripped or restored first)', () => {
  for (const [path, blob] of Object.entries(FROZEN_0100_BLOBS)) {
    assert.equal(blobId(readRepo(`${FROZEN_0100_DIR}/${path}`)), blob, `${path} is not the 0.10.0 file`)
  }
})

await t('frozen/suite-0.10.0 holds exactly the pinned files, and they are exactly what its probe.ts reaches inside it (nothing unpinned, nothing unreached)', () => {
  const pinned = Object.keys(FROZEN_0100_BLOBS).sort()
  assert.deepStrictEqual(listFiles(FROZEN_0100_DIR), pinned, 'a file in frozen/suite-0.10.0 is not pinned, or a pinned one is missing')
  assert.deepStrictEqual(importClosure0100().inside, pinned, 'the frozen probe.ts no longer reaches exactly the pinned files')
})

await t('the in-repo import closure of frozen/suite-0.10.0 outside it is exactly the pinned list, and every pinned file hashes to its pinned blob (git blob id recomputed)', () => {
  const closure = importClosure0100()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_0100_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_0100_BLOBS)')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_0100_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_0100_BLOBS)) assert.equal(blobId(readRepo(path)), blob, `${path} changed: freeze its 0.10.0 version into frozen/suite-0.10.0 first`)
})

// ---------------------------------------------------------------------------
// Harness — runOnce / identical / variants verbatim from
// guard-error-classification-differential.test.ts.
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

interface Run { result: ProbeResult; requests: string[]; threw: boolean }

async function runOnce(probe: Probe, createHandler: () => (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>, v: Variant): Promise<Run> {
  const handler = createHandler()
  const requests: string[] = []
  let position = 0
  let redirectsServed = 0
  let threw = false
  const fetchImpl: FetchLike = async (input, init, onGuardSignal) => {
    position++
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
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget: v.budget,
    now: () => '2026-09-25T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  return { result, requests, threw }
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
// Input set B's errors, and the one intended remap.
// ---------------------------------------------------------------------------

const DECLINED = { key: 'probe_declined_other_host' }
/** [label, error, whether the implementation remaps 0.10.0's catch reasons to DECLINED]. */
const ERRORS: [string, () => unknown, boolean][] = [
  ['OtherHostDeclined', () => new OtherHostDeclined(), true],
  ['own Error (adapter argument check)', () => new TypeError('guarded-fetch-adapter: unsupported request body type'), false],
  ['guard PRIVATE_USE', () => Object.assign(new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use'), { hop: 0 }), false],
]

/** 0.10.0's result with the one intended change: the rows its catch wrote as
 *  probe_aborted / probe_cascade_incomplete carry DECLINED instead. */
function remapped(old: ProbeResult): ProbeResult {
  const out = structuredClone(old)
  for (const a of out.assertions) {
    if (a.reason?.key === 'probe_aborted' || a.reason?.key === 'probe_cascade_incomplete') {
      a.reason = structuredClone(DECLINED)
      a.unverified_reason = structuredClone(DECLINED)
    }
  }
  return out
}

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

let totalA = 0, totalB = 0
const seen = { crossHostGets: 0, thrown: new Map<string, number>(), notReached: 0, remappedRows: 0, declinedBeforeHandshake: 0, declinedAfterHandshake: 0 }

for (const fixture of FIXTURE_CORPUS) {
  for (const [label, v] of variants()) {
    totalA++
    const id = `A ${fixture.id} / ${label}`
    try {
      const now = await runOnce(runProbe, fixture.createHandler, v)
      const old = await runOnce(frozen0100RunProbe, fixture.createHandler, v)
      if (!identical(now.result, old.result)) violation(id, `ProbeResult differs\n           new ${JSON.stringify(now.result).slice(0, 400)}\n           old ${JSON.stringify(old.result).slice(0, 400)}`)
      if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
      if (v.getRedirects?.crossHost && now.requests.some((r) => r.includes('.example.net'))) seen.crossHostGets++
    } catch (e) {
      violation(id, `threw ${(e as Error).message}`)
    }
  }
}

for (const fixture of FIXTURE_CORPUS) {
  for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
    for (const [label, make, remaps] of ERRORS) {
      totalB++
      const id = `B ${fixture.id} / ${label} @ request ${position}`
      const v: Variant = { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make } }
      try {
        const now = await runOnce(runProbe, fixture.createHandler, v)
        const old = await runOnce(frozen0100RunProbe, fixture.createHandler, v)
        if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
        if (now.threw !== old.threw) violation(id, 'one side reached the throwing request and the other did not')
        if (!now.threw) { seen.notReached++ }
        else seen.thrown.set(label, (seen.thrown.get(label) ?? 0) + 1)
        const expected = now.threw && remaps ? remapped(old.result) : old.result
        if (!identical(now.result, expected)) violation(id, `ProbeResult is not 0.10.0's ${remaps && now.threw ? 'with the one remap' : 'unchanged'}\n           new ${JSON.stringify(now.result.assertions.map((a) => [a.check_id, a.reason]))}\n           old ${JSON.stringify(old.result.assertions.map((a) => [a.check_id, a.reason]))}`)
        if (now.threw && remaps) {
          const rows = now.result.assertions.filter((a) => identical(a.reason, DECLINED))
          seen.remappedRows += rows.length
          if (rows.length === 0) violation(id, 'OtherHostDeclined was thrown but no row carries probe_declined_other_host')
          if (now.result.assertions.some((a) => a.reason?.key === 'probe_aborted' || a.reason?.key === 'probe_cascade_incomplete')) violation(id, 'OtherHostDeclined still produced probe_aborted / probe_cascade_incomplete')
          if (rows.some((a) => a.assertion_status !== 'UNVERIFIED')) violation(id, 'a declined row is not UNVERIFIED')
          const reach = now.result.assertions.find((a) => a.check_id === 'reachability')!
          if (reach.execution_status === 'ERROR') seen.declinedBeforeHandshake++
          else seen.declinedAfterHandshake++
        }
      } catch (e) {
        violation(id, `threw ${(e as Error).message}`)
      }
    }
  }
}

console.log(`  A: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants = ${totalA} (runs with a cross-host GET hop: ${seen.crossHostGets})`)
console.log(`  B: ${FIXTURE_CORPUS.length} fixtures × ${DEFAULT_PROBE_BUDGET.maxRequests} positions × ${ERRORS.length} errors = ${totalB} (request reached: ${totalB - seen.notReached}; not reached: ${seen.notReached}); rows remapped: ${seen.remappedRows}; OtherHostDeclined before the handshake ${seen.declinedBeforeHandshake}, after it ${seen.declinedAfterHandshake}; ${((Date.now() - started) / 1000).toFixed(1)}s`)

await t(`0.11.0 vs frozen 0.10.0: identical off the OtherHostDeclined path, and on it differs only by probe_declined_other_host: all ${totalA + totalB} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: every error is thrown, OtherHostDeclined lands both before the handshake and after it, and cross-host GET hops are exercised', () => {
  assert.ok(FIXTURE_CORPUS.length >= 76, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const [label] of ERRORS) assert.ok((seen.thrown.get(label) ?? 0) > 0, `${label} never thrown`)
  assert.ok(seen.declinedBeforeHandshake > 0, 'OtherHostDeclined never before the handshake')
  assert.ok(seen.declinedAfterHandshake > 0, 'OtherHostDeclined never after the handshake')
  assert.ok(seen.remappedRows > 0)
  assert.ok(seen.notReached > 0)
  assert.ok(seen.crossHostGets > 0, 'no run followed a cross-host GET hop')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
