/**
 * Suite 0.12.0 differential — the evidence that recording latency_profile,
 * auth_metadata and error_taxonomy honestly changed nothing but those rows.
 *
 * Suite 0.11.0 wrote COMPLETED/VERIFIED for three checks that had observed
 * nothing: latency_profile (nothing measures latency), auth_metadata (when the
 * tools/call answer was not a 401 there was no challenge to validate) and
 * error_taxonomy (when the tools/call answer was a 401 or 403 no protocol error
 * came back to classify). Suite 0.12.0 records all three SKIPPED/UNVERIFIED —
 * nothing for the check to look at — latency_profile with latency_not_recorded
 * on every run, the second with auth_no_challenge_observed, and the third with
 * error_shape_not_observed.
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.11.0 — ./frozen/suite-0.11.0/, byte for byte the suite 0.11.0
 *      files (317e3421; checks.json is main's at 47c13a3e, registry 0.10.0, the
 *      last one suite 0.11.0 shipped with): probe.ts's whole in-package import
 *      closure under src/, and checks.json beside it, in the same relative
 *      layout as packages/checks itself, so not one import specifier had to be
 *      edited and there is no `// FROZEN:` header. The first test checks each
 *      git blob id; the second, that nothing the frozen copy reaches outside
 *      that directory has changed (CLOSURE_0110_BLOBS). The frozen run
 *      therefore uses its own 0.11.0 judges and wire.ts, not the live ones.
 *
 * Inputs:
 *   A. The whole fixture corpus crossed with the budget / GuardSignals /
 *      baseline / GET-redirect variants guard-error-classification-
 *      differential.test.ts uses (same-host and cross-host chains up to one
 *      hop past the redirect budget).
 *   B. The corpus again, with request number p (p = 1 … maxRequests) throwing
 *      one error instead of answering: OtherHostDeclined, a plain Error of our
 *      own, and one ssrf-guard error — the paths on which rows that never ran
 *      get their reason from the catch.
 *
 * Invariant (suite-0120-remap.ts states the remap once; it reads only the
 * frozen result and the HTTP status the harness saw on the reserved-name
 * tools/call, nothing from the implementation under test):
 *   - for every input, the request sequence (method, URL, every header, body)
 *     is identical to 0.11.0's;
 *   - the implementation's ProbeResult is 0.11.0's with the remap and nothing
 *     else (same own keys in the same order at every level, Object.is on every
 *     leaf): latency_profile is SKIPPED/UNVERIFIED latency_not_recorded;
 *     auth_metadata that 0.11.0 recorded COMPLETED/VERIFIED on a tools/call
 *     answer that was not a 401 is SKIPPED/UNVERIFIED
 *     auth_no_challenge_observed; error_taxonomy that 0.11.0 recorded
 *     COMPLETED/VERIFIED on a 401 or 403 is SKIPPED/UNVERIFIED
 *     error_shape_not_observed. Every other row is 0.11.0's own.
 *   And, on the implementation's result alone, for every input (the claim the
 *   change exists to make true): auth_metadata is COMPLETED/VERIFIED only when
 *   the tools/call was answered 401, error_taxonomy only when it was answered
 *   and the answer was neither 401 nor 403, latency_profile never is, and a
 *   row that carries one of the three not-observed reasons is SKIPPED/UNVERIFIED
 *   (never COMPLETED, which would pull the badge of an open server down).
 *
 * Suite 0.13.0 (TODO 217) offers 2025-11-25 on the legacy initialize fallback and
 * records the offer. Each input therefore runs the implementation first and the
 * frozen suite through suite-0130-remap.ts's offerAsLive, which hands the target
 * the implementation's request wherever the frozen one differs only by the old
 * offer; the frozen result is then remapped by suite0130Remap after
 * suite0120Remap (probeOfferedRevision inserted, nothing else), and a replaced
 * header is allowed only on a run whose server declared no version. The offer
 * change itself is proved against frozen 0.12.0 by
 * suite-0130-differential.test.ts.
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
import { recordToolsCallStatus, suite0120Remap } from './suite-0120-remap.ts'
import { offerAsLive, offerSubstitutionProblem, suite0130Remap } from './suite-0130-remap.ts'
// Suite 0.14.0: the live result's authObservation is set aside before every comparison with the frozen result
// (suite-0140-remap.ts); suite-0140-differential.test.ts proves that key against frozen 0.13.0.
import { withoutAuthObservation } from './suite-0140-remap.ts'
import { runProbe as frozen0110RunProbe } from './frozen/suite-0.11.0/src/probe.ts'
import { OtherHostDeclined } from './other-host-declined.ts'
import { OtherHostDeclined as FrozenOtherHostDeclined } from './frozen/suite-0.11.0/src/other-host-declined.ts'
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
const FROZEN_0110_DIR = 'packages/checks/src/frozen/suite-0.11.0'
const readRepo = (path: string) => readFileSync(new URL(path, REPO_ROOT), 'utf8')
const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}

/** Every file in frozen/suite-0.11.0, by its path below that directory, pinned
 *  to `git rev-parse 317e3421:packages/checks/<path>` (suite 0.11.0), except
 *  checks.json, pinned to `git rev-parse 47c13a3e:packages/checks/checks.json`
 *  (registry 0.10.0: the registry suite 0.11.0 shipped with was bumped after
 *  317e3421 by two copy-only changes that left the suite version alone).
 *  Compared whole: no header is dropped and no import path is restored before
 *  hashing, because none was added or changed. */
const FROZEN_0110_BLOBS: Record<string, string> = {
  'checks.json': '679218719d8b2345c667bcd36f479548181caff7',
  'src/auth.ts': 'f8b78f074b997b38e39319d97ec93807f73a0c65',
  'src/error-taxonomy.ts': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
  'src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'src/other-host-declined.ts': 'f8e53d6ca2700e837d265ed4e839c019941cdd67',
  'src/probe.ts': 'f297753484a8774c6042663bf85a7d44144f48e2',
  'src/protocol.ts': '2d39fd28a93a21000b6cc008336971bd1080d030',
  'src/registry.ts': 'bcce9c9f3a032195548726da1c83985ae3e0b1f9',
  'src/types.ts': '59d38f860a3cd07989421fc2e6b97b60cabedd10',
  'src/wire.ts': '73314f32dec3befcb82edfa8afa70e05223d16b6',
}

/** The in-repo import closure of frozen/suite-0.11.0/src/probe.ts OUTSIDE that
 *  directory (importClosure0110; imports read off the TypeScript AST): only the
 *  three other workspace packages it imports by name, each file pinned to its
 *  blob at 47c13a3e (the same as at 317e3421 for every file below except the
 *  two re-pinned for the special-purpose address change, which came after it).
 *  Those two cannot alter what the frozen files compute: they reach ssrf-guard
 *  for its error classes and the ProbeBudget type, and nothing below calls
 *  guardedFetch, classifyIp or parseGuardedTarget. No live packages/checks file
 *  is in this list — the frozen copy reaches none, so the suite 0.12.0 edits to
 *  auth.ts, error-taxonomy.ts, probe.ts and checks.json cannot reach it. If this
 *  test goes red for any file, the frozen run no longer computes 0.11.0: freeze
 *  that file's 0.11.0 version first. */
const CLOSURE_0110_BLOBS: Record<string, string> = {
  // Re-pinned for the attestation-schema v0.4 dispatch, and again for suite 0.14.0's v0.4 amendments and credential-shapes.ts; the frozen suites use only assertUnverifiedHasReason and type Assertion, both unchanged.
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
  'packages/ssrf-guard/src/guarded-fetch.ts': 'eda760ca7ffb210feb2a685ca0dd43d34a9ab86a', // suite 0.11.0 (followRedirects; see above) — git hash-object packages/ssrf-guard/src/guarded-fetch.ts
  'packages/ssrf-guard/src/index.ts': '9d301879dc35ac0a85a2cd5005d70f2e75406755',
  'packages/ssrf-guard/src/ip-policy.ts': 'c40a0ef0a1af6ea5721edebcdd3e0660831b411e', // special-purpose address change (see above) — git hash-object packages/ssrf-guard/src/ip-policy.ts
  'packages/ssrf-guard/src/rate-limit.ts': '20f0e9e542de6708411456c0a46d7fdad77e0773',
  'packages/ssrf-guard/src/resolve.ts': '8ba7ae7c4a97c0589fbb8da1166de89f36bdb5d0',
  'packages/ssrf-guard/src/response-view.ts': 'b1b0e3e040f6d6acf66700758323b6bfae223d96',
  'packages/ssrf-guard/src/url-target.ts': 'c1d8f47ef7b0402b45bd9f555cd82fd0f0ec103a', // special-purpose address change (see above) — git hash-object packages/ssrf-guard/src/url-target.ts
}
const CLOSURE_0110_THIRD_PARTY: string[] = []

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
function importClosure0110(): { files: string[]; inside: string[]; thirdParty: string[] } {
  const packagesByName = new Map<string, string>()
  for (const dir of readdirSync(new URL('packages/', REPO_ROOT))) {
    const pj = new URL(`packages/${dir}/package.json`, REPO_ROOT)
    if (existsSync(pj)) packagesByName.set((JSON.parse(readFileSync(pj, 'utf8')) as { name: string }).name, `packages/${dir}`)
  }
  const seen = new Set<string>(), thirdParty = new Set<string>()
  const queue = [`${FROZEN_0110_DIR}/src/probe.ts`]
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
    files: all.filter((f) => !f.startsWith(`${FROZEN_0110_DIR}/`)).sort(),
    inside: all.filter((f) => f.startsWith(`${FROZEN_0110_DIR}/`)).map((f) => f.slice(FROZEN_0110_DIR.length + 1)).sort(),
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

await t('the frozen suite-0.11.0 files are the 317e3421 blobs (checks.json: the 47c13a3e one), byte for byte (git blob id recomputed, nothing stripped or restored first)', () => {
  for (const [path, blob] of Object.entries(FROZEN_0110_BLOBS)) {
    assert.equal(blobId(readRepo(`${FROZEN_0110_DIR}/${path}`)), blob, `${path} is not the 0.11.0 file`)
  }
})

await t('frozen/suite-0.11.0 holds exactly the pinned files, and they are exactly what its probe.ts reaches inside it (nothing unpinned, nothing unreached)', () => {
  const pinned = Object.keys(FROZEN_0110_BLOBS).sort()
  assert.deepStrictEqual(listFiles(FROZEN_0110_DIR), pinned, 'a file in frozen/suite-0.11.0 is not pinned, or a pinned one is missing')
  assert.deepStrictEqual(importClosure0110().inside, pinned, 'the frozen probe.ts no longer reaches exactly the pinned files')
})

await t('the in-repo import closure of frozen/suite-0.11.0 outside it is exactly the pinned list, and every pinned file hashes to its pinned blob (git blob id recomputed)', () => {
  const closure = importClosure0110()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_0110_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_0110_BLOBS)')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_0110_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_0110_BLOBS)) assert.equal(blobId(readRepo(path)), blob, `${path} changed: freeze its 0.11.0 version into frozen/suite-0.11.0 first`)
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

interface Run { result: ProbeResult; requests: string[]; threw: boolean; toolsCallStatus: number | null; substituted: { body: number; header: number } }

/** `live`: the implementation's request sequence for the same input, for the frozen run's offerAsLive (suite 0.13.0); omitted on the implementation's own run. */
async function runOnce(probe: Probe, createHandler: () => (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>, v: Variant, live?: readonly string[]): Promise<Run> {
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
  const recorded = recordToolsCallStatus(fetchImpl)
  const offer = offerAsLive(recorded.fetchImpl, live)
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: offer.fetchImpl,
    budget: v.budget,
    now: () => '2026-09-25T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  return { result, requests, threw, toolsCallStatus: recorded.toolsCallStatus(), substituted: offer.substituted() }
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
// Input set B's errors.
// ---------------------------------------------------------------------------

/** Errors on which the catch gives the rows that never ran their reason: [label, the error as the implementation
 *  receives it, the same error as the frozen 0.11.0 suite receives it]. Both parties handle every one of them the
 *  same way (0.11.0 already knows OtherHostDeclined); the only difference between their results is the remap.
 *  OtherHostDeclined is recognised by class, and each suite has its own class (the frozen copy lives in
 *  frozen/suite-0.11.0/src/other-host-declined.ts), so each is handed an instance of its own. */
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

const rowOf = (r: ProbeResult, id: string) => r.assertions.find((a) => a.check_id === id)!
const isCompletedVerified = (a: { execution_status: string; assertion_status: string }) => a.execution_status === 'COMPLETED' && a.assertion_status === 'VERIFIED'

/** What the remap changed, counted so the test below can say the input set reaches every part of it. */
const seen = {
  runs: 0,
  latencyRewritten: 0,
  authRewritten: 0,
  authVerifiedKept: 0,
  taxonomyRewritten: 0,
  taxonomyVerifiedKept: 0,
  thrown: new Map<string, number>(),
  notReached: 0,
  toolsCallStatuses: new Map<string, number>(),
}

/** The claim itself, read off the implementation's result and the harness's own observation only. */
function honest(id: string, r: Run) {
  const status = r.toolsCallStatus
  const latency = rowOf(r.result, 'latency_profile')
  if (!(latency.execution_status === 'SKIPPED' && latency.assertion_status === 'UNVERIFIED' && latency.reason?.key === 'latency_not_recorded')) {
    violation(id, `latency_profile is not SKIPPED/UNVERIFIED latency_not_recorded: ${JSON.stringify([latency.execution_status, latency.assertion_status, latency.reason])}`)
  }
  const auth = rowOf(r.result, 'auth_metadata')
  // status null: no tools/call was sent — the credential-gate path judges the 401 the handshake or tools/list itself got.
  if (isCompletedVerified(auth) && status !== null && status !== 401) violation(id, `auth_metadata is VERIFIED but the tools/call was answered ${status}, not 401`)
  const taxonomy = rowOf(r.result, 'error_taxonomy')
  if (isCompletedVerified(taxonomy) && (status === null || status === 401 || status === 403)) violation(id, `error_taxonomy is VERIFIED but the tools/call answer was ${status}`)
  // The not-observed reasons are SKIPPED/UNVERIFIED wherever they appear, on any branch.
  for (const a of r.result.assertions) {
    const key = a.reason?.key
    if ((key === 'latency_not_recorded' || key === 'auth_no_challenge_observed' || key === 'error_shape_not_observed') && !(a.execution_status === 'SKIPPED' && a.assertion_status === 'UNVERIFIED')) {
      violation(id, `${a.check_id} carries ${key} but is ${a.execution_status}/${a.assertion_status}, not SKIPPED/UNVERIFIED`)
    }
  }
}

/** Both runs of one input, compared. */
function compare(id: string, now: Run, old: Run, expectedOld: ProbeResult) {
  seen.runs++
  const key = String(old.toolsCallStatus)
  seen.toolsCallStatuses.set(key, (seen.toolsCallStatuses.get(key) ?? 0) + 1)
  if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
  const offerProblem = offerSubstitutionProblem(old.result, old.substituted)
  if (offerProblem) violation(id, offerProblem)
  if (now.toolsCallStatus !== old.toolsCallStatus) violation(id, `the tools/call was answered ${now.toolsCallStatus} for the implementation and ${old.toolsCallStatus} for 0.11.0`)
  if (!identical(withoutAuthObservation(now.result), expectedOld)) {
    violation(id, `ProbeResult is not 0.11.0's with the remap and nothing else\n           new ${JSON.stringify(now.result.assertions.map((a) => [a.check_id, a.execution_status, a.assertion_status, a.reason]))}\n           old ${JSON.stringify(expectedOld.assertions.map((a) => [a.check_id, a.execution_status, a.assertion_status, a.reason]))}`)
  }
  honest(id, now)
  const oldAuth = rowOf(old.result, 'auth_metadata'), newAuth = rowOf(now.result, 'auth_metadata')
  const oldTax = rowOf(old.result, 'error_taxonomy'), newTax = rowOf(now.result, 'error_taxonomy')
  if (rowOf(old.result, 'latency_profile').assertion_status !== rowOf(now.result, 'latency_profile').assertion_status) seen.latencyRewritten++
  if (isCompletedVerified(oldAuth)) {
    if (isCompletedVerified(newAuth)) seen.authVerifiedKept++
    else seen.authRewritten++
  }
  if (isCompletedVerified(oldTax)) {
    if (isCompletedVerified(newTax)) seen.taxonomyVerifiedKept++
    else seen.taxonomyRewritten++
  }
}

let totalA = 0, totalB = 0

for (const fixture of FIXTURE_CORPUS) {
  for (const [label, v] of variants()) {
    totalA++
    const id = `A ${fixture.id} / ${label}`
    try {
      const now = await runOnce(runProbe, fixture.createHandler, v)
      const old = await runOnce(frozen0110RunProbe, fixture.createHandler, v, now.requests)
      compare(id, now, old, suite0130Remap(suite0120Remap(old.result, old.toolsCallStatus), old.requests))
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
      const v: Variant = { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make } }
      const vFrozen: Variant = { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make: makeFrozen } }
      try {
        const now = await runOnce(runProbe, fixture.createHandler, v)
        const old = await runOnce(frozen0110RunProbe, fixture.createHandler, vFrozen, now.requests)
        if (now.threw !== old.threw) violation(id, 'one side reached the throwing request and the other did not')
        if (!now.threw) seen.notReached++
        else seen.thrown.set(label, (seen.thrown.get(label) ?? 0) + 1)
        compare(id, now, old, suite0130Remap(suite0120Remap(old.result, old.toolsCallStatus), old.requests))
      } catch (e) {
        violation(id, `threw ${(e as Error).message}`)
      }
    }
  }
}

console.log(`  A: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants = ${totalA}`)
console.log(`  B: ${FIXTURE_CORPUS.length} fixtures × ${DEFAULT_PROBE_BUDGET.maxRequests} positions × ${ERRORS.length} errors = ${totalB} (request reached: ${totalB - seen.notReached}; not reached: ${seen.notReached})`)
console.log(`  rows rewritten by the remap: latency_profile ${seen.latencyRewritten}; auth_metadata ${seen.authRewritten} (VERIFIED kept on a 401: ${seen.authVerifiedKept}); error_taxonomy ${seen.taxonomyRewritten} (VERIFIED kept: ${seen.taxonomyVerifiedKept})`)
console.log(`  tools/call answer seen by the harness (status: runs): ${[...seen.toolsCallStatuses].sort().map(([k, n]) => `${k}: ${n}`).join(', ')}`)
console.log(`  ${((Date.now() - started) / 1000).toFixed(1)}s`)

await t(`0.12.0 vs frozen 0.11.0: identical to 0.11.0 but for the three rows that recorded VERIFIED without observing anything, and none of them is VERIFIED unobserved: all ${totalA + totalB} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: every error is thrown, and the remap rewrote latency_profile, auth_metadata and error_taxonomy rows while leaving the observed VERIFIED ones alone', () => {
  assert.ok(FIXTURE_CORPUS.length >= 76, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const [label] of ERRORS) assert.ok((seen.thrown.get(label) ?? 0) > 0, `${label} never thrown`)
  assert.ok(seen.notReached > 0)
  assert.ok(seen.latencyRewritten > 0, 'no run had a latency_profile that 0.11.0 recorded differently')
  assert.ok(seen.authRewritten > 0, 'no run had an auth_metadata VERIFIED on a tools/call answer that was not a 401')
  assert.ok(seen.authVerifiedKept > 0, 'no run kept an auth_metadata VERIFIED on a genuine 401 challenge')
  assert.ok(seen.taxonomyRewritten > 0, 'no run had an error_taxonomy VERIFIED on a 401 or 403')
  assert.ok(seen.taxonomyVerifiedKept > 0, 'no run kept an error_taxonomy VERIFIED on a real protocol error')
  for (const status of ['200', '401', 'null']) assert.ok((seen.toolsCallStatuses.get(status) ?? 0) > 0, `no run saw a tools/call answered ${status}`)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
