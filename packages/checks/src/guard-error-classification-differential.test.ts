/**
 * T85 differential (suite 0.9.0) — the evidence that classifying ssrf-guard's
 * errors by class / code changed nothing but the reason those errors get.
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.8.0 — ./frozen/suite-0.8.0/probe.ts, byte for byte the suite
 *      0.8.0 (b439bc6; unchanged since f923e35) probe.ts apart from a
 *      four-line `// FROZEN:` header and `../../` import paths (the first test
 *      recomputes its git blob id). probe.ts is the only file T85 changes that
 *      the orchestrator runs; everything else it reaches is shared with the
 *      live code and pinned below (CLOSURE_080_BLOBS), the same way
 *      probe-tool-name-differential.test.ts pins the 0.7.1 oracle.
 *
 * Inputs:
 *   A. The TODO 458 / T86b input set: the whole fixture corpus crossed with
 *      its budget / GuardSignals / baseline / GET-redirect variants. No
 *      fetchImpl here throws anything but wire.ts's own ProbeAborted, so no
 *      run reaches the new branch.
 *   B. The corpus again, with request number p (p = 1 … maxRequests)
 *      throwing one error instead of answering: each ssrf-guard error the
 *      catch now classifies, and three of our own wrapper errors.
 *
 * Invariant:
 *   - A, and B for our own wrapper errors (or when the run never reaches
 *     request p): the two ProbeResults are identical (same own keys in the
 *     same order at every level, Object.is on every leaf) and so is the
 *     request sequence.
 *   - B for an ssrf-guard error: the request sequences are identical, and the
 *     implementation's ProbeResult is 0.8.0's with exactly this remap and
 *     nothing else — every row 0.8.0 gave `probe_aborted { message }` (the
 *     reachability row the catch wrote) or `probe_cascade_incomplete` (the
 *     rows that never ran) carries the classified reason instead, in both
 *     `reason` and `unverified_reason`. The classified reason depends on
 *     whether reachability was already settled when the error landed: once it
 *     is, a DNS failure or an unanswered request keeps 0.8.0's
 *     probe_cascade_incomplete (no remap at all), and a guard timeout becomes
 *     probe_budget_exhausted_duration { maxDurationMs }. Each guard error
 *     carries the `hop` guardedFetch gives it; the endpoint-naming keys
 *     (dns_failed, unanswered timeout) are expected at hop 0 only.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { posix } from 'node:path'
import ts from 'typescript'
import { DEFAULT_PROBE_BUDGET, BudgetExceeded, RateLimited, SsrfBlocked, UpstreamFetchFailed } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { runProbe as frozen080RunProbe } from './frozen/suite-0.8.0/probe.ts'
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

/** `git rev-parse b439bc6:packages/checks/src/probe.ts` (suite 0.8.0; the same blob at f923e35). */
const FROZEN_080_PROBE_BLOB = '9264f8730e0582158f80fb0a6a019e596e691cee'

/** The in-repo import closure of frozen/suite-0.8.0/probe.ts (importClosure below;
 *  imports read off the TypeScript AST), each file pinned to the output of
 *    git rev-parse b439bc6:<path>
 *  except the six marked "T85", which T85 PR-1 itself changes and which are
 *  pinned to its blob instead (the `git rev-parse <commit>:<path>` in each
 *  comment; the blob is the same at the PR-1 head). Re-pin reason: RESOLVER_UNAVAILABLE
 *  code change / upstream-failure class (ssrf-guard), and the reachability
 *  cannot_en/zh + docs_version (checks.json); round 2 adds the `hop` field
 *  and queryOne's DoH body read (ssrf-guard; round 4: resolveHost's A/AAAA precedence; T85 PR-1b: the DoH request timeout, R16, resolve.ts pinned to the PR-1b commit; TODO 591: the post-fetch re-check rethrows RESOLVER_UNAVAILABLE, R20, guarded-fetch.ts pinned to that commit) and registry_version 0.5.0
 *  (checks.json). None of it can change what the
 *  frozen file computes: it reaches ssrf-guard and checks.json only through
 *  type-only imports (types.ts, registry.ts), erased at run time, and every
 *  run below passes the registry in as input to both sides. If this test goes
 *  red for any other file, freeze its 0.8.0 version into frozen/suite-0.8.0
 *  first. */
const CLOSURE_080_BLOBS: Record<string, string> = {
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
  'packages/checks/checks.json': '522fb7042323bc2bd98bf7c8720962e5ca7a198e', // T85 round 2 (registry_version 0.5.0) — git rev-parse 962fdc6:packages/checks/checks.json
  'packages/checks/src/auth.ts': 'f8b78f074b997b38e39319d97ec93807f73a0c65',
  'packages/checks/src/error-taxonomy.ts': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
  'packages/checks/src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'packages/checks/src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'packages/checks/src/protocol.ts': 'e66f8fdddbd0e945bd30487e1b23a3d17aa56745',
  'packages/checks/src/registry.ts': 'bcce9c9f3a032195548726da1c83985ae3e0b1f9',
  'packages/checks/src/types.ts': '59d38f860a3cd07989421fc2e6b97b60cabedd10',
  'packages/checks/src/wire.ts': 'c0ab8b30a92e22457c20acb21bc166b6c1336e56',
  'packages/ssrf-guard/src/audit.ts': 'c2f08ab05e4bdb6425c5feba789d19e0c7293073',
  'packages/ssrf-guard/src/budget.ts': 'c920ff71d6e0477fd22ef79c0077973227cbb74f',
  'packages/ssrf-guard/src/dns-wire.ts': '04357f1c08ee2d649a382d2640580903323af222',
  'packages/ssrf-guard/src/errors.ts': '958b4f9b63d9a5901b2097a2d564ef2afff79e57', // T85 round 2 (hop field) — git rev-parse 962fdc6:packages/ssrf-guard/src/errors.ts
  'packages/ssrf-guard/src/guarded-fetch.ts': '3c96a62e1a4e1f3378ff4a31766f597d59852438', // TODO 591 (re-check RESOLVER_UNAVAILABLE rethrown, R20) — git rev-parse "$(git log -n1 --format=%h -G'discardBody' -- packages/ssrf-guard/src/guarded-fetch.ts)":packages/ssrf-guard/src/guarded-fetch.ts
  'packages/ssrf-guard/src/index.ts': '9d301879dc35ac0a85a2cd5005d70f2e75406755', // T85: git rev-parse 3696518:packages/ssrf-guard/src/index.ts
  'packages/ssrf-guard/src/ip-policy.ts': 'b581241df1a369ee55e780b1450d1997ab2635db',
  'packages/ssrf-guard/src/rate-limit.ts': '20f0e9e542de6708411456c0a46d7fdad77e0773',
  'packages/ssrf-guard/src/resolve.ts': '8ba7ae7c4a97c0589fbb8da1166de89f36bdb5d0', // T85 PR-1b (DoH timeout, R16) — git rev-parse "$(git log -n1 --format=%h -G'DOH_TIMEOUT_MS' -- packages/ssrf-guard/src/resolve.ts)":packages/ssrf-guard/src/resolve.ts
  'packages/ssrf-guard/src/response-view.ts': 'b1b0e3e040f6d6acf66700758323b6bfae223d96', // T85: git rev-parse 3696518:packages/ssrf-guard/src/response-view.ts
  'packages/ssrf-guard/src/url-target.ts': '46678f430c6534806c014b0265dc408c8fe29705',
}
const CLOSURE_080_THIRD_PARTY: string[] = []

const REPO_ROOT = new URL('../../../', import.meta.url)
const FROZEN_080_DIR = 'packages/checks/src/frozen/suite-0.8.0'
const readRepo = (path: string) => readFileSync(new URL(path, REPO_ROOT), 'utf8')
const blobId = (text: string) => {
  const bytes = Buffer.from(text.split('\r\n').join('\n'), 'utf8')
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}

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

/** importClosure071 from probe-tool-name-differential.test.ts, verbatim but for the entry point. */
function importClosure080(): { files: string[]; thirdParty: string[] } {
  const packagesByName = new Map<string, string>()
  for (const dir of readdirSync(new URL('packages/', REPO_ROOT))) {
    const pj = new URL(`packages/${dir}/package.json`, REPO_ROOT)
    if (existsSync(pj)) packagesByName.set((JSON.parse(readFileSync(pj, 'utf8')) as { name: string }).name, `packages/${dir}`)
  }
  const seen = new Set<string>(), thirdParty = new Set<string>()
  const queue = [`${FROZEN_080_DIR}/probe.ts`]
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
  return { files: [...seen].filter((f) => !f.startsWith(`${FROZEN_080_DIR}/`)).sort(), thirdParty: [...thirdParty].sort() }
}

await t('the frozen suite-0.8.0 probe.ts is the b439bc6 blob: header dropped, import paths restored, git blob id recomputed', () => {
  const lines = readRepo(`${FROZEN_080_DIR}/probe.ts`).replace(/\r\n/g, '\n').split('\n')
  let header = 0
  while (lines[header]!.startsWith('// FROZEN:')) header++
  assert.equal(header, 4, 'expected the four-line FROZEN header')
  const restored = lines.slice(header).map((l) => (l.startsWith('import ') ? l.replace("from '../../", "from './") : l)).join('\n')
  assert.equal(blobId(restored), FROZEN_080_PROBE_BLOB)
})

await t('the in-repo import closure of frozen/suite-0.8.0 is exactly the pinned list, and every pinned file hashes to its pinned blob (git blob id recomputed)', () => {
  const closure = importClosure080()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_080_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_080_BLOBS)')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_080_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_080_BLOBS)) assert.equal(blobId(readRepo(path)), blob, `${path} changed: freeze its 0.8.0 version into frozen/suite-0.8.0 first`)
})

// ---------------------------------------------------------------------------
// Harness — verbatim from credential-gate-withhold-differential.test.ts (T86b),
// plus `throwAt` (input set B).
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
  /** T85: request number `position` throws `make()` instead of answering. */
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

type Reason = { key: string; params?: Record<string, string | number> }
const B = DEFAULT_PROBE_BUDGET
/** What guardedFetch hands on: the error with the `hop` it failed at (0 = the URL it was given). */
const atHop = <E extends object>(hop: number, e: E): E => Object.assign(e, { hop })
const OTHER: Reason = { key: 'reachability_unanswered', params: { kind: 'other' } }
const INCOMPLETE: Reason = { key: 'probe_cascade_incomplete' }
/** [label, error, the reason while reachability is unsettled, the reason once it is settled — or null, null for our own errors, which must be unchanged]. */
const ERRORS: [string, () => unknown, Reason | null, Reason | null][] = [
  ['guard MAX_DURATION', () => atHop(0, new BudgetExceeded('MAX_DURATION', 'probe exceeded its 10000ms wall-clock budget')), { key: 'reachability_unanswered', params: { kind: 'timeout' } }, { key: 'probe_budget_exhausted_duration', params: { maxDurationMs: B.maxDurationMs } }],
  ['guard MAX_DURATION @ hop 1', () => atHop(1, new BudgetExceeded('MAX_DURATION', 'probe exceeded its 10000ms wall-clock budget')), OTHER, { key: 'probe_budget_exhausted_duration', params: { maxDurationMs: B.maxDurationMs } }],
  ['UpstreamFetchFailed', () => atHop(0, new UpstreamFetchFailed(new TypeError('Network connection lost.'))), OTHER, INCOMPLETE],
  ['RESOLUTION_FAILED', () => atHop(0, new SsrfBlocked('RESOLUTION_FAILED', 'DNS resolution failed with RCODE 3')), { key: 'reachability_dns_failed' }, INCOMPLETE],
  ['RESOLUTION_FAILED @ hop 1', () => atHop(1, new SsrfBlocked('RESOLUTION_FAILED', 'DNS resolution failed with RCODE 3')), OTHER, INCOMPLETE],
  ['RESOLVER_UNAVAILABLE', () => atHop(0, new SsrfBlocked('RESOLVER_UNAVAILABLE', 'DoH resolver returned HTTP 503')), { key: 'probe_resolver_unavailable' }, { key: 'probe_resolver_unavailable' }],
  ['PRIVATE_USE', () => atHop(0, new SsrfBlocked('PRIVATE_USE', '10.0.0.1 is private-use')), { key: 'probe_blocked_by_policy', params: { code: 'PRIVATE_USE' } }, { key: 'probe_blocked_by_policy', params: { code: 'PRIVATE_USE' } }],
  ['CLOUD_METADATA', () => atHop(0, new SsrfBlocked('CLOUD_METADATA', '169.254.169.254 is a cloud instance metadata address')), { key: 'probe_blocked_by_policy', params: { code: 'CLOUD_METADATA' } }, { key: 'probe_blocked_by_policy', params: { code: 'CLOUD_METADATA' } }],
  ['guard RateLimited', () => atHop(0, new RateLimited('RATE_LIMITED', 'no rate-limit decision')), { key: 'probe_rate_limited' }, { key: 'probe_rate_limited' }],
  ['guard MAX_REQUESTS', () => atHop(0, new BudgetExceeded('MAX_REQUESTS', 'x')), { key: 'probe_budget_exhausted_requests', params: { maxRequests: B.maxRequests } }, { key: 'probe_budget_exhausted_requests', params: { maxRequests: B.maxRequests } }],
  ['guard MAX_REDIRECTS', () => atHop(0, new BudgetExceeded('MAX_REDIRECTS', 'x')), { key: 'probe_budget_exhausted_redirects', params: { maxRedirects: B.maxRedirects } }, { key: 'probe_budget_exhausted_redirects', params: { maxRedirects: B.maxRedirects } }],
  ['guard MAX_BODY_BYTES', () => atHop(0, new BudgetExceeded('MAX_BODY_BYTES', 'x')), { key: 'probe_budget_exhausted_body', params: { maxBodyBytes: B.maxBodyBytes } }, { key: 'probe_budget_exhausted_body', params: { maxBodyBytes: B.maxBodyBytes } }],
  ['own Error (trial host restriction)', () => new Error('trial probe declined to fetch "x.example.com"'), null, null],
  ['own TypeError (adapter body type)', () => new TypeError('guarded-fetch-adapter: unsupported request body type'), null, null],
  ['own RangeError (adapter timeoutMs)', () => new RangeError('guarded-fetch-adapter: timeoutMs must be a positive number of milliseconds, got 0'), null, null],
]

/** 0.8.0's result with the one intended change: the rows its catch wrote as
 *  probe_aborted / probe_cascade_incomplete carry `reason` instead. */
function remapped(old: ProbeResult, reason: Reason): ProbeResult {
  const out = structuredClone(old)
  for (const a of out.assertions) {
    if (a.reason?.key === 'probe_aborted' || a.reason?.key === 'probe_cascade_incomplete') {
      a.reason = structuredClone(reason)
      a.unverified_reason = structuredClone(reason)
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

let totalA = 0
for (const fixture of FIXTURE_CORPUS) {
  for (const [label, v] of variants()) {
    totalA++
    const id = `A ${fixture.id} / ${label}`
    try {
      const now = await runOnce(runProbe, fixture.createHandler, v)
      const old = await runOnce(frozen080RunProbe, fixture.createHandler, v)
      if (!identical(now.result, old.result)) violation(id, `ProbeResult differs\n           new ${JSON.stringify(now.result).slice(0, 400)}\n           old ${JSON.stringify(old.result).slice(0, 400)}`)
      if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
    } catch (e) {
      violation(id, `threw ${(e as Error).message}`)
    }
  }
}

let totalB = 0
const seen = { thrown: new Map<string, number>(), notReached: 0, remappedRows: 0, reachabilityByCatch: new Map<string, number>(), afterHandshake: new Map<string, number>() }
for (const fixture of FIXTURE_CORPUS) {
  for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
    for (const [label, make, unsettledReason, settledReason] of ERRORS) {
      totalB++
      const id = `B ${fixture.id} / ${label} @ request ${position}`
      const v: Variant = { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make } }
      try {
        const now = await runOnce(runProbe, fixture.createHandler, v)
        const old = await runOnce(frozen080RunProbe, fixture.createHandler, v)
        if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
        if (now.threw !== old.threw) violation(id, 'one side reached the throwing request and the other did not')
        if (!now.threw) { seen.notReached++ }
        else seen.thrown.set(label, (seen.thrown.get(label) ?? 0) + 1)
        // Settled when the error landed = 0.8.0 did not write reachability from its catch.
        const settled = old.result.assertions.find((a) => a.check_id === 'reachability')!.execution_status !== 'ERROR'
        const reason = settled ? settledReason : unsettledReason
        const expected = now.threw && reason !== null ? remapped(old.result, reason) : old.result
        if (!identical(now.result, expected)) violation(id, `ProbeResult is not 0.8.0's ${reason === null || !now.threw ? 'unchanged' : 'with the one remap'}\n           new ${JSON.stringify(now.result.assertions.map((a) => [a.check_id, a.reason]))}\n           old ${JSON.stringify(old.result.assertions.map((a) => [a.check_id, a.reason]))}`)
        if (now.threw && reason !== null) {
          seen.remappedRows += now.result.assertions.filter((a) => identical(a.reason, reason)).length
          const reach = now.result.assertions.find((a) => a.check_id === 'reachability')!
          const bucket = reach.execution_status === 'ERROR' ? seen.reachabilityByCatch : seen.afterHandshake
          bucket.set(label, (bucket.get(label) ?? 0) + 1)
          if (now.result.assertions.some((a) => a.reason?.key === 'probe_aborted')) violation(id, 'a guard error still produced probe_aborted')
          if (reason.key !== 'probe_cascade_incomplete' && now.result.assertions.some((a) => a.reason?.key === 'probe_cascade_incomplete')) violation(id, 'a guard error still produced probe_cascade_incomplete')
          if (settled && now.result.assertions.some((a) => a.reason?.key === 'reachability_dns_failed' || a.reason?.key === 'reachability_unanswered')) violation(id, 'a never-ran row says the endpoint did not answer, after it had')
        }
      } catch (e) {
        violation(id, `threw ${(e as Error).message}`)
      }
    }
  }
}

console.log(`  A: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants = ${totalA}`)
console.log(`  B: ${FIXTURE_CORPUS.length} fixtures × ${DEFAULT_PROBE_BUDGET.maxRequests} positions × ${ERRORS.length} errors = ${totalB} (request reached: ${totalB - seen.notReached}; not reached: ${seen.notReached}); rows remapped: ${seen.remappedRows}; ${((Date.now() - started) / 1000).toFixed(1)}s`)
for (const [label] of ERRORS) console.log(`    ${label}: thrown ${seen.thrown.get(label) ?? 0}; reachability written by the catch ${seen.reachabilityByCatch.get(label) ?? '-'}; after the handshake ${seen.afterHandshake.get(label) ?? '-'}`)

await t(`0.9.0 vs frozen 0.8.0: identical off the catch path, and on it differs only by the classified reason: all ${totalA + totalB} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: every error is thrown, and every guard error lands both before the handshake (reachability by the catch) and after it', () => {
  assert.ok(FIXTURE_CORPUS.length >= 74, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const [label, , reason] of ERRORS) {
    assert.ok((seen.thrown.get(label) ?? 0) > 0, `${label} never thrown`)
    if (reason === null) continue
    assert.ok((seen.reachabilityByCatch.get(label) ?? 0) > 0, `${label} never before the handshake`)
    assert.ok((seen.afterHandshake.get(label) ?? 0) > 0, `${label} never after the handshake`)
  }
  assert.ok(seen.notReached > 0)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
