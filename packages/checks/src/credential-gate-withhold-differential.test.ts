/**
 * T86b differential (suite 0.8.0) — the evidence that withholding the
 * reserved-name tools/call under a credential gate changed nothing on any run
 * that is not behind one, over the TODO 458 input set: the whole fixture
 * corpus crossed with its budget / GuardSignals / baseline / GET-redirect
 * variants (wire-budget-differential.test.ts; its `variants()` and `runOnce`
 * harness are reused below verbatim, marked).
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.7.1 — ./frozen/suite-0.7.1/{probe,protocol,auth,error-taxonomy}.ts,
 *      byte for byte the suite 0.7.1 (2c99377) files apart from a four-line
 *      `// FROZEN:` header and `../../` import paths (the first test
 *      recomputes each git blob id). Everything else it reaches is shared
 *      with the live code and pinned to its 2c99377b blob by
 *      probe-tool-name-differential.test.ts (CLOSURE_071_BLOBS).
 *
 * A run is behind a credential gate when 0.7.1 recorded tools_list as
 * credential_required: both of 0.7.1's gated branches write exactly that, and
 * nothing else does.
 *
 * Invariant, for every input:
 *   - Not gated ⇒ the two ProbeResults are identical (same own keys in the
 *     same order at every level, Object.is on every leaf) and so is the
 *     request sequence the target sees (URL, method, headers, body).
 *   - Gated ⇒ the implementation sends no tools/call; its requests start with
 *     0.7.1's requests up to 0.7.1's tools/call (all of them, if 0.7.1 sent
 *     none), and anything after that is a GET (the gate challenge's metadata
 *     document, and redirects on the way to it); error_taxonomy is SKIPPED /
 *     UNVERIFIED with tools_list's own reason; auth_metadata is COMPLETED, or
 *     SKIPPED with one of our own budget aborts when that GET ran out of
 *     budget; every row written before the decision is identical to 0.7.1's.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { runProbe } from './probe.ts'
import { runProbe as frozen071RunProbe } from './frozen/suite-0.7.1/probe.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { ApprovedBaseline, FetchLike, GuardSignals, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

/** `git rev-parse 2c99377:packages/checks/src/<name>.ts` (suite 0.7.1). */
const FROZEN_071_BLOBS: Record<string, string> = {
  'probe': 'e5eba03ee610e76d9f637207ca2c69809c5f5de2',
  'auth': '926a95cf8753f79c1d7085589f836bcde857b534',
  'protocol': '5f246eb66fa9397bcfc3c0779c5551761fdc56b5',
  'error-taxonomy': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
}

await t('the frozen 0.7.1 files are the 2c99377 blobs: header dropped, import paths restored, git blob id recomputed', () => {
  for (const [name, blob] of Object.entries(FROZEN_071_BLOBS)) {
    const raw = readFileSync(new URL(`./frozen/suite-0.7.1/${name}.ts`, import.meta.url), 'utf8').replace(/\r\n/g, '\n')
    const lines = raw.split('\n')
    let header = 0
    while (lines[header]!.startsWith('// FROZEN:')) header++
    assert.equal(header, 4, `${name}: expected the four-line FROZEN header`)
    const restored = lines.slice(header).map((l) => (l.startsWith('import ') ? l.replace("from '../../", "from './") : l)).join('\n')
    const bytes = Buffer.from(restored, 'utf8')
    const id = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
    assert.equal(id, blob, `${name}.ts is not the 0.7.1 file`)
  }
})

// ---------------------------------------------------------------------------
// Harness — verbatim from wire-budget-differential.test.ts (TODO 458), minus
// the fourth-argument capture that file needs and this one does not.
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
}

interface Run { result: ProbeResult; requests: string[] }

async function runOnce(probe: Probe, createHandler: () => (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>, v: Variant): Promise<Run> {
  const handler = createHandler()
  const requests: string[] = []
  let position = 0
  let redirectsServed = 0
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
    return handler(input, init)
  }
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget: v.budget,
    now: () => '2026-09-23T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  return { result, requests }
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
// The invariant.
// ---------------------------------------------------------------------------

/** Rows runProbe writes before it decides whether to send the tools/call. */
const DECIDED_BEFORE_THE_CALL = [
  'tls_certificate', 'reachability', 'discovery_handshake', 'protocol_revision', 'transport_type', 'latency_profile',
  'tools_list', 'toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene', 'toolset_unchanged_vs_approved', 'schema_unchanged_vs_approved',
]
const methodOf = (request: string) => JSON.parse(request)[0] as string
const rpcMethodOf = (request: string) => {
  const body = JSON.parse(request)[3] as string | null
  try { return body === null ? null : (JSON.parse(body) as { method?: unknown }).method ?? null } catch { return null }
}

let total = 0, violations = 0
const failures: string[] = []
const seen = { notGated: 0, gated: 0, gatedToolsCallBy071: 0, gatedWithMetadataGet: 0, gatedAuthAborted: 0, gatedFixtures: new Set<string>(), status403Fixtures: new Set<string>() }
const started = Date.now()

function violation(id: string, what: string) {
  violations++
  if (failures.length < 200) failures.push(`${id}: ${what}`)
}

for (const fixture of FIXTURE_CORPUS) {
  for (const [label, v] of variants()) {
    total++
    const id = `${fixture.id} / ${label}`
    let now: Run, old: Run
    try {
      now = await runOnce(runProbe, fixture.createHandler, v)
      old = await runOnce(frozen071RunProbe, fixture.createHandler, v)
    } catch (e) {
      violation(id, `threw ${(e as Error).message}`)
      continue
    }
    const row = (r: ProbeResult, checkId: string) => r.assertions.find((a) => a.check_id === checkId)!
    if (row(old.result, 'tools_list').reason?.key !== 'credential_required') {
      seen.notGated++
      if (!identical(now.result, old.result)) violation(id, `not gated: ProbeResult differs\n           new ${JSON.stringify(now.result).slice(0, 400)}\n           old ${JSON.stringify(old.result).slice(0, 400)}`)
      if (!identical(now.requests, old.requests)) violation(id, `not gated: request sequence differs\n           new ${now.requests.join(' | ')}\n           old ${old.requests.join(' | ')}`)
      continue
    }
    seen.gated++
    seen.gatedFixtures.add(fixture.id)
    const cut = old.requests.findIndex((r) => rpcMethodOf(r) === 'tools/call')
    if (cut >= 0) seen.gatedToolsCallBy071++
    const before = cut < 0 ? old.requests : old.requests.slice(0, cut)
    if (now.requests.some((r) => rpcMethodOf(r) === 'tools/call')) violation(id, 'gated: tools/call sent')
    if (!identical(now.requests.slice(0, before.length), before)) violation(id, `gated: requests before the call differ\n           new ${now.requests.join(' | ')}\n           old ${old.requests.join(' | ')}`)
    const rest = now.requests.slice(before.length)
    if (!rest.every((r) => methodOf(r) === 'GET')) violation(id, `gated: a non-GET request after the decision: ${rest.join(' | ')}`)
    if (rest.length > 0) seen.gatedWithMetadataGet++
    const et = row(now.result, 'error_taxonomy'), tl = row(now.result, 'tools_list')
    if (et.execution_status !== 'SKIPPED' || et.assertion_status !== 'UNVERIFIED' || !identical(et.reason, tl.reason) || !identical(et.unverified_reason, tl.reason)) {
      violation(id, `gated: error_taxonomy = ${et.execution_status}/${et.assertion_status} ${JSON.stringify(et.reason)}`)
    }
    const auth = row(now.result, 'auth_metadata')
    const aborted = auth.execution_status === 'SKIPPED' && (auth.reason?.key ?? '').startsWith('probe_')
    if (aborted) seen.gatedAuthAborted++
    if (auth.execution_status !== 'COMPLETED' && !aborted) violation(id, `gated: auth_metadata = ${auth.execution_status}/${auth.assertion_status} ${JSON.stringify(auth.reason)}`)
    for (const checkId of DECIDED_BEFORE_THE_CALL) {
      if (!identical(row(now.result, checkId), row(old.result, checkId))) violation(id, `gated: ${checkId} differs from 0.7.1`)
    }
  }
  if ((await runOnce(runProbe, fixture.createHandler, { budget: DEFAULT_PROBE_BUDGET })).result.assertions.some((a) => a.reason?.params?.status === 403)) seen.status403Fixtures.add(fixture.id)
}

console.log(`  inputs: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants = ${total}; ${((Date.now() - started) / 1000).toFixed(1)}s`)
console.log(`  not gated (identical to 0.7.1): ${seen.notGated}; gated: ${seen.gated} across ${seen.gatedFixtures.size} fixtures (0.7.1 sent tools/call on ${seen.gatedToolsCallBy071}; metadata GET after the decision on ${seen.gatedWithMetadataGet}; auth_metadata cut by a budget abort on ${seen.gatedAuthAborted})`)
console.log(`  fixtures whose run records an HTTP 403 in a reason (identical to 0.7.1 unless gated): ${[...seen.status403Fixtures].sort().join(', ')}`)

await t(`not behind a credential gate, 0.8.0 is indistinguishable from 0.7.1; behind one, it never sends the tools/call: all ${total} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: gated and non-gated runs, gated runs where 0.7.1 sent the call, metadata GETs after the decision, budget aborts during that GET, and 403s all occur', () => {
  assert.ok(FIXTURE_CORPUS.length >= 74, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const [what, n] of Object.entries(seen)) assert.ok((typeof n === 'number' ? n : n.size) > 0, `${what} never seen`)
  assert.ok(seen.status403Fixtures.has('forbidden-403-not-credential-gated'))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
