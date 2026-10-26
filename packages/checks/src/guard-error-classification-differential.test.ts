/**
 * T85 differential (suite 0.9.0) — the evidence that classifying ssrf-guard's
 * errors by class / code changed nothing but the reason those errors get.
 *
 * Two parties, both the real orchestrator:
 *
 *   1. The implementation: runProbe (./probe.ts).
 *   2. FROZEN 0.8.0 — ./frozen/suite-0.8.0/{probe,auth,error-taxonomy}.ts, byte
 *      for byte the suite 0.8.0 (b439bc6; unchanged since f923e35) files apart
 *      from a four-line `// FROZEN:` header and `../../` import paths (the first
 *      test recomputes their git blob ids). probe.ts is the only file T85
 *      changes that the orchestrator runs; auth.ts and error-taxonomy.ts were
 *      shared with the live code until suite 0.12.0 changed their verdicts and
 *      were frozen here then (see below). Everything else the frozen files
 *      reach is shared with the live code and pinned below
 *      (CLOSURE_080_BLOBS), the same way probe-tool-name-differential.test.ts
 *      pins the 0.7.1 oracle.
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
 *     request sequence — after the suite 0.12.0 remap that every comparison
 *     in this file applies to 0.8.0's result (suite-0120-remap.ts: the three
 *     checks that stopped recording VERIFIED for what they did not observe).
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
 *
 * Suite 0.13.0 (TODO 217) changes the live protocol.ts's legacy initialize offer
 * (2025-06-18 -> 2025-11-25) and records the offer. protocol.ts is frozen here
 * then (below), so the frozen 0.8.0 run keeps offering 2025-06-18; each input
 * runs the implementation first and 0.8.0 through suite-0130-remap.ts's
 * offerAsLive (the target is handed the implementation's request wherever
 * 0.8.0's differs only by the old offer), 0.8.0's result is remapped by
 * suite0130Remap after suite0120Remap (probeOfferedRevision inserted, nothing
 * else), and a replaced header is allowed only on a run whose server declared
 * no version. The offer change itself is proved against frozen 0.12.0 by
 * suite-0130-differential.test.ts.
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
import { recordToolsCallStatus, suite0120Remap } from './suite-0120-remap.ts'
import { offerAsLive, offerSubstitutionProblem, suite0130Remap } from './suite-0130-remap.ts'
// Suite 0.14.0: the live result's authObservation is set aside before every comparison with the frozen result
// (suite-0140-remap.ts); suite-0140-differential.test.ts proves that key against frozen 0.13.0.
import { withoutAuthObservation } from './suite-0140-remap.ts'
import { pagedToolsList } from './suite-0150-remap.ts'
import { recordSuite0160, suite0160Remap } from './suite-0160-remap.ts'
import type { Suite0160Observed } from './suite-0160-remap.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { ApprovedBaseline, FetchLike, GuardSignals, ProbeResult } from './types.ts'
import { RUNS_ONCE_ONLY, HAS_FULL_SET, IS_MERGE, keepThisShard, writeShardOut, readShardIns, mergeCountMaps, SHARD_COUNT, SHARD_INDEX } from './differential-shard.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// The frozen copy is what it says it is, and so is everything it reaches.
// ---------------------------------------------------------------------------

/** `git rev-parse b439bc6:packages/checks/src/<name>.ts` (suite 0.8.0; the same blobs at f923e35).
 *  auth.ts and error-taxonomy.ts are the same blobs they were in the live tree until suite 0.12.0
 *  (git rev-parse HEAD~:… at that change), which changed what judgeAuthChallenge and judgeErrorTaxonomy
 *  say about an answer that proves nothing; they were frozen here then, with probe.ts's two imports
 *  pointed at them, so the frozen run stays the 0.8.0 behaviour. protocol.ts is the T96 blob both parties ran
 *  from suite 0.10.0 until suite 0.13.0, frozen here then (see CLOSURE_080_BLOBS). */
const FROZEN_080_BLOBS: Record<string, string> = {
  'protocol': '2d39fd28a93a21000b6cc008336971bd1080d030',
  'probe': '9264f8730e0582158f80fb0a6a019e596e691cee',
  'auth': 'f8b78f074b997b38e39319d97ec93807f73a0c65',
  'error-taxonomy': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
}

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
 *  first.
 *
 *  T96 (suite 0.10.0) re-pins protocol.ts to its T96 blob, and unlike the
 *  re-pins above that one DOES change what the frozen file computes (which
 *  2xx discover answers fall back to initialize). It stays a differential of
 *  probe.ts alone: both parties import the same live protocol.ts at run time
 *  (./probe.ts, and frozen/suite-0.8.0/probe.ts through ../../protocol.ts),
 *  so the change reaches both sides identically. Freezing protocol.ts here
 *  would have meant editing the frozen probe.ts's imports. T96's own change
 *  is carried by discover-fallback-differential.test.ts (live vs frozen 0.9.0).
 *
 *  Suite 0.11.0 re-pins three files to their 0.11.0 blob (git hash-object
 *  <path> at that change): checks.json (registry_version 0.9.0, nothing
 *  else), wire.ts (a GET redirect hop to another
 *  host drops authorization / proxy-authorization / cookie) and ssrf-guard's
 *  guarded-fetch.ts (the followRedirects option, default unchanged). None
 *  changes what this differential computes: checks.json is reached type-only;
 *  both parties run the same live wire.ts, and the only GET either sends —
 *  auth.ts's metadata fetch, including the GET-redirect variants of input set
 *  A — carries no headers, so no hop has anything to drop; no run here calls
 *  guardedFetch, and the trial host restriction this file's input set B
 *  imitates with a plain Error now throws OtherHostDeclined in production,
 *  which is carried by declined-host-differential.test.ts (live vs frozen
 *  0.10.0).
 *
 *  Suite 0.12.0 re-pins two files again, and freezes the two it would otherwise have changed under the
 *  frozen probe.ts (FROZEN_080_BLOBS above): checks.json (registry 0.11.0: latency_profile's, auth_metadata's
 *  and error_taxonomy's docs_version and copy; reached type-only, passed in as input to both sides) and auth.ts.
 *  auth.ts stays in this closure because the live protocol.ts imports its classifyCredentialChallenge, which
 *  suite 0.12.0 did not touch; the function that changed (judgeAuthChallenge) is reached by nothing here, since
 *  the frozen probe.ts uses the frozen auth.ts. error-taxonomy.ts leaves the closure: only probe.ts imported it.
 *
 *  Suite 0.13.0 freezes protocol.ts here, as the blob both parties ran from T96 (suite 0.10.0) until then
 *  (2d39fd2…, the T96 re-pin above), with probe.ts's, auth.ts's and error-taxonomy.ts's imports of it pointed at
 *  ./protocol.ts and its own import of auth.ts at the frozen auth.ts (f8b78f0…; the one thing it imports from it,
 *  classifyCredentialChallenge, and everything it calls, are byte-identical in the 0.12.0 auth.ts it ran with
 *  until then — the f8b78f0 -> 0f32e7b diff is one hunk, in judgeAuthChallenge): 0.13.0 changes the live file's
 *  legacy offer, which the frozen run must not pick up. Live protocol.ts and auth.ts leave this closure. It re-pins two files to their 0.13.0 blob (git hash-object <path> at that
 *  change): checks.json (registry 0.12.0: registry_version, nothing else) and types.ts (ProbeResult gains the
 *  optional probeOfferedRevision, and its doc), both reached type-only — the frozen files, and the shared
 *  wire.ts and fingerprint.ts, import types.ts with `import type`, erased at run time — so neither can alter
 *  what this differential computes.
 *
 *  Suite 0.14.0 (auth-gated signing) re-pins the same two files to their 0.14.0 blob (git hash-object <path>):
 *  checks.json (registry 0.13.0: registry_version, nothing else) and types.ts (ProbeResult gains the optional
 *  authObservation, and its doc). Same type-only reach, so neither can alter what this differential computes.
 *  The live auth.ts and the new auth-observation.ts are not in this closure. The live result's new
 *  authObservation key is set aside before each comparison (suite-0140-remap.ts); suite-0140-differential.test.ts
 *  proves it against frozen 0.13.0.
 *
 *  Registry 0.10.0 re-pins checks.json alone (git hash-object at that change):
 *  redirect_policy's how_en/how_zh copy and its docs_version v0.2.0, nothing
 *  else; same type-only reach, so it cannot alter what this differential
 *  computes.
 *
 *  The special-purpose address change re-pins two ssrf-guard files to their
 *  blob at that change (git hash-object <path>): ip-policy.ts (the IANA
 *  special-purpose address tables) and url-target.ts (host name rules, before
 *  any lookup). Neither can alter what this differential computes: the files
 *  in this closure reach ssrf-guard only for its error classes and the
 *  ProbeBudget type, and nothing they run calls guardedFetch, classifyIp or
 *  parseGuardedTarget.
 *
 *  Suite 0.15.0 re-pins three files to their 0.15.0 blob (git hash-object <path>): checks.json (registry 0.14.0:
 *  the new budget.max_tools_list_pages, copy and docs_version of ten checks), registry.ts (the type of that field)
 *  and wire.ts (a GET hop's Location is read, and a cross-host one recorded, before the hop budget is checked).
 *  checks.json and registry.ts are reached type-only and every run passes the registry in as input. The frozen
 *  probe.ts reads redirectCrossHostObserved only on a run that finishes, and the hop over budget always ends
 *  the run (ProbeAborted MAX_REDIRECTS, as before, also for a Location that does not parse), so the new order
 *  cannot alter what the frozen files compute. The suite 0.15.0 changes themselves are carried by the remap
 *  (suite-0150-remap.ts) and proved against frozen 0.14.0 by suite-0150-differential.test.ts.
 *
 *  Suite 0.16.0 (latency_profile measured) re-pins three files to their 0.16.0 blob (git hash-object <path>) and
 *  adds one: checks.json (registry 0.15.0: copy and docs_version v0.3.0 of latency_profile), types.ts
 *  (GuardSignals gains the optional responseHeadersMs, and its doc), wire.ts (sendRequest keeps the time a
 *  FetchLike reports for a POST in the new ProbeContext.latency) and the new latency.ts it imports
 *  (isLatencySampleMs, a pure test of that number, and the LatencyObservations type). The frozen files never read
 *  ProbeContext.latency or a responseHeadersMs; wire.ts keeping it sends no request, throws nothing and changes no
 *  field they read (requestCount, redirectCrossHostObserved, dnsAnswerChangedObserved), and checks.json is
 *  reached type-only with the registry passed in as input. So none of the four can alter what the frozen files
 *  compute. The suite 0.16.0 change itself is carried by the remap (suite-0160-remap.ts) and proved against
 *  frozen 0.15.0 by suite-0160-differential.test.ts. */
const CLOSURE_080_BLOBS: Record<string, string> = {
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
  'packages/checks/checks.json': 'a7d40b5bf344ca1cf7610519b392bff484583aa7', // registry 0.15.0 (suite 0.16.0, see above) — git hash-object packages/checks/checks.json
  'packages/checks/src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'packages/checks/src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'packages/checks/src/latency.ts': '64947a43c414ded3590e599a7f08569391da6bef', // suite 0.16.0, reached from wire.ts (see above) — git hash-object packages/checks/src/latency.ts
  'packages/checks/src/registry.ts': '6f610be98235985b0a27d4cfac5ba805b6a3f51b', // suite 0.15.0 (type-only; see above) — git hash-object packages/checks/src/registry.ts
  'packages/checks/src/types.ts': 'e5cb68a8775242ea17d8c1520076f54beaf2a393', // suite 0.16.0 (type-only; see above) — git hash-object packages/checks/src/types.ts
  'packages/checks/src/wire.ts': '4eaaee5217f9acc55457191b123bc27127a83505', // suite 0.16.0 (see above) — git hash-object packages/checks/src/wire.ts
  'packages/ssrf-guard/src/audit.ts': 'c2f08ab05e4bdb6425c5feba789d19e0c7293073',
  'packages/ssrf-guard/src/budget.ts': 'c920ff71d6e0477fd22ef79c0077973227cbb74f',
  'packages/ssrf-guard/src/dns-wire.ts': '04357f1c08ee2d649a382d2640580903323af222',
  'packages/ssrf-guard/src/errors.ts': '958b4f9b63d9a5901b2097a2d564ef2afff79e57', // T85 round 2 (hop field) — git rev-parse 962fdc6:packages/ssrf-guard/src/errors.ts
  'packages/ssrf-guard/src/guarded-fetch.ts': 'eda760ca7ffb210feb2a685ca0dd43d34a9ab86a', // suite 0.11.0 (followRedirects; see above) — git hash-object packages/ssrf-guard/src/guarded-fetch.ts
  'packages/ssrf-guard/src/index.ts': '9d301879dc35ac0a85a2cd5005d70f2e75406755', // T85: git rev-parse 3696518:packages/ssrf-guard/src/index.ts
  'packages/ssrf-guard/src/ip-policy.ts': 'c40a0ef0a1af6ea5721edebcdd3e0660831b411e', // special-purpose address change (see above) — git hash-object packages/ssrf-guard/src/ip-policy.ts
  'packages/ssrf-guard/src/rate-limit.ts': '20f0e9e542de6708411456c0a46d7fdad77e0773',
  'packages/ssrf-guard/src/resolve.ts': '8ba7ae7c4a97c0589fbb8da1166de89f36bdb5d0', // T85 PR-1b (DoH timeout, R16) — git rev-parse "$(git log -n1 --format=%h -G'DOH_TIMEOUT_MS' -- packages/ssrf-guard/src/resolve.ts)":packages/ssrf-guard/src/resolve.ts
  'packages/ssrf-guard/src/response-view.ts': 'b1b0e3e040f6d6acf66700758323b6bfae223d96', // T85: git rev-parse 3696518:packages/ssrf-guard/src/response-view.ts
  'packages/ssrf-guard/src/url-target.ts': 'c1d8f47ef7b0402b45bd9f555cd82fd0f0ec103a', // special-purpose address change (see above) — git hash-object packages/ssrf-guard/src/url-target.ts
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

// Static/file-hash checks, unaffected by input sharding — run exactly once
// (shard 0, or the single unsharded process). See differential-shard.ts.
if (RUNS_ONCE_ONLY) {
await t('the frozen suite-0.8.0 probe.ts, auth.ts and error-taxonomy.ts are the b439bc6 blobs: header dropped, import paths restored, git blob id recomputed', () => {
  assert.deepStrictEqual(readdirSync(new URL(`${FROZEN_080_DIR}/`, REPO_ROOT)).sort(), Object.keys(FROZEN_080_BLOBS).map((n) => `${n}.ts`).sort(), 'frozen/suite-0.8.0 holds a file that is not pinned, or a pinned one is missing')
  for (const [name, blob] of Object.entries(FROZEN_080_BLOBS)) {
    const lines = readRepo(`${FROZEN_080_DIR}/${name}.ts`).replace(/\r\n/g, '\n').split('\n')
    let header = 0
    while (lines[header]!.startsWith('// FROZEN:')) header++
    assert.equal(header, 4, `${name}: expected the four-line FROZEN header`)
    const restored = lines.slice(header).map((l) => (l.startsWith('import ') ? l.replace("from '../../", "from './") : l)).join('\n')
    assert.equal(blobId(restored), blob, `frozen/suite-0.8.0/${name}.ts is not the file it claims to be`)
  }
})

await t('the in-repo import closure of frozen/suite-0.8.0 is exactly the pinned list, and every pinned file hashes to its pinned blob (git blob id recomputed)', () => {
  const closure = importClosure080()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_080_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_080_BLOBS)')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_080_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_080_BLOBS)) assert.equal(blobId(readRepo(path)), blob, `${path} changed: freeze its 0.8.0 version into frozen/suite-0.8.0 first`)
})
}

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

interface Run { result: ProbeResult; requests: string[]; threw: boolean; toolsCallStatus: number | null; substituted: { body: number; header: number }; observed: Suite0160Observed }

/** `live`: the implementation's request sequence for the same input, for 0.8.0's offerAsLive (suite 0.13.0); omitted on the implementation's own run. */
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
  // Suites 0.15.0 and 0.16.0: what suite0160Remap reads off this run's transport.
  const suite0150 = recordSuite0160(offer.fetchImpl)
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: suite0150.fetchImpl,
    budget: v.budget,
    now: () => '2026-09-25T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
    ...(v.approvedBaseline ? { approvedBaseline: v.approvedBaseline } : {}),
  })
  return { result, requests, threw, toolsCallStatus: recorded.toolsCallStatus(), substituted: offer.substituted(), observed: suite0150.observed() }
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

type ShardState = {
  totalA: number
  totalB: number
  violations: number
  failures: string[]
  seen: { thrown: Record<string, number>; notReached: number; remappedRows: number; reachabilityByCatch: Record<string, number>; afterHandshake: Record<string, number> }
}

let totalA = 0
let totalB = 0
let pagedSetAside = 0
const seen = { thrown: new Map<string, number>(), notReached: 0, remappedRows: 0, reachabilityByCatch: new Map<string, number>(), afterHandshake: new Map<string, number>() }
// TODO 441 (CI speed): each loop gets its own continuously-incrementing shard
// index — see differential-shard.ts's module doc. Unsharded (no env set)
// both loops and everything after them behave exactly as before this task.
if (!IS_MERGE) {
  const idxA = { n: 0 }
  for (const fixture of FIXTURE_CORPUS) {
    for (const [label, v] of variants()) {
      if (!keepThisShard(idxA)) continue
      totalA++
      const id = `A ${fixture.id} / ${label}`
      try {
        const now = await runOnce(runProbe, fixture.createHandler, v)
        const old = await runOnce(frozen080RunProbe, fixture.createHandler, v, now.requests)
        // Suite 0.15.0: a run whose tools/list paged is set aside (counted per shard); suite-0150-differential.test.ts proves it.
        if (pagedToolsList(now.requests)) { pagedSetAside++; continue }
        const want = suite0160Remap(suite0130Remap(suite0120Remap(old.result, old.toolsCallStatus), old.requests), old.observed)
        const offerProblem = offerSubstitutionProblem(old.result, old.substituted)
        if (offerProblem) violation(id, offerProblem)
        if (!identical(withoutAuthObservation(now.result), want)) violation(id, `ProbeResult differs\n           new ${JSON.stringify(now.result).slice(0, 400)}\n           old ${JSON.stringify(want).slice(0, 400)}`)
        if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
      } catch (e) {
        violation(id, `threw ${(e as Error).message}`)
      }
    }
  }

  const idxB = { n: 0 }
  for (const fixture of FIXTURE_CORPUS) {
    for (let position = 1; position <= DEFAULT_PROBE_BUDGET.maxRequests; position++) {
      for (const [label, make, unsettledReason, settledReason] of ERRORS) {
        if (!keepThisShard(idxB)) continue
        totalB++
        const id = `B ${fixture.id} / ${label} @ request ${position}`
        const v: Variant = { budget: DEFAULT_PROBE_BUDGET, throwAt: { position, make } }
        try {
          const now = await runOnce(runProbe, fixture.createHandler, v)
          const old = await runOnce(frozen080RunProbe, fixture.createHandler, v, now.requests)
          // Suite 0.15.0: a run whose tools/list paged is set aside (counted per shard); suite-0150-differential.test.ts proves it.
          if (pagedToolsList(now.requests)) { pagedSetAside++; continue }
          if (!identical(now.requests, old.requests)) violation(id, 'request sequence differs')
          const offerProblem = offerSubstitutionProblem(old.result, old.substituted)
          if (offerProblem) violation(id, offerProblem)
          if (now.threw !== old.threw) violation(id, 'one side reached the throwing request and the other did not')
          if (!now.threw) { seen.notReached++ }
          else seen.thrown.set(label, (seen.thrown.get(label) ?? 0) + 1)
          // Settled when the error landed = 0.8.0 did not write reachability from its catch.
          const settled = old.result.assertions.find((a) => a.check_id === 'reachability')!.execution_status !== 'ERROR'
          const reason = settled ? settledReason : unsettledReason
          const expected = suite0160Remap(suite0130Remap(suite0120Remap(now.threw && reason !== null ? remapped(old.result, reason) : old.result, old.toolsCallStatus), old.requests), old.observed)
          if (!identical(withoutAuthObservation(now.result), expected)) violation(id, `ProbeResult is not 0.8.0's ${reason === null || !now.threw ? 'unchanged' : 'with the one remap'}\n           new ${JSON.stringify(now.result.assertions.map((a) => [a.check_id, a.reason]))}\n           old ${JSON.stringify(old.result.assertions.map((a) => [a.check_id, a.reason]))}`)
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

  console.log(`  A: ${FIXTURE_CORPUS.length} fixtures × ${[...variants()].length} variants = ${totalA}${SHARD_COUNT > 1 ? ` [shard ${SHARD_INDEX + 1}/${SHARD_COUNT}]` : ''}; set aside, tools/list paged (suite 0.15.0, A + B): ${pagedSetAside}`)
  console.log(`  B: ${FIXTURE_CORPUS.length} fixtures × ${DEFAULT_PROBE_BUDGET.maxRequests} positions × ${ERRORS.length} errors = ${totalB}${SHARD_COUNT > 1 ? ` [shard ${SHARD_INDEX + 1}/${SHARD_COUNT}]` : ''} (request reached: ${totalB - seen.notReached}; not reached: ${seen.notReached}); rows remapped: ${seen.remappedRows}; ${((Date.now() - started) / 1000).toFixed(1)}s`)
  for (const [label] of ERRORS) console.log(`    ${label}: thrown ${seen.thrown.get(label) ?? 0}; reachability written by the catch ${seen.reachabilityByCatch.get(label) ?? '-'}; after the handshake ${seen.afterHandshake.get(label) ?? '-'}`)
}

if (SHARD_COUNT > 1 && !IS_MERGE) {
  writeShardOut({
    totalA,
    totalB,
    violations,
    failures,
    seen: {
      thrown: Object.fromEntries(seen.thrown),
      notReached: seen.notReached,
      remappedRows: seen.remappedRows,
      reachabilityByCatch: Object.fromEntries(seen.reachabilityByCatch),
      afterHandshake: Object.fromEntries(seen.afterHandshake),
    },
  } satisfies ShardState)
}

let effTotalA = totalA, effTotalB = totalB, effViolations = violations, effFailures = failures
let effThrown = seen.thrown, effNotReached = seen.notReached
let effReachabilityByCatch = seen.reachabilityByCatch, effAfterHandshake = seen.afterHandshake
if (IS_MERGE) {
  const shards = readShardIns<ShardState>()
  effTotalA = shards.reduce((s, x) => s + x.totalA, 0)
  effTotalB = shards.reduce((s, x) => s + x.totalB, 0)
  effViolations = shards.reduce((s, x) => s + x.violations, 0)
  effFailures = shards.flatMap((x) => x.failures).slice(0, 200)
  effThrown = mergeCountMaps(shards.map((x) => x.seen.thrown))
  effNotReached = shards.reduce((s, x) => s + x.seen.notReached, 0)
  effReachabilityByCatch = mergeCountMaps(shards.map((x) => x.seen.reachabilityByCatch))
  effAfterHandshake = mergeCountMaps(shards.map((x) => x.seen.afterHandshake))
  console.log(`  [merge] ${shards.length} shard(s) → totalA=${effTotalA} totalB=${effTotalB} violations=${effViolations}`)
}

if (HAS_FULL_SET) {
await t(`0.9.0 vs frozen 0.8.0: identical off the catch path, and on it differs only by the classified reason: all ${effTotalA + effTotalB} inputs`, () => {
  if (effViolations > 0) throw new Error(`${effViolations} violation(s)\n         ${effFailures.slice(0, 25).join('\n         ')}${effFailures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the input set is not vacuous: every error is thrown, and every guard error lands both before the handshake (reachability by the catch) and after it', () => {
  assert.ok(FIXTURE_CORPUS.length >= 74, `fixture corpus shrank to ${FIXTURE_CORPUS.length}`)
  for (const [label, , reason] of ERRORS) {
    assert.ok((effThrown.get(label) ?? 0) > 0, `${label} never thrown`)
    if (reason === null) continue
    assert.ok((effReachabilityByCatch.get(label) ?? 0) > 0, `${label} never before the handshake`)
    assert.ok((effAfterHandshake.get(label) ?? 0) > 0, `${label} never after the handshake`)
  }
  assert.ok(effNotReached > 0)
})
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
