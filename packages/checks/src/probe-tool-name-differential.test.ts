/**
 * T86 differential invariant test — the primary evidence that withholding the
 * tools/call carrying the probe's reserved tool name changed nothing else.
 * Since T86b (suite 0.8.0) it also carries the T86b differential over the same
 * inputs; see "T86b" below.
 *
 * Three parties, the same shape as failed-reasons-differential.test.ts (T73b),
 * whose scripted server, T73 corpus, stage generators and oracle reading
 * functions are reused below verbatim (marked):
 *
 *   1. The T86 implementation: runProbe as of suite 0.7.x, end to end. Since
 *      T86b changed probe.ts / protocol.ts / auth.ts, that is
 *      ./frozen/suite-0.7.1/probe.ts (with its frozen protocol.ts, auth.ts and
 *      error-taxonomy.ts, the last frozen so that it reads the frozen
 *      protocol.ts rather than the live one T86b changed): the 0.7.0 and 0.7.1
 *      blobs of probe / protocol / auth are identical (8551e58, 2c99377), so
 *      this is exactly the code T86 shipped, and the first test below
 *      recomputes each blob id to prove it. Everything else the frozen copies
 *      reach — the whole in-repo import closure, workspace packages and
 *      checks.json included — is pinned to its 2c99377b blob by the second
 *      test (CLOSURE_071_BLOBS), because the frozen copies are the 0.7.1
 *      behaviour only while it is.
 *   2. FROZEN 0.6.0 — ./frozen/suite-0.6.0/{probe,protocol,error-taxonomy}.ts,
 *      byte-for-byte the suite 0.6.0 (a05097e) files apart from a four-line
 *      `// FROZEN:` header and `../../` import paths; the first test below
 *      recomputes each file's git blob id to prove it. They still import what
 *      T86 does not touch (wire.ts, auth.ts, hygiene.ts, fingerprint.ts,
 *      registry.ts, types.ts, checks.json — `git diff a05097e` on those is
 *      empty for T86). A later change to one of them must freeze the 0.6.0
 *      version first, or this stops being a differential. DO NOT "update" the
 *      frozen copy to match a later implementation. (TODO 458, suite 0.7.1,
 *      changed wire.ts, whose 0.6.0 and 0.7.0 versions are the same blob; it
 *      froze that version as frozen/suite-0.7.0/wire.ts, and
 *      wire-budget-differential.test.ts shows the new wire.ts gives these
 *      frozen files identical results for every in-budget input it tries. Every
 *      input here answers at once, far inside the duration budget.)
 *   3. ORACLE — T73b's independent JSON-RPC / SSE reading and handshake
 *      classification (verbatim), plus the T86 rule as ordered branches. It
 *      imports nothing from ./probe.ts or ./protocol.ts.
 *
 * T86 invariant, for every input (T86 implementation vs 0.6.0):
 *   - ORACLE says the call is sent (a complete first page with no exact
 *     reserved name, or a credential gate with no readable list — T86 R2:
 *     a readable list is judged even behind a gated handshake), or the run aborts before
 *     the call (a 429 / 503 + Retry-After, or 0.6.0's own throw on a null
 *     tool entry) ⇒ the implementation's ProbeResult is identical to 0.6.0's
 *     (same own keys in the same order at every level, Object.is on every
 *     leaf — stricter than equal JSON bytes), and so is the request sequence.
 *     Nothing is normalized: ProbeResult carries no suite version.
 *   - ORACLE says the call is withheld (exact name on the first page ⇒
 *     probe_tool_name_collision; a nextCursor, or tools/list failed ⇒
 *     probe_tool_name_unverifiable) ⇒ no tools/call is on the wire, the
 *     request sequence is 0.6.0's up to that call, error_taxonomy and
 *     auth_metadata are SKIPPED / UNVERIFIED with reason and unverified_reason
 *     exactly `{ key }` (no params member), and every other row and
 *     ProbeResult field is identical to 0.6.0's run against the same server
 *     answering tools/call with the ordinary unknown-tool error (0.6.0 would
 *     have sent the call; an aborting reply there would cascade rows the new
 *     code legitimately judges, so the comparison fixes a non-aborting one).
 *
 * T86b invariant, for the same inputs (runProbe, ./probe.ts, vs the frozen
 * 0.7.1 run above). A credential gate is what T86b's ORACLE (t86bGated) reads
 * off the script: the handshake credential-gated, or a completed handshake
 * whose tools/list is a 401 carrying the valid challenge, with no 429 / 503 +
 * Retry-After before the decision.
 *   - Not gated ⇒ ProbeResult and request sequence identical to 0.7.1's.
 *   - Gated ⇒ no tools/call on the wire; the request sequence is 0.7.1's up
 *     to its tools/call (all of it, where 0.7.1 withheld too); error_taxonomy
 *     SKIPPED / UNVERIFIED with { key: 'credential_required', params: { scheme:
 *     'bearer' } }; auth_metadata COMPLETED with exactly what 0.7.1's
 *     judgeAuthMetadata returns for a 401 carrying the gate's header (every gate
 *     here carries VALID_CHALLENGE, which names no metadata document, so no GET
 *     follows); every other row and ProbeResult field identical to 0.7.1's run
 *     against the same server answering tools/call with CALL_DEFAULT.
 */
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { posix } from 'node:path'
import ts from 'typescript'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import { runProbe } from './probe.ts'
import { runProbe as frozenRunProbe } from './frozen/suite-0.6.0/probe.ts'
import { runProbe as frozen071RunProbe } from './frozen/suite-0.7.1/probe.ts'
import { judgeAuthMetadata as frozen071JudgeAuthMetadata } from './frozen/suite-0.7.1/auth.ts'
import { createProbeContext } from './wire.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import type { FetchLike, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

// ---------------------------------------------------------------------------
// The frozen copy is what it says it is.
// ---------------------------------------------------------------------------

/** Blob ids of packages/checks/src/{name}.ts at a05097e (suite 0.6.0),
 *  from `git rev-parse a05097e:packages/checks/src/<name>.ts`. */
const FROZEN_BLOBS: Record<string, string> = {
  'probe': 'fb4a0e8666d4afe32d96c2e4ea46b4541867ceaa',
  'protocol': '8edaf3a8dd2c2af90e9702425557ca9601fe0342',
  'error-taxonomy': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
}

/** Blob ids of packages/checks/src/{name}.ts at 2c99377 (suite 0.7.1; the
 *  same blobs as at 8551e58, suite 0.7.0), from `git rev-parse`. */
const FROZEN_071_BLOBS: Record<string, string> = {
  'probe': 'e5eba03ee610e76d9f637207ca2c69809c5f5de2',
  'auth': '926a95cf8753f79c1d7085589f836bcde857b534',
  'protocol': '5f246eb66fa9397bcfc3c0779c5551761fdc56b5',
  'error-taxonomy': '93d0c1862dc60a690dbf15c7feb4a10f135a8945',
}

/** The in-repo import closure of frozen/suite-0.7.1, pinned to its blobs at
 *  2c99377b. Starting from the four frozen files, every import is followed —
 *  value and type-only, relative, `@mcpcheckup/*` workspace packages (through
 *  their package.json `exports`), and JSON such as checks.json — down to leaf
 *  files in this repo (importClosure071 below, reading each file's imports off
 *  the TypeScript AST, never off a text pattern; the frozen files themselves are
 *  checked by the blob test above and are not in this list). Each value is the
 *  output of
 *    git rev-parse 2c99377b:<path>
 *  for the repo-relative path it is keyed by. Imports that leave the repo
 *  (node:*, npm packages) are listed in CLOSURE_071_THIRD_PARTY and not pinned;
 *  today there are none (runtime globals such as fetch and crypto.subtle are
 *  not imports).
 *
 *  Why: the frozen copies are the suite 0.7.1 behaviour only while every file
 *  they reach is byte-identical to 2c99377b — a change anywhere in this
 *  closure changes what "0.7.1" computes without touching the frozen files.
 *  If this test goes red, copy the 2c99377b version of that file into
 *  frozen/suite-0.7.1 (and point the frozen imports at it) BEFORE changing the
 *  file, then recompute this list. The test asserts both halves: the pinned
 *  list is exactly the closure computed from the working tree, and every
 *  pinned file still hashes to its 2c99377b blob, so no file in the closure
 *  other than the frozen copies differs from 2c99377b.
 *
 *  T85 (suite 0.8.0 -> 0.9.0) re-pin — reason: RESOLVER_UNAVAILABLE code change /
 *  upstream-failure class, plus checks.json's reachability
 *  cannot_en/zh and docs_version (TODO 571, R13 ⑤); round 2: the guard's hop field, queryOne's DoH body read, registry_version 0.5.0; round 4: resolveHost's A/AAAA precedence; T85 PR-1b: the DoH request timeout (R16), resolve.ts pinned to the PR-1b commit; TODO 591: the post-fetch re-check rethrows RESOLVER_UNAVAILABLE (R20), guarded-fetch.ts pinned to that commit. The six entries marked
 *  "T85 re-pin" are pinned to the T85 PR-1 blob instead, each the output of
 *  the `git rev-parse <commit>:<path>` in its comment (the T85 PR-1 commit that
 *  last changed the file; the blob is the same at the PR-1 head). Why this keeps the
 *  differential sound rather than freezing them: the frozen 0.7.1 files reach
 *  ssrf-guard and checks.json only through type-only imports (types.ts,
 *  registry.ts), which are erased at run time, and every run below passes the
 *  registry in as input to both sides — so neither change can alter what the
 *  frozen code computes. Every other entry is still its 2c99377b blob. */
const CLOSURE_071_BLOBS: Record<string, string> = {
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
  'packages/checks/checks.json': '522fb7042323bc2bd98bf7c8720962e5ca7a198e', // T85 re-pin, round 2 (registry_version 0.5.0) — git rev-parse 962fdc6:packages/checks/checks.json
  'packages/checks/src/fingerprint.ts': 'a523c95151b1bcae036c9c97f6c80d2c69b12470',
  'packages/checks/src/hygiene.ts': '1120712366d47ee75588280a9967ea758f5a943d',
  'packages/checks/src/registry.ts': 'bcce9c9f3a032195548726da1c83985ae3e0b1f9',
  'packages/checks/src/types.ts': '59d38f860a3cd07989421fc2e6b97b60cabedd10',
  'packages/checks/src/wire.ts': 'c0ab8b30a92e22457c20acb21bc166b6c1336e56',
  'packages/ssrf-guard/src/audit.ts': 'c2f08ab05e4bdb6425c5feba789d19e0c7293073',
  'packages/ssrf-guard/src/budget.ts': 'c920ff71d6e0477fd22ef79c0077973227cbb74f',
  'packages/ssrf-guard/src/dns-wire.ts': '04357f1c08ee2d649a382d2640580903323af222',
  'packages/ssrf-guard/src/errors.ts': '958b4f9b63d9a5901b2097a2d564ef2afff79e57', // T85 re-pin, round 2 (hop field) — git rev-parse 962fdc6:packages/ssrf-guard/src/errors.ts
  'packages/ssrf-guard/src/guarded-fetch.ts': '3c96a62e1a4e1f3378ff4a31766f597d59852438', // TODO 591 re-pin (re-check RESOLVER_UNAVAILABLE rethrown, R20) — git rev-parse "$(git log -n1 --format=%h -G'discardBody' -- packages/ssrf-guard/src/guarded-fetch.ts)":packages/ssrf-guard/src/guarded-fetch.ts
  'packages/ssrf-guard/src/index.ts': '9d301879dc35ac0a85a2cd5005d70f2e75406755', // T85 re-pin: git rev-parse 3696518:packages/ssrf-guard/src/index.ts
  'packages/ssrf-guard/src/ip-policy.ts': 'b581241df1a369ee55e780b1450d1997ab2635db',
  'packages/ssrf-guard/src/rate-limit.ts': '20f0e9e542de6708411456c0a46d7fdad77e0773',
  'packages/ssrf-guard/src/resolve.ts': '8ba7ae7c4a97c0589fbb8da1166de89f36bdb5d0', // T85 re-pin, PR-1b (DoH timeout, R16) — git rev-parse "$(git log -n1 --format=%h -G'DOH_TIMEOUT_MS' -- packages/ssrf-guard/src/resolve.ts)":packages/ssrf-guard/src/resolve.ts
  'packages/ssrf-guard/src/response-view.ts': 'b1b0e3e040f6d6acf66700758323b6bfae223d96', // T85 re-pin: git rev-parse 3696518:packages/ssrf-guard/src/response-view.ts
  'packages/ssrf-guard/src/url-target.ts': '46678f430c6534806c014b0265dc408c8fe29705',
}
const CLOSURE_071_THIRD_PARTY: string[] = []

const REPO_ROOT = new URL('../../../', import.meta.url)
const FROZEN_071_DIR = 'packages/checks/src/frozen/suite-0.7.1'
const readRepo = (path: string) => readFileSync(new URL(path, REPO_ROOT), 'utf8')

/** Module specifiers of one source file, read off the TypeScript AST (the
 *  whole tree, via ts.forEachChild): import declarations (value, type-only
 *  and side-effect), export … from, import x = require('…'), dynamic
 *  import('…'), import('…') types, and /// <reference path> /
 *  /// <reference types> directives. A specifier that is not a string literal
 *  (a computed dynamic import, a template literal) cannot be followed, so it
 *  THROWS rather than being skipped: a closure that silently lost an edge
 *  would pin less than the frozen files reach. */
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

/** Follows every import from the four frozen files to in-repo leaves. */
function importClosure071(): { files: string[]; thirdParty: string[] } {
  const packagesByName = new Map<string, string>()
  for (const dir of readdirSync(new URL('packages/', REPO_ROOT))) {
    const pj = new URL(`packages/${dir}/package.json`, REPO_ROOT)
    if (existsSync(pj)) packagesByName.set((JSON.parse(readFileSync(pj, 'utf8')) as { name: string }).name, `packages/${dir}`)
  }
  const seen = new Set<string>(), thirdParty = new Set<string>()
  const queue = ['probe', 'auth', 'protocol', 'error-taxonomy'].map((n) => `${FROZEN_071_DIR}/${n}.ts`)
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
  return { files: [...seen].filter((f) => !f.startsWith(`${FROZEN_071_DIR}/`)).sort(), thirdParty: [...thirdParty].sort() }
}

for (const [dir, blobs] of [['suite-0.6.0', FROZEN_BLOBS], ['suite-0.7.1', FROZEN_071_BLOBS]] as const)
await t(`the frozen ${dir} files are the ${dir === 'suite-0.6.0' ? 'a05097e' : '2c99377'} blobs: header dropped, import paths restored, git blob id recomputed`, () => {
  for (const [name, blob] of Object.entries(blobs)) {
    const raw = readFileSync(new URL(`./frozen/${dir}/${name}.ts`, import.meta.url), 'utf8').replace(/\r\n/g, '\n')
    const lines = raw.split('\n')
    let header = 0
    while (lines[header]!.startsWith('// FROZEN:')) header++
    assert.equal(header, 4, `${name}: expected the four-line FROZEN header`)
    const restored = lines.slice(header).map((l) => (l.startsWith('import ') ? l.replace("from '../../", "from './") : l)).join('\n')
    const bytes = Buffer.from(restored, 'utf8')
    const id = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
    assert.equal(id, blob, `${dir}/${name}.ts is not the file it claims to be`)
  }
})

await t('the in-repo import closure of frozen/suite-0.7.1 is exactly the pinned list, and every pinned file is still its 2c99377b blob (git blob id recomputed)', () => {
  const closure = importClosure071()
  assert.deepStrictEqual(closure.files, Object.keys(CLOSURE_071_BLOBS).sort(), 'the pinned list is not the import closure: recompute it (see CLOSURE_071_BLOBS)')
  assert.deepStrictEqual(closure.thirdParty, CLOSURE_071_THIRD_PARTY, 'the closure reaches a new out-of-repo import')
  for (const [path, blob] of Object.entries(CLOSURE_071_BLOBS)) {
    const bytes = Buffer.from(readRepo(path).split('\r\n').join('\n'), 'utf8')
    const id = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
    assert.equal(id, blob, `${path} changed since 2c99377b: freeze its 2c99377b version into frozen/suite-0.7.1 first`)
  }
})

// ---------------------------------------------------------------------------
// The scripted server — verbatim from failed-reasons-differential.test.ts (T73b).
// ---------------------------------------------------------------------------

const ENDPOINT = 'https://notes-mcp.example.com/mcp'
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

// ---------------------------------------------------------------------------
// T86 additions to the scripted server: a scripted tools/call reply, the
// resource_metadata document a challenged tools/call points at, and a record
// of every request.
// ---------------------------------------------------------------------------

const RESERVED = '__mcpcheckup_probe_nonexistent_tool__'
const METADATA_PATH = '/.well-known/oauth-protected-resource'
const METADATA_CHALLENGE = `Bearer realm="mcp", resource_metadata="https://notes-mcp.example.com${METADATA_PATH}"`

interface T86Script extends Script { toolsCall: Resp }

/** 0.6.0's pinned unknown-tool reply (T73b's TOOLS_CALL_REPLY): an ordinary JSON-RPC error. */
const CALL_DEFAULT = resp(200, 'application/json', '{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Unknown tool"}}')
/** A server that would run the tool: a successful result. */
const CALL_RUNS = resp(200, 'application/json', '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}]}}')
/** Gated invocation: 401 + a challenge whose metadata document is served. */
const CALL_GATED = (() => {
  const r = resp(401, null, '')
  r.headers.set('www-authenticate', METADATA_CHALLENGE)
  return r
})()
/** Rate-limited invocation: aborts the round at tools/call. */
const CALL_429 = resp(429, null, '')
const TOOLS_CALL_REPLIES: [string, Resp][] = [['default', CALL_DEFAULT], ['runs', CALL_RUNS], ['gated', CALL_GATED], ['429', CALL_429]]
const METADATA_DOC = resp(200, 'application/json', '{"resource":"https://notes-mcp.example.com","authorization_servers":["https://notes-mcp.example.com/oauth"]}')

function recordingFetch(s: T86Script, calls: string[]): FetchLike {
  return async (input, init) => {
    const method = typeof init?.body === 'string' ? (JSON.parse(init.body) as { method?: unknown }).method : undefined
    const path = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url).pathname
    calls.push(typeof method === 'string' ? method : `${init?.method ?? 'GET'} ${path}`)
    const r =
      method === 'server/discover' ? s.discover
      : method === 'initialize' ? s.initialize
      : method === 'notifications/initialized' ? s.ack
      : method === 'tools/list' ? s.toolsList
      : method === 'tools/call' ? s.toolsCall
      : path === METADATA_PATH ? METADATA_DOC
      : resp(404, 'text/plain', 'Not Found')
    return toResponse(r)
  }
}

async function run(probe: typeof runProbe, s: T86Script): Promise<{ result: ProbeResult; calls: string[] }> {
  const calls: string[] = []
  let seq = 0
  const result = await probe({
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl: recordingFetch(s, calls),
    budget: DEFAULT_PROBE_BUDGET,
    now: () => '2026-09-23T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  })
  return { result, calls }
}

// ---------------------------------------------------------------------------
// ORACLE — verbatim from failed-reasons-differential.test.ts (T73b): reason
// constructor, SSE / JSON-RPC reading, handshake classification.
// ---------------------------------------------------------------------------

type OReason = { key: string; params?: Record<string, number> }
const K = (key: string, params: Record<string, number> = {}): OReason => (Object.keys(params).length > 0 ? { key, params } : { key })

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

function oracleCode(m: OMessage): Record<string, number> {
  if (m === null || m.kind !== 'error' || !Number.isSafeInteger(m.code)) return {}
  return { jsonrpc_error_code: Object.is(m.code, -0) ? 0 : m.code }
}

const rateLimited = (r: Resp) => r.status === 429 || (r.status === 503 && r.headers.has('retry-after'))
const challenged = (r: Resp) => r.status === 401 && r.challenge

type OHandshake = { aborted: true } | { aborted: false; ok: boolean; gated: boolean; declared: string | null; fail?: OReason }

function oracleHandshake(s: Script): OHandshake {
  const d = s.discover
  if (rateLimited(d)) return { aborted: true }
  if (d.status === 200) {
    const m = oracleRead(d)
    const sv = oracleField(m, 'supportedVersions')
    if (Array.isArray(sv) && typeof sv[0] === 'string') return { aborted: false, ok: true, gated: false, declared: sv[0] }
    const fail = m === null ? K('handshake_discover_not_jsonrpc') : m.kind === 'error' ? K('handshake_discover_jsonrpc_error', oracleCode(m)) : K('handshake_discover_no_supported_versions')
    return { aborted: false, ok: false, gated: false, declared: null, fail }
  }
  if (d.status >= 400 && d.status <= 499) {
    const m = oracleRead(d)
    if (m !== null && m.kind === 'error' && [-32020, -32021, -32022].includes(m.code)) {
      return { aborted: false, ok: false, gated: false, declared: null, fail: K('handshake_discover_rejected', { status: d.status, jsonrpc_error_code: m.code }) }
    }
    const i = s.initialize
    if (rateLimited(i)) return { aborted: true }
    if (i.status !== 200) return { aborted: false, ok: false, gated: challenged(i), declared: null, fail: K('handshake_initialize_http_error', { status: i.status }) }
    const im = oracleRead(i)
    const pv = oracleField(im, 'protocolVersion')
    if (typeof pv !== 'string') {
      const fail = im === null ? K('handshake_initialize_not_jsonrpc') : im.kind === 'error' ? K('handshake_initialize_jsonrpc_error', oracleCode(im)) : K('handshake_initialize_no_protocol_version')
      return { aborted: false, ok: false, gated: false, declared: null, fail }
    }
    const a = s.ack
    if (rateLimited(a)) return { aborted: true }
    if (a.status < 200 || a.status > 299) return { aborted: false, ok: false, gated: challenged(a), declared: pv, fail: K('handshake_ack_http_error', { status: a.status }) }
    return { aborted: false, ok: true, gated: false, declared: pv }
  }
  return { aborted: false, ok: false, gated: false, declared: null, fail: K('handshake_discover_http_error', { status: d.status }) }
}

// ---------------------------------------------------------------------------
// ORACLE — the T86 rule, as ordered branches over the reading above.
// ---------------------------------------------------------------------------

type Decision = 'abort' | 'send' | OReason

const branchCounts = new Map<string, number>()

function oracleDecision(s: Script): Decision {
  const branch = (name: string, d: Decision): Decision => {
    branchCounts.set(name, (branchCounts.get(name) ?? 0) + 1)
    return d
  }
  const hs = oracleHandshake(s)
  if (hs.aborted) return branch('abort (handshake)', 'abort')
  const tl = s.toolsList
  if (rateLimited(tl)) return branch('abort (tools/list)', 'abort')
  const challenge = challenged(tl)
  const m = oracleRead(tl)
  const tools = oracleField(m, 'tools')
  const readable = Array.isArray(tools) && !challenge
  /** a / b on a readable first page (T86 R2: on every branch, gated or not). */
  const listVerdict = (list: unknown[], where: string): Decision | null => {
    if (list.some((tool) => isPlainObject(tool) && tool.name === RESERVED)) return branch(`a (collision${where})`, K('probe_tool_name_collision'))
    const result = (m as { result: Record<string, unknown> }).result
    if (Object.prototype.hasOwnProperty.call(result, 'nextCursor') && result.nextCursor !== null) return branch(`b (nextCursor${where})`, K('probe_tool_name_unverifiable'))
    return null
  }
  if (hs.gated) {
    // The handshake-gated branch never runs the hygiene check, so a null entry does not throw there.
    if (readable) return listVerdict(tools as unknown[], ', handshake gated') ?? branch('send (handshake gated, readable, no collision)', 'send')
    return branch('c1 (handshake gated, no readable list)', 'send')
  }
  if (hs.ok && challenge) return branch('c1 (tools/list gated)', 'send')
  if (!readable) return branch('c2 (tools/list failed)', K('probe_tool_name_unverifiable'))
  const list = tools as unknown[]
  // Unchanged since 0.6.0: a null entry makes the hygiene check throw, and the
  // catch cascades every check not yet written, these two rows included.
  if (list.includes(null)) return branch('abort (null tool entry)', 'abort')
  return listVerdict(list, '') ?? branch('send (complete, no collision)', 'send')
}

// ---------------------------------------------------------------------------
// The per-input check.
// ---------------------------------------------------------------------------

const T86_ROWS = ['error_taxonomy', 'auth_metadata']
const failures: string[] = []
let violations = 0
const decisionCounts = new Map<string, number>()

function violation(id: string, what: string) {
  violations++
  if (failures.length < 200) failures.push(`${id}: ${what}`)
}

/** Identical own keys in identical order at every level, Object.is on every
 *  leaf (iterative: some tool arrays are deep). */
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

const withoutT86Rows = (r: ProbeResult) => ({ ...r, assertions: r.assertions.filter((a) => !T86_ROWS.includes(a.check_id)) })

async function checkInput(id: string, s: T86Script): Promise<void> {
  const want = oracleDecision(s)
  const label = typeof want === 'string' ? want : want.key
  decisionCounts.set(label, (decisionCounts.get(label) ?? 0) + 1)
  const now = await run(frozen071RunProbe, s)
  await checkT86b(id, s, now)
  const sent = now.calls.includes('tools/call')

  if (typeof want === 'string') {
    const then = await run(frozenRunProbe, s)
    if (want === 'send' && !sent) violation(id, 'oracle says send, implementation withheld tools/call')
    if (want === 'abort' && sent) violation(id, 'oracle says the round aborts before the decision, but tools/call was sent')
    if (!identical(now.calls, then.calls)) violation(id, `requests ${JSON.stringify(now.calls)} vs 0.6.0 ${JSON.stringify(then.calls)}`)
    if (!identical(now.result, then.result)) violation(id, 'ProbeResult differs from 0.6.0')
    return
  }

  const then = await run(frozenRunProbe, { ...s, toolsCall: CALL_DEFAULT })
  if (sent) violation(id, `oracle says withhold (${want.key}), tools/call was sent`)
  const cut = then.calls.indexOf('tools/call')
  if (cut < 0 || !identical(now.calls, then.calls.slice(0, cut))) violation(id, `requests ${JSON.stringify(now.calls)} vs 0.6.0 ${JSON.stringify(then.calls)}`)
  for (const check_id of T86_ROWS) {
    const a = now.result.assertions.find((x) => x.check_id === check_id)!
    if (a.execution_status !== 'SKIPPED' || a.assertion_status !== 'UNVERIFIED' || !identical(a.reason, want) || !identical(a.unverified_reason, want)) {
      violation(id, `${check_id} = ${a.execution_status}/${a.assertion_status} ${JSON.stringify(a.reason)} / ${JSON.stringify(a.unverified_reason)}, oracle ${JSON.stringify(want)}`)
    }
  }
  if (!identical(withoutT86Rows(now.result), withoutT86Rows(then.result))) violation(id, 'outside error_taxonomy / auth_metadata, the result differs from 0.6.0')
}

// ---------------------------------------------------------------------------
// T86b: runProbe (./probe.ts) against the frozen 0.7.1 run of the same input.
// ---------------------------------------------------------------------------

/** T86b ORACLE: is the run behind a credential gate when the call would be
 *  decided? Reads the script only, through the T73b handshake reading above. */
function t86bGated(s: Script): boolean {
  const hs = oracleHandshake(s)
  if (hs.aborted || rateLimited(s.toolsList)) return false
  return hs.gated || (hs.ok && challenged(s.toolsList))
}

const GATE_REASON = { key: 'credential_required', params: { scheme: 'bearer' } }
/** 0.7.1's own auth_metadata judgment for a 401 carrying VALID_CHALLENGE. It
 *  names no metadata document, so it fetches nothing. */
const GATE_AUTH = await frozen071JudgeAuthMetadata({
  fetchImpl: async () => { throw new Error('VALID_CHALLENGE names no metadata document; nothing may be fetched') },
  budget: DEFAULT_PROBE_BUDGET,
  ctx: createProbeContext(Date.now()),
  callResult: { status: 401, headers: new Headers({ 'www-authenticate': VALID_CHALLENGE }), bodyText: '', currentEndpoint: ENDPOINT },
})
const t86b = { gated: 0, notGated: 0, oneFewer: 0, alsoWithheldBy071: 0, status403: 0 }

async function checkT86b(id: string, s: T86Script, then: { result: ProbeResult; calls: string[] }): Promise<void> {
  const now = await run(runProbe, s)
  if (s.initialize.status === 403 || s.ack.status === 403 || s.toolsList.status === 403) t86b.status403++
  if (!t86bGated(s)) {
    t86b.notGated++
    if (!identical(now.calls, then.calls)) violation(id, `T86b not gated: requests ${JSON.stringify(now.calls)} vs 0.7.1 ${JSON.stringify(then.calls)}`)
    if (!identical(now.result, then.result)) violation(id, 'T86b not gated: ProbeResult differs from 0.7.1')
    return
  }
  t86b.gated++
  const base = s.toolsCall === CALL_DEFAULT ? then : await run(frozen071RunProbe, { ...s, toolsCall: CALL_DEFAULT })
  const cut = base.calls.indexOf('tools/call')
  if (cut < 0) t86b.alsoWithheldBy071++
  else if (now.calls.length === base.calls.length - 1) t86b.oneFewer++
  if (now.calls.includes('tools/call')) violation(id, 'T86b gated: tools/call was sent')
  if (!identical(now.calls, cut < 0 ? base.calls : base.calls.slice(0, cut))) violation(id, `T86b gated: requests ${JSON.stringify(now.calls)} vs 0.7.1 ${JSON.stringify(base.calls)}`)
  const et = now.result.assertions.find((x) => x.check_id === 'error_taxonomy')!
  if (et.execution_status !== 'SKIPPED' || et.assertion_status !== 'UNVERIFIED' || !identical(et.reason, GATE_REASON) || !identical(et.unverified_reason, GATE_REASON)) {
    violation(id, `T86b gated: error_taxonomy = ${et.execution_status}/${et.assertion_status} ${JSON.stringify(et.reason)}`)
  }
  const auth = now.result.assertions.find((x) => x.check_id === 'auth_metadata')!
  const authReason = GATE_AUTH.status === 'VERIFIED' ? null : GATE_AUTH.reason
  if (auth.execution_status !== 'COMPLETED' || auth.assertion_status !== GATE_AUTH.status || !identical(auth.reason, authReason)) {
    violation(id, `T86b gated: auth_metadata = ${auth.execution_status}/${auth.assertion_status} ${JSON.stringify(auth.reason)}, 0.7.1 on the gate header ${JSON.stringify(GATE_AUTH)}`)
  }
  if (!identical(withoutT86Rows(now.result), withoutT86Rows(base.result))) violation(id, 'T86b gated: outside error_taxonomy / auth_metadata, the result differs from 0.7.1')
}

// ---------------------------------------------------------------------------
// The input set — verbatim from failed-reasons-differential.test.ts (T73b):
// statuses, content types, the T73 corpus, stage-specific bodies, pinned
// stages and the four wire-stage generators.
// ---------------------------------------------------------------------------

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

const INITIALIZE_BODIES: string[] = [
  rpcResult('{"protocolVersion":"2025-06-18","capabilities":{}}'),
  rpcResult('{"protocolVersion":"2025-03-26"}'),
  rpcResult('{"protocolVersion":"2024-11-05"}'),
  rpcResult('{"protocolVersion":"2023-01-01"}'),
  rpcResult('{"protocolVersion":"2099-01-01"}'),
  rpcResult(`{"protocolVersion":"${CANARY}"}`),
  rpcResult('{"protocolVersion":""}'),
  rpcResult('{"protocolVersion":20250618}'),
  rpcResult('{"protocolVersion":null}'),
  rpcResult('{"protocolVersion":["2025-06-18"]}'),
  rpcResult('{"capabilities":{}}'),
  rpcResult('null'),
  rpcResult('["2025-06-18"]'),
  rpcError('-32602'), rpcError('-32601'), rpcError('-0'), rpcError('1.5'), rpcError('9007199254740993'), rpcError('-32022'),
  sse(rpcResult('{"protocolVersion":"2025-06-18"}')),
  sse(rpcError('-32603')),
]

const VALID_TOOLS = '[{"name":"search_notes","inputSchema":{"type":"object"}},{"name":"get_note","inputSchema":{"type":"object"}}]'
const TOOLS_BODIES: string[] = [
  rpcResult(`{"tools":${VALID_TOOLS}}`),
  rpcResult('{"tools":[]}'),
  rpcResult(`{"tools":"${CANARY}"}`),
  rpcResult('{"tools":null}'),
  rpcResult('{"tools":{"0":{"name":"a"}}}'),
  rpcResult('{"nextCursor":"x"}'),
  rpcResult('[]'),
  rpcResult('{"tools":[{"description":"no name","inputSchema":{}}]}'),
  rpcResult('{"tools":[{"name":"a"}]}'),
  sse(rpcResult(`{"tools":${VALID_TOOLS}}`)),
  sse(rpcError('-32603')),
  rpcError('-32603'), rpcError('-0'), rpcError('1e300'),
]

// Pinned stages.
const DISCOVER_OK = resp(200, 'application/json', rpcResult('{"supportedVersions":["2026-07-28"]}'))
const DISCOVER_FALLBACK = resp(404, 'text/plain', 'Not Found')
const DISCOVER_FAILED = resp(500, 'text/plain', 'Internal Server Error')
const INIT_OK = resp(200, 'application/json', rpcResult('{"protocolVersion":"2025-06-18","capabilities":{}}'))
const ACK_OK = resp(202, null, '')
const TOOLS_OK = resp(200, 'application/json', rpcResult(`{"tools":${VALID_TOOLS}}`))

function* discoverStage(): Generator<[string, Script, Resp]> {
  const base = { initialize: INIT_OK, ack: ACK_OK, toolsList: TOOLS_OK }
  for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
    const d = resp(status, ct, body)
    yield [`status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { discover: d, ...base }, d]
  }
  for (const status of REDIRECTS) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
    const d = resp(status, ct, body, { location: bi % 2 === 0 ? 'https://notes-mcp.example.com/mcp/v2' : 'https://mirror.example.com/mcp' })
    yield [`redirect=${status} ct=${JSON.stringify(ct)} body#${bi}`, { discover: d, ...base }, d]
  }
  for (const status of [...STATUSES, ...REDIRECTS]) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of DISCOVER_BODIES.entries()) {
    const d = resp(status, ct, body)
    yield [`discover-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { discover: d, ...base }, d]
  }
}

function* initializeStage(): Generator<[string, Script, Resp]> {
  const base = { discover: DISCOVER_FALLBACK, ack: ACK_OK, toolsList: TOOLS_OK }
  for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
    const i = resp(status, ct, body)
    yield [`status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { initialize: i, ...base }, i]
  }
  for (const status of [...STATUSES, ...REDIRECTS]) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of INITIALIZE_BODIES.entries()) {
    const i = resp(status, ct, body)
    yield [`initialize-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { initialize: i, ...base }, i]
  }
}

function* ackStage(): Generator<[string, Script, Resp]> {
  const base = { discover: DISCOVER_FALLBACK, initialize: INIT_OK, toolsList: TOOLS_OK }
  const statuses = [200, 201, 202, 204, 206, 299, ...REDIRECTS, 400, 401, 403, 404, 405, 406, 415, 429, 500, 502, 503]
  const bodies = ['', `Nope ${CANARY}`, rpcError('-32600'), rpcResult('{}')]
  for (const status of statuses) for (const challenge of [false, true]) for (const [bi, body] of bodies.entries()) {
    const a = resp(status, bi === 0 ? null : 'text/plain', body, { challenge })
    yield [`status=${status} challenge=${challenge} body#${bi}`, { ack: a, ...base }, a]
  }
}

function* toolsListStage(): Generator<[string, Script, Resp]> {
  const handshakes: [string, Omit<Script, 'toolsList'>][] = [
    ['modern-ok', { discover: DISCOVER_OK, initialize: INIT_OK, ack: ACK_OK }],
    ['legacy-ok', { discover: DISCOVER_FALLBACK, initialize: INIT_OK, ack: ACK_OK }],
    ['failed-not-gated', { discover: DISCOVER_FAILED, initialize: INIT_OK, ack: ACK_OK }],
  ]
  for (const [hn, hs] of handshakes) for (const challenge of [false, true]) {
    for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
      const tl = resp(status, ct, body, { challenge })
      yield [`${hn} challenge=${challenge} status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: tl }, tl]
    }
    for (const status of STATUSES) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of TOOLS_BODIES.entries()) {
      const tl = resp(status, ct, body, { challenge })
      yield [`${hn} challenge=${challenge} tools-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: tl }, tl]
    }
  }
}


// ---------------------------------------------------------------------------
// T86 stages.
// ---------------------------------------------------------------------------

const GATED = resp(401, null, '', { challenge: true })
/** T73b's three tools/list handshakes plus the two credential-gated ones (c1
 *  at the handshake layer: gated initialize, gated notifications/initialized). */
const T86_HANDSHAKES: [string, Omit<Script, 'toolsList'>][] = [
  ['modern-ok', { discover: DISCOVER_OK, initialize: INIT_OK, ack: ACK_OK }],
  ['legacy-ok', { discover: DISCOVER_FALLBACK, initialize: INIT_OK, ack: ACK_OK }],
  ['failed-not-gated', { discover: DISCOVER_FAILED, initialize: INIT_OK, ack: ACK_OK }],
  ['initialize-gated', { discover: DISCOVER_FALLBACK, initialize: GATED, ack: ACK_OK }],
  ['ack-gated', { discover: DISCOVER_FALLBACK, initialize: INIT_OK, ack: GATED }],
]

/** The T73b stages, each input served with 0.6.0's pinned tools/call reply. */
function* t73bStages(): Generator<[string, T86Script]> {
  for (const [name, stage] of [['discover', discoverStage], ['initialize', initializeStage], ['ack', ackStage], ['tools/list', toolsListStage]] as const) {
    for (const [id, script] of stage()) yield [`${name} ${id}`, { ...script, toolsCall: CALL_DEFAULT }]
  }
}

/** T73b's tools/list corpus behind the two gated handshakes it does not cover. */
function* gatedToolsListStage(): Generator<[string, T86Script]> {
  for (const [hn, hs] of T86_HANDSHAKES.slice(3)) for (const challenge of [false, true]) {
    for (const status of STATUSES) for (const ct of CONTENT_TYPES) for (const [bi, body] of CORPUS_BODIES.entries()) {
      yield [`${hn} challenge=${challenge} status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: resp(status, ct, body, { challenge }), toolsCall: CALL_DEFAULT }]
    }
    for (const status of STATUSES) for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of TOOLS_BODIES.entries()) {
      yield [`${hn} challenge=${challenge} tools-specific status=${status} ct=${JSON.stringify(ct)} body#${bi}`, { ...hs, toolsList: resp(status, ct, body, { challenge }), toolsCall: CALL_DEFAULT }]
    }
  }
}

const tool = (name: string) => `{"name":${JSON.stringify(name)},"inputSchema":{"type":"object"}}`
const CLEAN = `${tool('search_notes')},${tool('get_note')}`
/** tools/list `result` values: exact names, near misses, and nextCursor shapes. */
const T86_RESULTS: string[] = [
  `{"tools":[${tool(RESERVED)}]}`,
  `{"tools":[${CLEAN},${tool(RESERVED)}]}`,
  `{"tools":[${tool(RESERVED)},${CLEAN}]}`,
  `{"tools":[${CLEAN},${tool(RESERVED)},${tool(RESERVED)}]}`,
  `{"tools":[${tool(RESERVED)}],"nextCursor":"p2"}`,
  `{"nextCursor":"p2","tools":[${CLEAN},${tool(RESERVED)}]}`,
  `{"tools":[{"name":"\\u005f_mcpcheckup_probe_nonexistent_tool__","inputSchema":{"type":"object"}}]}`,
  `{"tools":[{"name":"${RESERVED}"}]}`,
  `{"tools":[${CLEAN},${tool(`${RESERVED}x`)}]}`,
  `{"tools":[${tool(RESERVED.toUpperCase())}]}`,
  `{"tools":[${tool(` ${RESERVED}`)}]}`,
  `{"tools":[${tool(`${RESERVED} `)}]}`,
  `{"tools":[${tool(RESERVED.slice(0, -1))}]}`,
  `{"tools":[${tool(RESERVED.slice(1))}]}`,
  `{"tools":[{"name":"n","description":"${RESERVED}","inputSchema":{"type":"object"}}]}`,
  `{"tools":[{"name":"n","meta":{"name":"${RESERVED}"},"inputSchema":{"type":"object"}}]}`,
  `{"tools":["${RESERVED}"]}`,
  `{"tools":[{"name":["${RESERVED}"]}]}`,
  `{"tools":[[{"name":"${RESERVED}"}]]}`,
  `{"tools":[null,${tool('a')}]}`,
  `{"tools":[${CLEAN}],"nextCursor":"p2"}`,
  `{"tools":[${CLEAN}],"nextCursor":""}`,
  `{"tools":[${CLEAN}],"nextCursor":0}`,
  `{"tools":[${CLEAN}],"nextCursor":false}`,
  `{"tools":[${CLEAN}],"nextCursor":{}}`,
  `{"tools":[${CLEAN}],"nextCursor":[]}`,
  `{"tools":[${CLEAN}],"nextCursor":null}`,
  `{"tools":[${CLEAN}],"nextCursor":"p2","nextCursor":null}`,
  `{"tools":[${CLEAN}],"nextCursor":null,"nextCursor":"p2"}`,
  `{"tools":[],"nextCursor":"p2"}`,
  '{"tools":[]}',
  `{"tools":[{"name":"a","nextCursor":"p2","inputSchema":{"type":"object"}}]}`,
  `{"tools":[${CLEAN}],"NextCursor":"p2","next_cursor":"p2"}`,
]
const T86_BODIES: string[] = [
  ...T86_RESULTS.map(rpcResult),
  ...T86_RESULTS.map((r) => sse(rpcResult(r))),
  `{"jsonrpc":"2.0","id":1,"nextCursor":"p2","result":{"tools":[${CLEAN}]}}`,
  `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"${RESERVED}"}}`,
]

function* t86Stage(): Generator<[string, T86Script]> {
  for (const [hn, hs] of T86_HANDSHAKES) for (const challenge of [false, true]) for (const status of [200, 401, 500]) {
    for (const ct of ['application/json', 'text/event-stream', null]) for (const [bi, body] of T86_BODIES.entries()) for (const [cn, call] of TOOLS_CALL_REPLIES) {
      yield [`${hn} challenge=${challenge} status=${status} ct=${JSON.stringify(ct)} body#${bi} call=${cn}`, { ...hs, toolsList: resp(status, ct, body, { challenge }), toolsCall: call }]
    }
  }
}

// ---------------------------------------------------------------------------
// Run.
// ---------------------------------------------------------------------------

console.log('T86 differential invariant：T86 实现（冻结的 0.7.1）vs 冻结的 0.6.0 vs 独立 oracle（保留名 tools/call 发与不发）；同一批输入上再做 T86b：现行实现 vs 冻结的 0.7.1')

const stageSizes: [string, number][] = []
const started = Date.now()
for (const [name, inputs] of [['T73b stages', t73bStages()], ['gated handshakes × tools/list corpus', gatedToolsListStage()], ['T86 tools/list bodies × tools/call replies', t86Stage()]] as const) {
  const t0 = Date.now()
  let n = 0
  for (const [id, script] of inputs) {
    n++
    await checkInput(`${name} ${id}`, script)
  }
  stageSizes.push([name, n])
  console.log(`  stage ${name}: ${n} inputs, ${((Date.now() - t0) / 1000).toFixed(1)}s`)
}
const total = stageSizes.reduce((n, [, k]) => n + k, 0)
console.log(`  input set: ${stageSizes.map(([n, k]) => `${n}=${k}`).join(' + ')} = ${total}; ${((Date.now() - started) / 1000).toFixed(1)}s`)
console.log(`  oracle decisions: ${[...decisionCounts.entries()].sort().map(([k, v]) => `${k}=${v}`).join(' ')}`)
console.log(`  oracle branches: ${[...branchCounts.entries()].sort().map(([k, v]) => `${k}=${v}`).join(' ')}`)
console.log(`  T86b: not gated ${t86b.notGated} (identical to 0.7.1), gated ${t86b.gated} (${t86b.oneFewer} with exactly one request fewer — the tools/call — and ${t86b.alsoWithheldBy071} that 0.7.1 withheld too); inputs with a 403 at initialize / ack / tools/list: ${t86b.status403}; 0.7.1's auth_metadata on the gate header: ${JSON.stringify(GATE_AUTH)}`)

await t(`the invariant holds for all ${total} inputs`, () => {
  if (violations > 0) throw new Error(`${violations} violation(s)\n         ${failures.slice(0, 25).join('\n         ')}${failures.length > 25 ? '\n         … and more' : ''}`)
})

await t('the T86b input split is not vacuous: gated inputs where 0.7.1 sent the call and where it withheld it, non-gated inputs, and 403s all occur; every gated input is accounted for', () => {
  assert.equal(t86b.gated + t86b.notGated, total)
  assert.equal(t86b.oneFewer + t86b.alsoWithheldBy071, t86b.gated, 'every gated input either drops exactly the tools/call or was withheld by 0.7.1 too')
  for (const [what, n] of Object.entries(t86b)) assert.ok(n > 0, `${what} never seen`)
  assert.equal(GATE_AUTH.status, 'UNVERIFIED')
})

await t('the input set is not vacuous: every oracle branch is reached', () => {
  for (const branch of ['abort (handshake)', 'abort (tools/list)', 'abort (null tool entry)', 'c1 (handshake gated, no readable list)', 'c1 (tools/list gated)', 'a (collision)', 'b (nextCursor)', 'a (collision, handshake gated)', 'b (nextCursor, handshake gated)', 'send (handshake gated, readable, no collision)', 'c2 (tools/list failed)', 'send (complete, no collision)']) {
    assert.ok((branchCounts.get(branch) ?? 0) > 0, `${branch} never reached`)
  }
})

await t('the oracle agrees with itself on hand-derived anchor cases (guards the oracle, not the implementation)', () => {
  const s = (toolsList: Resp, hs: Omit<Script, 'toolsList'> = T86_HANDSHAKES[0]![1]): Script => ({ ...hs, toolsList })
  const json = (r: string) => resp(200, 'application/json', rpcResult(r))
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[{"name":"\\u005f_mcpcheckup_probe_nonexistent_tool__"}]}`))), { key: 'probe_tool_name_collision' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${tool(RESERVED)}],"nextCursor":"p2"}`))), { key: 'probe_tool_name_collision' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${CLEAN}],"nextCursor":""}`))), { key: 'probe_tool_name_unverifiable' })
  assert.equal(oracleDecision(s(json(`{"tools":[${CLEAN}],"nextCursor":null}`))), 'send')
  assert.equal(oracleDecision(s(json(`{"tools":[${tool(`${RESERVED}x`)}]}`))), 'send')
  assert.deepStrictEqual(oracleDecision(s(resp(502, 'text/html', '<p>x</p>'))), { key: 'probe_tool_name_unverifiable' })
  assert.equal(oracleDecision(s(resp(401, 'application/json', rpcResult(`{"tools":[${tool(RESERVED)}]}`), { challenge: true }))), 'send')
  assert.deepStrictEqual(oracleDecision(s(resp(401, 'application/json', rpcResult(`{"tools":[${CLEAN}]}`), { challenge: true }), T86_HANDSHAKES[2]![1])), { key: 'probe_tool_name_unverifiable' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${tool(RESERVED)}]}`), T86_HANDSHAKES[3]![1])), { key: 'probe_tool_name_collision' })
  assert.deepStrictEqual(oracleDecision(s(json(`{"tools":[${CLEAN}],"nextCursor":"p2"}`), T86_HANDSHAKES[4]![1])), { key: 'probe_tool_name_unverifiable' })
  assert.equal(oracleDecision(s(json(`{"tools":[${CLEAN}]}`), T86_HANDSHAKES[3]![1])), 'send')
  assert.equal(oracleDecision(s(resp(500, 'text/plain', 'x'), T86_HANDSHAKES[3]![1])), 'send')
  assert.equal(oracleDecision(s(resp(429, null, ''))), 'abort')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
