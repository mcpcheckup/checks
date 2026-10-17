/**
 * TODO 217: every run records the revision our probe offered
 * (ProbeResult.probeOfferedRevision) next to the one the server answered
 * (protocolRevisionDeclared), and the legacy fallback offers the newest legacy
 * revision the registry knows (2025-11-25), once.
 *
 * The corpus-wide check reads the offer off the wire, not off the code: for
 * every fixture, the value recorded must be the revision carried by the last
 * handshake request the probe sent (server/discover or initialize), and it
 * may be null only when protocolRevisionDeclared is null too.
 */
import assert from 'node:assert/strict'
import { runProbe } from './probe.ts'
import { offeredRevision } from './protocol.ts'
import { CHECKS_REGISTRY } from './registry.ts'
import { FIXTURE_CORPUS } from '@mcpcheckup/fixtures'
import { DEFAULT_PROBE_BUDGET } from '@mcpcheckup/ssrf-guard'
import type { ProbeInput, ProbeResult } from './types.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ENDPOINT = 'https://notes-mcp.example.com/mcp'

function makeInput(fetchImpl: ProbeInput['fetchImpl'], maxRequests = DEFAULT_PROBE_BUDGET.maxRequests): ProbeInput {
  let seq = 0
  return {
    target: { slug: 'example/notes-mcp', transport: 'remote', endpointUrl: ENDPOINT },
    fetchImpl,
    budget: { ...DEFAULT_PROBE_BUDGET, maxRequests },
    now: () => '2026-08-18T00:00:00.000Z',
    newId: () => `probe-${++seq}`,
    provenance: 'INDEPENDENTLY_OBSERVED',
    registry: CHECKS_REGISTRY,
  }
}

/** One outbound request as the server saw it: its JSON-RPC method and the revision it carried. */
interface SentRequest { method: string | null; offered: string | null; header: string | null }

function readSent(init: RequestInit | undefined): SentRequest {
  const headers = new Headers(init?.headers)
  let body: Record<string, unknown> | null = null
  try { body = typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : null } catch { body = null }
  const method = typeof body?.method === 'string' ? body.method : null
  const params = (body?.params ?? {}) as Record<string, unknown>
  const meta = (params._meta ?? {}) as Record<string, unknown>
  const offered =
    method === 'initialize' ? (params.protocolVersion as string)
    : method === 'server/discover' ? (meta['io.modelcontextprotocol/protocolVersion'] as string)
    : null
  return { method, offered, header: headers.get('mcp-protocol-version') }
}

async function runCapturing(handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>, maxRequests?: number): Promise<{ result: ProbeResult; sent: SentRequest[] }> {
  const sent: SentRequest[] = []
  const capturing: ProbeInput['fetchImpl'] = async (input, init) => {
    sent.push(readSent(init))
    return handler(input, init)
  }
  const result = await runProbe(makeInput(capturing, maxRequests))
  return { result, sent }
}

function fixture(id: string) {
  const f = FIXTURE_CORPUS.find((x) => x.id === id)
  assert.ok(f, `fixture ${id} is not in the corpus`)
  return f
}

const HANDSHAKE_METHODS = new Set(['server/discover', 'initialize'])
const lastHandshakeOffer = (sent: SentRequest[]): string | null =>
  sent.filter((s) => s.method !== null && HANDSHAKE_METHODS.has(s.method)).at(-1)?.offered ?? null

console.log('\nTODO 217 · the offer is the newest revision the registry knows on each branch')

await t('offeredRevision: modern = the newest revision_matrix entry, legacy = the newest one below it (2025-11-25)', () => {
  const matrix = [...(CHECKS_REGISTRY.checks.find((c) => c.check_id === 'protocol_revision')?.revision_matrix ?? [])].sort()
  assert.ok(matrix.length >= 2, 'protocol_revision has a revision_matrix')
  assert.equal(offeredRevision('modern'), matrix.at(-1))
  assert.equal(offeredRevision('legacy'), matrix.at(-2))
  assert.equal(offeredRevision('legacy'), '2025-11-25')
})

console.log('\nTODO 217 · fixtures: what was offered, and what was answered')

await t('modern-baseline-clean: offered 2026-07-28 on server/discover, answered 2026-07-28', async () => {
  const { result, sent } = await runCapturing(fixture('modern-baseline-clean').createHandler())
  assert.equal(result.probeOfferedRevision, '2026-07-28')
  assert.equal(result.protocolRevisionDeclared, '2026-07-28')
  assert.equal(sent.filter((s) => s.method === 'initialize').length, 0, 'a modern server gets no initialize')
})

await t('legacy-baseline-clean: the fallback initialize offers 2025-11-25 (was 2025-06-18); the server answered 2025-06-18 and that is what is recorded', async () => {
  const { result, sent } = await runCapturing(fixture('legacy-baseline-clean').createHandler())
  const inits = sent.filter((s) => s.method === 'initialize')
  assert.deepEqual(inits.map((s) => s.offered), ['2025-11-25'], 'exactly one initialize, carrying 2025-11-25: no version ladder')
  assert.equal(result.probeOfferedRevision, '2025-11-25')
  assert.equal(result.protocolRevisionDeclared, '2025-06-18')
  // After the handshake the probe speaks the answered revision, as before.
  assert.equal(sent.find((s) => s.method === 'tools/list')?.header, '2025-06-18')
})

await t('a legacy server that supports 2025-11-25 answers with it: the negotiated value is the server\'s highest, in one initialize', async () => {
  const base = fixture('legacy-baseline-clean').createHandler()
  const SUPPORTED = ['2025-03-26', '2025-06-18', '2025-11-25']
  const echoing = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const s = readSent(init)
    if (s.method !== 'initialize') return base(input, init)
    const answer = SUPPORTED.includes(s.offered ?? '') ? s.offered : SUPPORTED.at(-1)
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 'probe-2', result: { protocolVersion: answer, capabilities: {} } }), {
      status: 200,
      headers: { 'content-type': 'application/json', 'mcp-session-id': 's-217' },
    })
  }
  const { result, sent } = await runCapturing(echoing)
  assert.equal(sent.filter((s) => s.method === 'initialize').length, 1)
  assert.equal(result.probeOfferedRevision, '2025-11-25')
  assert.equal(result.protocolRevisionDeclared, '2025-11-25')
})

await t('credential-gated-handshake: discover and the fallback initialize both 401 — offered is the initialize\'s 2025-11-25, nothing was answered', async () => {
  const { result, sent } = await runCapturing(fixture('credential-gated-handshake').createHandler())
  assert.equal(lastHandshakeOffer(sent), '2025-11-25')
  assert.equal(result.probeOfferedRevision, '2025-11-25')
  assert.equal(result.protocolRevisionDeclared, null)
  assert.equal(result.assertions.find((a) => a.check_id === 'protocol_revision')?.unverified_reason?.key, 'credential_required')
})

await t('recognized-modern-error-code-401-not-exempted: a modern server rejecting discover — offered 2026-07-28, no fallback, nothing answered', async () => {
  const { result, sent } = await runCapturing(fixture('recognized-modern-error-code-401-not-exempted').createHandler())
  assert.equal(sent.filter((s) => s.method === 'initialize').length, 0)
  assert.equal(result.probeOfferedRevision, '2026-07-28')
  assert.equal(result.protocolRevisionDeclared, null)
})

await t('response-exceeds-budget: a cascade AFTER the handshake keeps the offer and the answer', async () => {
  const { result } = await runCapturing(fixture('response-exceeds-budget').createHandler())
  const toolsList = result.assertions.find((a) => a.check_id === 'tools_list')!
  assert.equal(toolsList.execution_status, 'SKIPPED')
  assert.equal(toolsList.unverified_reason?.key, 'probe_budget_exhausted_body')
  assert.equal(result.probeOfferedRevision, '2026-07-28')
  assert.equal(result.protocolRevisionDeclared, '2026-07-28')
})

await t('legacy-baseline-clean, maxRequests=4: the budget runs out after the handshake — offered 2025-11-25 is kept', async () => {
  const { result, sent } = await runCapturing(fixture('legacy-baseline-clean').createHandler(), 4)
  assert.equal(sent.length, 4)
  assert.equal(result.probeOfferedRevision, '2025-11-25')
  assert.equal(result.protocolRevisionDeclared, '2025-06-18')
})

await t('maxRequests=0: nothing was sent, so nothing was offered — null, as protocolRevisionDeclared', async () => {
  const { result, sent } = await runCapturing(fixture('legacy-baseline-clean').createHandler(), 0)
  assert.equal(sent.length, 0)
  assert.equal(result.probeOfferedRevision, null)
  assert.equal(result.protocolRevisionDeclared, null)
})

await t('maxRequests=1 on a legacy server: discover was answered, the fallback initialize never went out — the handshake did not return, so null (as protocolRevisionDeclared and reachability)', async () => {
  const { result, sent } = await runCapturing(fixture('legacy-baseline-clean').createHandler(), 1)
  assert.deepEqual(sent.map((s) => s.method), ['server/discover'])
  assert.equal(result.probeOfferedRevision, null)
  assert.equal(result.protocolRevisionDeclared, null)
  assert.equal(result.assertions.find((a) => a.check_id === 'reachability')?.execution_status, 'ERROR')
})

await t('a fetch that throws on the first request: null', async () => {
  const result = await runProbe(makeInput(async () => { throw new Error('connection refused') }))
  assert.equal(result.probeOfferedRevision, null)
  assert.equal(result.protocolRevisionDeclared, null)
})

await t('stdio: no request at all, null', async () => {
  const input = makeInput(async () => new Response('unexpected'))
  const result = await runProbe({ ...input, target: { slug: 'example/local-tool', transport: 'stdio', packageRef: 'example-local-tool@1.0.0' } })
  assert.equal(result.probeOfferedRevision, null)
})

console.log(`\nTODO 217 · corpus: all ${FIXTURE_CORPUS.length} fixtures, offer read off the wire`)

await t('every fixture: probeOfferedRevision is a string or null (never absent), equals the last handshake request\'s revision when set, and is set whenever protocolRevisionDeclared is', async () => {
  let set = 0, unset = 0
  const seen = new Set<string>()
  for (const f of FIXTURE_CORPUS) {
    const { result, sent } = await runCapturing(f.createHandler())
    assert.ok(Object.hasOwn(result, 'probeOfferedRevision'), `${f.id}: probeOfferedRevision is absent`)
    const offered = result.probeOfferedRevision
    assert.ok(offered === null || typeof offered === 'string', `${f.id}: ${String(offered)}`)
    if (offered === null) {
      unset++
      assert.equal(result.protocolRevisionDeclared, null, `${f.id}: an answer with no offer`)
    } else {
      set++
      seen.add(offered)
      assert.equal(offered, lastHandshakeOffer(sent), `${f.id}: recorded ${offered}, the wire says ${String(lastHandshakeOffer(sent))}`)
    }
  }
  console.log(`       ${set} with an offer, ${unset} without; offers seen: ${[...seen].sort().join(', ')}`)
  // Not vacuous: the corpus exercises both branches.
  assert.deepEqual([...seen].sort(), ['2025-11-25', '2026-07-28'])
})

// A run stored before the probe recorded its offer is read as the legacy branch when its
// discovery_handshake reason is one of these. That rule holds only if those reasons come
// off the legacy branch alone; checked here on the live probe over the whole corpus, the
// request sequence read off the wire.
const LEGACY_ONLY_REASONS = ['handshake_ack_http_error', 'credential_required']
await t('every fixture: a discovery_handshake reason read as legacy-only comes with an initialize on the wire and the legacy offer recorded', async () => {
  const hits: string[] = []
  for (const f of FIXTURE_CORPUS) {
    const { result, sent } = await runCapturing(f.createHandler())
    const dh = result.assertions.find((a) => a.check_id === 'discovery_handshake')
    if (!dh?.reason || !LEGACY_ONLY_REASONS.includes(dh.reason.key)) continue
    hits.push(`${f.id}:${dh.reason.key}`)
    assert.ok(sent.some((r) => r.method === 'initialize'), `${f.id}: ${dh.reason.key} without an initialize`)
    assert.equal(result.probeOfferedRevision, offeredRevision('legacy'), `${f.id}: ${dh.reason.key} with offer ${String(result.probeOfferedRevision)}`)
  }
  console.log(`       ${hits.length} fixtures carry one: ${hits.join(', ')}`)
  // Not vacuous: both reasons occur in the corpus.
  assert.deepEqual([...new Set(hits.map((h) => h.split(':')[1]))].sort(), [...LEGACY_ONLY_REASONS].sort())
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
