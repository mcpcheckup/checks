import type { Fixture, ExpectedAssertion, FetchHandler } from '../types.ts'
import { jsonRpcResult, rawResponse } from '../helpers.ts'
import {
  CLEAN_TOOLS,
  PROBE_RESERVED_TOOL_NAME,
  TOOLS_WITH_RESERVED_NAME,
  LARGE_NESTED_TOOLSET,
  ENDPOINT,
  createModernHandler,
  createLegacyHandler,
  modernSampleRun,
  legacySampleRun,
  cleanBaselineAssertions,
  withOverride,
} from './shared.ts'

export const modernBaselineClean: Fixture = {
  id: 'modern-baseline-clean',
  description: '一个完全正确的 2026-07-28 modern 实现：server/discover 可用、每请求 _meta 携带协议版本、没有 initialize 握手。',
  protocolRevision: '2026-07-28',
  kind: 'positive',
  guardsAgainst:
    'P0 正确性要求（PRD §5.2）：证明探测器不会因为「只认旧 initialize 握手」而把一个完全正确的最新实现误判成 discovery_handshake=FAILED。' +
    '这条同时是本对拍集里最重要的 negative control——它以「全部通过」的正例形式存在，' +
    '专门用来防止后面那些反例被一个「不管三七二十一全判 FAILED」的坏探测器意外满足。',
  tools: CLEAN_TOOLS,
  createHandler: () => createModernHandler(CLEAN_TOOLS),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const legacyBaselineClean: Fixture = {
  id: 'legacy-baseline-clean',
  description: '一个完全正确的 legacy（2025-06-18）实现：initialize / notifications/initialized / Mcp-Session-Id 握手全部按规范完成。',
  protocolRevision: '2025-06-18',
  kind: 'positive',
  guardsAgainst:
    '证明探测器对 legacy 实现同样公平——不会因为它"不支持 server/discover"就误判。' +
    '按 2026-07-28 规范的探测算法：先尝试现代请求，收到非现代错误形状的 400 后正确回退到 initialize，' +
    'discovery_handshake 依然是 VERIFIED。',
  tools: CLEAN_TOOLS,
  createHandler: () => createLegacyHandler(CLEAN_TOOLS),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const legacyStrictAcceptEnforcement: Fixture = {
  id: 'legacy-strict-accept-enforcement',
  description:
    '一个完全合规的 legacy（2025-06-18）实现，严格执行 Streamable HTTP 传输规范"发送消息给服务器"一节的第 2 条：' +
    '"The client MUST include an Accept header, listing both application/json and text/event-stream as supported ' +
    'content types"——对包括 initialize 在内的每一个 POST 都校验 Accept，不满足则 406。',
  protocolRevision: '2025-06-18',
  kind: 'positive',
  guardsAgainst:
    'Task Y 判责：mcp.deepwiki.com/mcp（L2b 入库探测中 disqualified）用真实抓包证实，它的 legacy initialize/' +
    'notifications/initialized/tools/list 全部要求 Accept 头同时列出 application/json 与 text/event-stream，' +
    '缺失即 406——而 packages/checks/src/protocol.ts 的 legacy 回退路径（performLegacyHandshake / ' +
    'performToolsList 的 legacy 分支 / performUnknownToolCall 的 legacy 分支）从未发送这个头。' +
    '规范原文见 modelcontextprotocol.io/specification/2025-06-18/basic/transports#sending-messages-to-the-server ' +
    '第 2 条，且"Backwards Compatibility"一节明确把这条要求延伸到第一个 InitializeRequest 本身，不是只对后续请求。' +
    '本条对拍集里已有的 legacy-baseline-clean 的 mock server 从不校验 Accept 头，所以这个 bug 一直没被拦住——' +
    '这条 fixture 按 DeepWiki 真实观察到的行为塑形（406 + 同一句错误文案），专门锁住"发给合规 legacy 实现的每一个' +
    '请求都必须带 Accept 头"这件事。',
  tools: CLEAN_TOOLS,
  createHandler: () => createLegacyHandler(CLEAN_TOOLS, { enforceAcceptHeader: true }),
  sampleRun: (handler) => legacySampleRun(handler, { includeAcceptHeader: true }),
  expectedAssertions: cleanBaselineAssertions(),
}

export const legacyNoSessionId: Fixture = {
  id: 'legacy-no-session-id',
  description: '一个完全合规的 legacy（2025-06-18）实现：从不分配 Mcp-Session-Id——规范只说服务器 MAY 分配，不是 MUST。',
  protocolRevision: '2025-06-18',
  kind: 'positive',
  guardsAgainst:
    'Task Y 判责：mcp.deepwiki.com/mcp 用真实抓包证实，它的 initialize/tools/list/tools/call 响应从来没有 Mcp-Session-Id 头——' +
    '而 packages/checks/src/protocol.ts 的 performLegacyHandshake 曾经把"没有 session id"当成握手失败的信号' +
    '（`!sessionId` 直接判 handshakeOk=false），把一个完全合规、只是选择不用 session 的服务器错误地判成 FAILED。' +
    '规范原文见 modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management 第 1 条：' +
    '"A server using the Streamable HTTP transport MAY assign a session ID at initialization time"——MAY，不是 MUST。' +
    '本条对拍集里已有的 legacy-baseline-clean 的 mock server 总是分配 FIXED_SESSION_ID，从未覆盖"完全不分配"这个合法分支，' +
    '所以这个 bug 一直没被拦住。',
  tools: CLEAN_TOOLS,
  createHandler: () => createLegacyHandler(CLEAN_TOOLS, { omitSessionId: true }),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const legacySseFramedResponses: Fixture = {
  id: 'legacy-sse-framed-responses',
  description:
    '一个完全合规的 legacy（2025-06-18）实现：对 initialize/tools/list/tools/call 这类 JSON-RPC request 一律用 ' +
    'Content-Type: text/event-stream 的单帧 SSE（`event: message\\ndata: <json>\\n\\n`）返回响应，而不是 application/json。',
  protocolRevision: '2025-06-18',
  kind: 'positive',
  guardsAgainst:
    'Task Y 判责：mcp.deepwiki.com/mcp 用真实抓包证实，它的 initialize/tools/list 响应 Content-Type 是 text/event-stream，' +
    'body 是一个 `event: message\\ndata: {...}\\n\\n` 形状的 SSE 帧——而 packages/checks/src/protocol.ts 的 ' +
    'parseJsonRpcBody 曾经对任何响应体都直接 JSON.parse(bodyText)，SSE 帧文本不是合法 JSON，解析失败被当成"不是 ' +
    'JSON-RPC"，握手/tools_list 因此被误判 FAILED。规范原文见 ' +
    'modelcontextprotocol.io/specification/2025-06-18/basic/transports#sending-messages-to-the-server 第 5 条：' +
    '"If the input is a JSON-RPC request, the server MUST either return Content-Type: text/event-stream, to initiate ' +
    'an SSE stream, or Content-Type: application/json, to return one JSON object. The client MUST support both these ' +
    'cases."——这里是一次性 POST 回复选择了 SSE 帧形状，不是长连接推送。本条对拍集里已有的 legacy-baseline-clean 的 ' +
    'mock server 只用过 application/json，从未覆盖这个合法分支，所以这个 bug 一直没被拦住。',
  tools: CLEAN_TOOLS,
  createHandler: () => createLegacyHandler(CLEAN_TOOLS, { sseFramedResponses: true }),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const legacyDiscover401Unauthorized: Fixture = {
  id: 'legacy-discover-401-unauthorized',
  description:
    '一个完全合规的 legacy（2025-06-18）实现：面对它压根不认识的现代 server/discover 探测，网关兜底策略把' +
    '这个未知方法当成"未授权路由"处理，返回裸 401（非 JSON-RPC 的 {"error":"unauthorized"} body）而不是 400；' +
    '随后匿名 initialize / notifications/initialized / tools/list 全部按规范正常完成。',
  protocolRevision: '2025-06-18',
  kind: 'positive',
  guardsAgainst:
    '误报调查判责结论 (b)（droproom/mcp，2026-08-30）：packages/checks/src/protocol.ts 的 performHandshake ' +
    '曾经只把 HTTP 400 当作"回退到 legacy initialize"的信号（`discover.status === 400`）。真实观测到的 ' +
    'droproom.net/api/mcp——一个完全合规的 legacy 服务器，只是把"未知方法"兜底响应码选成了 401 而不是 400——' +
    '因此从未触发回退，discovery_handshake 与级联的 protocol_revision、tools_list（连同下游 5 项）全部被' +
    '错误判为 FAILED/SKIPPED，而官方 @modelcontextprotocol/sdk 客户端针对同一服务器的匿名全流程（initialize → ' +
    'notifications/initialized → tools/list）完全走通，同轮另外 6 项检查也全部 VERIFIED——这是我们自己的探测器缺陷，' +
    '不是对方违反规范。规范原文见 modelcontextprotocol.io/specification/2026-07-28/basic/versioning' +
    '#compatibility-matrix，"Dual-era client / Legacy server" 一行："the modern request returns a `4xx` without ' +
    'a recognized modern error body, and the client falls back to `initialize`"——是泛化的 4xx，不是窄化的 400。' +
    '修复把判定条件从 `=== 400` 放宽到 `>= 400 && < 500`；本条 fixture 按 droproom 的真实响应形状塑形，专门锁住' +
    '"合规 legacy 服务器的兜底状态码选了 401 而不是 400"这个此前从未被覆盖的合法分支。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createLegacyHandler(CLEAN_TOOLS, {
      discoverProbeResponse: () => rawResponse(401, {}, JSON.stringify({ error: 'unauthorized' })),
    }),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const modernDiscoverFullShape: Fixture = {
  id: 'modern-discover-full-shape',
  description:
    '一个 modern 实现，server/discover 响应带上规范允许的完整可选结构：嵌套的 capabilities（每个能力自己的 listChanged 标志）、' +
    'ttlMs、cacheScope，以及 serverInfo 放在规范规定的 `_meta[\'io.modelcontextprotocol/serverInfo\']` 路径下，而不是顶层 serverInfo 字段。',
  protocolRevision: '2026-07-28',
  kind: 'positive',
  guardsAgainst:
    'Task T 判责：一个字段名错位的 bug（读 `protocolVersions` 而规范字段名是 `supportedVersions`，' +
    '且 serverInfo 校验读的是顶层而不是规范规定的 `_meta` 路径下）曾经让探测器把一个完全合规、真实存在的 modern ' +
    'server（Cloudflare 的 docs.mcp.cloudflare.com/mcp）误判为 discovery_handshake/protocol_revision FAILED，' +
    '而对拍集里已有的 16 条 fixture 全部绿灯——因为 packages/fixtures 自己的 mock server 恰好复刻了同一个错误字段名，' +
    '两边的错误互相抵消，从未被测出来。这条 fixture 按真实抓包到的响应结构塑形（见 Task T 报告），' +
    '专门锁住"规范允许的完整/可选结构必须被正确解析"这件事，不依赖 mock 与实现共享同一个错字。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      discoverResponse: (id) =>
        jsonRpcResult(id, {
          resultType: 'complete',
          supportedVersions: ['2026-07-28'],
          capabilities: { tools: { listChanged: true }, prompts: { listChanged: true } },
          ttlMs: 0,
          cacheScope: 'private',
          _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'notes-mcp', version: '1.4.0' } },
        }),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const largeToolsetNestedSchemas: Fixture = {
  id: 'large-toolset-nested-schemas',
  description: '一个 modern 实现，工具集较大（8 个工具）且 inputSchema 含多层嵌套（object 套 object、array of object）。',
  protocolRevision: '2026-07-28',
  kind: 'positive',
  guardsAgainst:
    '压 toolset_fingerprint / schema_fingerprint 的投影与规范化路径——嵌套结构、数组、enum 混在一起时，' +
    'canonicalizer 的 nfc-jcs/v1 规范化与 projectSchemas 的字段白名单投影必须仍然稳定、可重复计算，不因为结构变复杂就跑偏。',
  tools: LARGE_NESTED_TOOLSET,
  createHandler: () => createModernHandler(LARGE_NESTED_TOOLSET),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

// ---- Credential-gated positive controls ----
// A server that deliberately puts protocol handshake / tool discovery behind
// authentication is exercising a legitimate access-control choice, not a
// protocol defect — see the credential-gate rule's "期望行为" (expected
// behavior) definitions, tracked internally.
// The two fixtures below are its acceptance-criteria positive cases, one per
// cascade layer (handshake layer, tools-list layer).

const CREDENTIAL_GATE_METADATA_PATH = '/.well-known/oauth-protected-resource'
const CREDENTIAL_GATE_METADATA_URL = `${new URL(ENDPOINT).origin}${CREDENTIAL_GATE_METADATA_PATH}`
/** A real RFC 9110 §11.3 challenge shape (auth-scheme "Bearer" followed by
 *  SP-separated auth-params) — not invented header syntax. */
const CREDENTIAL_GATE_CHALLENGE = `Bearer realm="mcp", resource_metadata="${CREDENTIAL_GATE_METADATA_URL}"`

const TOOLS_DERIVED_CHECK_IDS = ['toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene', 'toolset_unchanged_vs_approved', 'schema_unchanged_vs_approved']

/** Every request — modern server/discover, legacy initialize, notifications/
 *  initialized, tools/list, tools/call — gets the same 401 + WWW-Authenticate
 *  challenge, except the resource_metadata document itself (served normally so
 *  auth_metadata, an unrelated check, gets its real VERIFIED result rather than
 *  being complicated by this fixture's own subject matter). */
function createCredentialGatedEverywhereHandler(): FetchHandler {
  return async (input) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    if (url.pathname === CREDENTIAL_GATE_METADATA_PATH) {
      return rawResponse(
        200,
        { 'content-type': 'application/json' },
        JSON.stringify({ resource: new URL(ENDPOINT).origin, authorization_servers: [`${new URL(ENDPOINT).origin}/oauth`] }),
      )
    }
    return rawResponse(401, { 'www-authenticate': CREDENTIAL_GATE_CHALLENGE }, null)
  }
}

export function credentialGatedCascadeAssertions(gatedCheckIds: string[]): ExpectedAssertion[] {
  const reason = { key: 'credential_required', params: { scheme: 'bearer' } }
  const base = cleanBaselineAssertions()
    .filter((a) => !TOOLS_DERIVED_CHECK_IDS.includes(a.check_id))
    .concat(TOOLS_DERIVED_CHECK_IDS.map((check_id): ExpectedAssertion => ({ check_id, execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason })))
  return gatedCheckIds.reduce(
    (acc, check_id) => withOverride(acc, { check_id, execution_status: 'COMPLETED', assertion_status: 'UNVERIFIED', reason }),
    base,
  )
}

export const credentialGatedHandshake: Fixture = {
  id: 'credential-gated-handshake',
  description:
    '一个有意把整个握手放在鉴权后面的服务器：server/discover、legacy initialize、tools/list、tools/call 全部返回 401，' +
    '并附带合法的 RFC 9110 §11.6.1 WWW-Authenticate: Bearer challenge（含 resource_metadata 指针）。',
  protocolRevision: null,
  kind: 'positive',
  guardsAgainst:
    'credential-gate 规则的核心正例（握手层）：这是一次合法的访问控制选择，不是协议缺陷——探测器必须把 ' +
    'discovery_handshake / protocol_revision / tools_list 记 UNVERIFIED/credential_required，而不是像此前那样一律 ' +
    'FAILED，把"我们没能验证"报成了"它坏了"。同时证明这不是简单地"看到 401 就豁免"：豁免要求结构合法的 ' +
    'WWW-Authenticate 头，且这条 fixture 走的正是既有的 modern → legacy 回退路径——server/discover 先被 401 拒绝，' +
    '回退到 legacy initialize，initialize 本身也被同样的 401+challenge 挡住——回退顺序本身不因这次新增而改变一行' +
    '控制流（判据只读已经取到的响应，从不影响是否回退）。',
  createHandler: () => createCredentialGatedEverywhereHandler(),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: credentialGatedCascadeAssertions(['discovery_handshake', 'protocol_revision', 'tools_list']),
}

/** `Basic` SP `,` SP `Bearer ...` — two challenges, with list OWS in front of
 *  the comma. RFC 9110 §5.6.1's `#rule` permits that OWS; the bare `Basic` is
 *  already a complete first challenge. Built by concatenation so the single
 *  space before the comma is visible in the source rather than hiding inside a
 *  longer string literal. */
const LIST_OWS_CHALLENGE = 'Basic' + ' ' + ', ' + `Bearer realm="mcp", resource_metadata="${CREDENTIAL_GATE_METADATA_URL}"`

/** Swaps the scheme in a credential_required cascade. Written as a transform
 *  OVER credentialGatedCascadeAssertions rather than by parameterising it, so
 *  that helper — and therefore every existing fixture's expectedAssertions —
 *  stays byte-identical; this file's only removed line this round is the
 *  corpus version constant in version.ts. */
function withChallengeScheme(assertions: ExpectedAssertion[], scheme: string): ExpectedAssertion[] {
  return assertions.map((a) => (a.reason?.key === 'credential_required' ? { ...a, reason: { key: 'credential_required', params: { scheme } } } : a))
}

export const credentialChallengeListOwsBeforeComma: Fixture = {
  id: 'credential-challenge-list-ows-before-comma',
  description:
    '与 credential-gated-handshake 相同的"整个握手都在鉴权后面"的服务器，但 WWW-Authenticate 是一个两条 challenge 的' +
    '列表，且第一条 challenge（裸 `Basic`）与逗号之间隔着一个 list OWS 空格：`Basic , Bearer realm="mcp", resource_metadata="…"`。',
  protocolRevision: null,
  kind: 'positive',
  guardsAgainst:
    'Codex PR#19（round 11）指出的判据**过窄**的一面：逗号前的空白是 RFC 9110 §5.6.1 的 list OWS，不是"空的参数段"。' +
    '此前 classifyCredentialChallenge 看到 scheme 之后有空白就假定那是 challenge 自己的 1*SP 分隔符，于是把这个完全' +
    '合法的列表判成 null，credential-gated 出口整个不生效，三条协议检查退回 FAILED——把"我们没能验证"又报成了' +
    '"它坏了"。同时钉住 Lead 对 Codex 3919297516 的裁定：多条 challenge 时**第一条说了算**，所以这里的 scheme 是' +
    '`basic` 而不是后面那条的 `bearer`。',
  createHandler: (): FetchHandler => async (input) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    if (url.pathname === CREDENTIAL_GATE_METADATA_PATH) {
      return rawResponse(
        200,
        { 'content-type': 'application/json' },
        JSON.stringify({ resource: new URL(ENDPOINT).origin, authorization_servers: [`${new URL(ENDPOINT).origin}/oauth`] }),
      )
    }
    return rawResponse(401, { 'www-authenticate': LIST_OWS_CHALLENGE }, null)
  },
  sampleRun: (handler) => legacySampleRun(handler),
  // INTENTIONAL PAIRING, do not "fix" one side to match the other (reviewer
  // finding, round 12). This fixture pins a run where the three protocol
  // checks report credential_required with scheme 'basic' — the FIRST
  // challenge in the list — while auth_metadata is COMPLETED/VERIFIED,
  // audited from the SECOND (Bearer) challenge's resource_metadata pointer.
  // The two come from different challenges on purpose:
  // classifyCredentialChallenge deliberately reads only the first challenge
  // and reports its scheme, whereas judgeAuthMetadata's parseBearerChallenge
  // is a scheme-agnostic regex over the whole header value and so finds the
  // resource_metadata parameter wherever it sits. Each assertion is
  // individually true of this response, and neither is a bug: making
  // auth_metadata say 'basic', or making the protocol checks say 'bearer',
  // would each make one of them false.
  expectedAssertions: withChallengeScheme(credentialGatedCascadeAssertions(['discovery_handshake', 'protocol_revision', 'tools_list']), 'basic'),
}

export const credentialGatedToolsList: Fixture = {
  id: 'credential-gated-tools-list',
  description: '一个 modern 实现：server/discover 握手完全正常；唯一被鉴权挡住的是 tools/list 本身，返回 401 + 合法 WWW-Authenticate: Bearer challenge。',
  protocolRevision: '2026-07-28',
  kind: 'positive',
  guardsAgainst:
    'credential-gate 规则的第二个落点（工具列表层）：握手本身没有被挡，discovery_handshake / protocol_revision ' +
    '必须保留它们真实的 VERIFIED 结果——credential-gating 只发生在 tools/list 这一步时，不能让它污染已经真实验证过的' +
    '握手结论。只有 tools_list 本身及其下游五项记 UNVERIFIED/credential_required；tools/call 本身完全公开（有的服务端' +
    '只隐藏工具清单、不隐藏调用能力本身，是同样合法的设计选择），error_taxonomy / auth_metadata 因此保持真实结果不受' +
    '影响，与 no-credentials-unverifiable-auth（那条是 tools/call 本身被挡）互补，不重复。',
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsListResponse: () => rawResponse(401, { 'www-authenticate': CREDENTIAL_GATE_CHALLENGE }, null),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: credentialGatedCascadeAssertions(['tools_list']),
}

export const credentialGatedToolsListWithToolsBody: Fixture = {
  id: 'credential-gated-tools-list-with-tools-body',
  description:
    '一个 modern 实现：server/discover 握手完全正常；tools/list 返回 HTTP 401 + 合法 WWW-Authenticate: Bearer challenge，' +
    '但同一个响应的 body 里**带着一份结构完好的 result.tools 数组**（现实里的成因：鉴权代理配置错误，把 401 盖在了一个' +
    '上游本已成功的响应上）。',
  protocolRevision: '2026-07-28',
  kind: 'positive',
  guardsAgainst:
    'Codex 在 PR#19 上提的第二个 P2（round 9）：判据必须在**读 body 之前**、只按状态码与响应头分类。' +
    '此前 performToolsList 只在 !ok 的那一支挂 credentialChallenge，于是这种"401 但 body 里有合法工具数组"的响应会' +
    '得到 ok=true 且不带 challenge，probe.ts 落到 else if (toolsList.ok)：tools_list 记 VERIFIED，并且' +
    '**从一个服务端自己标成 401 的响应里算出并（签名运行时）发布 toolset/schema 指纹**。指导原则：401 是服务端' +
    '声明这次响应未经授权，签名证据绝不能从服务端自己不认的响应里推导出来。修法是让 challenge 直接否决 ok，' +
    '把 tools 在源头置空，这样无论握手成功与否，指纹路径都到不了这种响应。' +
    '与 credential-gated-tools-list（同样 401+challenge，但 body 是空的）配对：那条证明豁免出口存在，这条证明出口' +
    '不因 body 的内容而被绕开。',
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsListResponse: (id) =>
        rawResponse(
          401,
          { 'www-authenticate': CREDENTIAL_GATE_CHALLENGE, 'content-type': 'application/json' },
          JSON.stringify({ jsonrpc: '2.0', id, result: { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public', tools: CLEAN_TOOLS } }),
        ),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: credentialGatedCascadeAssertions(['tools_list']),
}

/** T6.9-F round 2. The one request-count shape the corpus never covered: a
 *  LEGACY server whose handshake fully succeeds — `server/discover` 4xx (1) →
 *  `initialize` (2) → `notifications/initialized` (3) — then `tools/list` (4),
 *  then a `tools/call` (5) answered with 401 + a challenge carrying a
 *  resource_metadata pointer, which makes judgeAuthMetadata fetch that document
 *  (6). Every other credential-gated fixture is short of this: the modern ones
 *  never pay for the legacy fallback, and credential-gated-handshake's 401 lands
 *  on `initialize`, which skips `notifications/initialized` — so the corpus
 *  maximum was 5 and 6 existed only as a code-read upper bound.
 *
 *  Everything about this server is legitimate, which is why it is a positive:
 *  hiding tool *invocation* behind auth while leaving the tool *catalogue*
 *  public is a deliberate access-control choice (the exact mirror of
 *  credential-gated-tools-list, which hides the catalogue and leaves invocation
 *  public), and the challenge it sends is well-formed and backed by a real
 *  metadata document. So the run reaches its normal conclusions rather than a
 *  cascade — nothing here is a defect to report about the target. */
const legacyToolsCallGatedBaseHandler = (): FetchHandler =>
  createLegacyHandler(CLEAN_TOOLS, {
    toolsCallResponse: () => rawResponse(401, { 'www-authenticate': CREDENTIAL_GATE_CHALLENGE }, null),
  })

export const legacyToolsCallCredentialGated: Fixture = {
  id: 'legacy-tools-call-credential-gated',
  description:
    '一个 legacy 实现：server/discover 走 4xx 回退，initialize 与 notifications/initialized 全部成功，tools/list 公开返回工具清单；' +
    '唯一被鉴权挡住的是 tools/call 本身，返回 401 + 合法 WWW-Authenticate: Bearer challenge（含 resource_metadata 指针），' +
    '该 resource_metadata 文档本身正常提供。',
  protocolRevision: '2025-06-18',
  kind: 'positive',
  guardsAgainst:
    '语料此前从未覆盖的**最贵的一条路径**：完整 legacy 握手（3 次）+ tools/list（4）+ tools/call（5）+ ' +
    'tools/call 的 401 challenge 引出的 resource_metadata 抓取（6）= 6 次出站请求。T6.9-F 第一轮实测全语料 38 条 ' +
    'fixture 的最大值只有 5，于是「未认领预算取 8 还剩多少余量」这个论证依据的是一个**读码得出、无 fixture 覆盖**的' +
    '上界 6——一个没有被任何东西钉住的数字。这条 fixture 把 6 变成实测值：probe.test.ts 的四路径计数表因此多出' +
    '第五行，预算若被调到 5 或更低，这条会立刻以「cascade 被截断」变红。' +
    '同时它守住一条判定语义：tools/call 被挡不得污染已经真实验证过的握手与 tools/list —— ' +
    'discovery_handshake / protocol_revision / tools_list 及其下游五项全部保留真实的 VERIFIED 结果，' +
    '只有 auth_metadata 从这次 401 的 challenge 与它指向的文档里得出结论。与 credential-gated-tools-list（挡清单、放调用）' +
    '成镜像，与 no-credentials-unverifiable-auth（modern、裸 401 无 challenge）互补：那条证明「看不见 metadata」是 ' +
    'UNVERIFIED，这条证明「看得见且自洽」才是 VERIFIED。',
  tools: CLEAN_TOOLS,
  createHandler: (): FetchHandler => {
    const base = legacyToolsCallGatedBaseHandler()
    return async (input, init) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
      // 与 createCredentialGatedEverywhereHandler 同一个处理：resource_metadata
      // 文档正常提供，让 auth_metadata 得到它真实的结论，而不是被这条 fixture
      // 自己的主题（tools/call 的凭据门）搅浑。它必须由这一层拦下——
      // createLegacyHandler 按 JSON-RPC method 路由，一个无 body 的 GET 会落进
      // 它的 default 分支返回一个 JSON-RPC 错误，那不是一份 metadata 文档。
      if (url.pathname === CREDENTIAL_GATE_METADATA_PATH) {
        return rawResponse(
          200,
          { 'content-type': 'application/json' },
          JSON.stringify({ resource: new URL(ENDPOINT).origin, authorization_servers: [`${new URL(ENDPOINT).origin}/oauth`] }),
        )
      }
      return base(input, init)
    }
  },
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

// ---- T86: when the probe still sends its reserved tool name ----

/** Names close to the reserved one but not it, plus a description that
 *  mentions it: only an exact `name` match withholds the call. */
const TOOLS_NEAR_MISS_NAMES = [
  ...CLEAN_TOOLS,
  { name: `${PROBE_RESERVED_TOOL_NAME}x`, description: 'Suffix variant.', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: PROBE_RESERVED_TOOL_NAME.toUpperCase(), description: 'Case variant.', inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
  { name: 'mention_only', description: `Not named ${PROBE_RESERVED_TOOL_NAME}.`, inputSchema: { type: 'object', properties: {}, additionalProperties: false } },
]

export const probeToolNameNearMissStillSent: Fixture = {
  id: 'probe-tool-name-near-miss-still-sent',
  description:
    '一个 modern 服务器：tools/list 完整（无 nextCursor），其中有与探测保留名相近但不相同的工具名（多一个后缀、大小写不同），' +
    '另有一个工具只在描述里提到这个名字。',
  protocolRevision: '2026-07-28',
  kind: 'positive',
  guardsAgainst:
    'T86 的反向：只有 name 与保留名逐字相等才不发 tools/call——不做大小写折叠、不去空白、不按前缀或子串匹配，也不看描述。' +
    '相近的名字不是同一个工具，这里 tools/call 照发，服务器照常以「未知工具」作答，整轮与干净基线一致。',
  tools: TOOLS_NEAR_MISS_NAMES,
  createHandler: () => createModernHandler(TOOLS_NEAR_MISS_NAMES),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const probeToolNameGatedToolsListStillSent: Fixture = {
  id: 'probe-tool-name-gated-tools-list-still-sent',
  description:
    '一个 modern 服务器：握手正常；tools/list 返回 401 + 合法 WWW-Authenticate: Bearer challenge，401 的 body 里带着一份含保留名的工具数组；' +
    'tools/call 同样是 401 + challenge，resource_metadata 文档正常提供。',
  protocolRevision: '2026-07-28',
  kind: 'positive',
  guardsAgainst:
    'T86 的凭据门控一支：tools/list 被 401 + challenge 挡住时 tools/call 照发，与 0.6.0 一致——auth_metadata 要靠这次' +
    '无凭据调用的 401 来观察，而未认证的调用在门控服务器上执行不到任何工具。401 的 body 是服务端自己不认的响应，' +
    '里面的工具名不构成「首页同名」（与 credential-gated-tools-list-with-tools-body 同一条原则）。',
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsListResponse: (id) =>
        rawResponse(
          401,
          { 'www-authenticate': CREDENTIAL_GATE_CHALLENGE, 'content-type': 'application/json' },
          JSON.stringify({ jsonrpc: '2.0', id, result: { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public', tools: TOOLS_WITH_RESERVED_NAME } }),
        ),
      toolsCallResponse: () => rawResponse(401, { 'www-authenticate': CREDENTIAL_GATE_CHALLENGE }, null),
      onOtherPath: (call) =>
        call.url.pathname === CREDENTIAL_GATE_METADATA_PATH
          ? rawResponse(
              200,
              { 'content-type': 'application/json' },
              JSON.stringify({ resource: new URL(ENDPOINT).origin, authorization_servers: [`${new URL(ENDPOINT).origin}/oauth`] }),
            )
          : undefined,
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: credentialGatedCascadeAssertions(['tools_list']),
}
