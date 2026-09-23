import type { Fixture, ExpectedAssertion, FetchHandler } from '../types.ts'
import { jsonRpcResult, jsonRpcError, rawResponse } from '../helpers.ts'
import {
  CLEAN_TOOLS,
  TOOLS_WITH_RESERVED_NAME,
  ENDPOINT,
  MIRROR_ENDPOINT,
  createModernHandler,
  createLegacyHandler,
  modernSampleRun,
  legacySampleRun,
  cleanBaselineAssertions,
  withOverride,
  withOverrides,
  latencyObserved,
  unclaimedDriftAssertions,
  type ModernHandlerOptions,
} from './shared.ts'
import { credentialGatedCascadeAssertions } from './positive.ts'

export const staleProtocolVersion: Fixture = {
  id: 'stale-protocol-version',
  description: '一个 legacy 握手完全正常，但 initialize 响应里声明的 protocolVersion 是一个从未在矩阵里出现过的旧字符串。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'PRD 点名的四类之一：stale version。探测器不能只要「声明了某个 revision 字符串」就判定通过——' +
    '必须真的对照 checks.json 的 revision_matrix 校验成员资格。discovery_handshake 依然 VERIFIED（握手机制本身走对了），' +
    '但 protocol_revision 必须 FAILED——这两个 check 是独立的，一个"握手做对了"不能掩盖"版本号本身不认识"。',
  tools: CLEAN_TOOLS,
  createHandler: () => createLegacyHandler(CLEAN_TOOLS, { protocolVersion: '2023-01-01' }),
  sampleRun: (handler) => legacySampleRun(handler, { protocolVersion: '2023-01-01' }),
  expectedAssertions: withOverride(cleanBaselineAssertions(), failedWith('protocol_revision', 'protocol_revision_unknown')),
}

export const toolsListIllegalStructure: Fixture = {
  id: 'tools-list-illegal-structure',
  description: '一个 modern 实现，tools/list 的 result.tools 不是数组，而是一个字符串。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    'tools_list 的核心职责：下游 agent 会直接解析这个结构，解析失败就是 FAILED，不是 OBSERVED_RISK 或 UNVERIFIED——' +
    '结构合法性是可以确定性判定的事实，不是"观察到风险"这种留有余地的判断。' +
    '同时证明指纹与 hygiene 检查在没有可用工具数据时正确地退到 UNVERIFIED，而不是对着非法数据硬算出一个假指纹。',
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsListResponse: (id) => jsonRpcResult(id, { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public', tools: 'not-an-array' }),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(
    cleanBaselineAssertions()
      .filter((a) => !['toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene'].includes(a.check_id))
      .concat(
        ['toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene'].map(
          (check_id): ExpectedAssertion => ({
            check_id,
            execution_status: 'SKIPPED',
            assertion_status: 'UNVERIFIED',
            reason: { key: 'tools_list_invalid_structure', params: {} },
          }),
        ),
      ),
    [failedWith('tools_list', 'tools_list_not_array', { status: 200 }), ...probeCallWithheld('probe_tool_name_unverifiable')],
  ),
}

export const legacyEverythingRequiresAuthStillFails: Fixture = {
  id: 'legacy-everything-requires-auth-still-fails',
  description:
    '一个真正不可匿名访问的服务器：server/discover、initialize、tools/list、tools/call 无一例外全部返回裸 401' +
    '（非 JSON-RPC body）——包括本应触发 legacy 回退之后的那次 initialize 本身也失败。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    '误报调查判责结论 (b)（droproom/mcp，2026-08-30）修复的反向验证：把 performHandshake 对 server/discover 的' +
    '回退触发条件从 `=== 400` 放宽到 `>= 400 && < 500` 之后，必须证明这次放宽只是"多给一次回退机会"，不是' +
    '"看到任何 4xx 就默认握手成功"——一个 initialize 本身也真的失败（同样返回 401）的服务器，回退尝试之后依然' +
    '必须落在 handshakeOk=false / discovery_handshake FAILED，fail-closed 语义不能被这次放宽出的更宽状态码范围' +
    '意外打开一个新洞。与 legacy-discover-401-unauthorized（同一次放宽的正例）配对，构成判责结论 (b) 要求的' +
    '双向负向测试。',
  createHandler: (): FetchHandler => async () => rawResponse(401, {}, null),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(
    cleanBaselineAssertions()
      .filter(
        (a) =>
          !['toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene', 'toolset_unchanged_vs_approved', 'schema_unchanged_vs_approved'].includes(
            a.check_id,
          ),
      )
      .concat(
        ['toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene', 'toolset_unchanged_vs_approved', 'schema_unchanged_vs_approved'].map(
          (check_id): ExpectedAssertion => ({
            check_id,
            execution_status: 'SKIPPED',
            assertion_status: 'UNVERIFIED',
            reason: { key: 'tools_list_invalid_structure', params: {} },
          }),
        ),
      ),
    [
      failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 401 }),
      revisionMissing(),
      failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 401 }),
      ...probeCallWithheld('probe_tool_name_unverifiable'),
    ],
  ),
}

export const errorResponseNonconformantShape: Fixture = {
  id: 'error-response-nonconformant-shape',
  description: '一个 modern 实现，discover / tools/list 都正常；触发一次安全的错误场景（调用不存在的工具）时，返回的是纯文本 500，不是 JSON-RPC 错误。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    'error_taxonomy：偏离协议定义的错误形状只记 OBSERVED_RISK，不是 FAILED——' +
    '错误形状不规范会让下游 agent 无法正确重试，这是"卫生问题"而不是"这个 server 坏了"，两者后果不同、判定也应该不同。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsCallResponse: () => rawResponse(500, { 'content-type': 'text/plain' }, 'Internal Server Error'),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  // T73: the signed reason records the class (not_json), the status and the
  // bounded media type — never the body text itself.
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('not_json', 500, 'text/plain')),
}

export const noCredentialsUnverifiableAuth: Fixture = {
  id: 'no-credentials-unverifiable-auth',
  description: '一个 modern 实现，discover / tools/list 完全公开；唯一一次触达受保护操作（tools/call）时收到裸 401，没有 WWW-Authenticate、没有 body。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    'auth_metadata 的 no_credential_status：完全无法观察到任何认证 metadata 时是 UNVERIFIED，不是 OBSERVED_RISK——' +
    '"看不见"和"看见了但不对"是两件不同的事，前者不能证明任何缺陷，只能说明我们没有凭据。' +
    '裸 401 本身是 HTTP 层在 JSON-RPC 处理之前就做的合法拒绝，不算协议错误形状问题，所以 error_taxonomy 不受影响，仍是 VERIFIED。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsCallResponse: () => rawResponse(401, {}, null),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), {
    check_id: 'auth_metadata',
    execution_status: 'COMPLETED',
    assertion_status: 'UNVERIFIED',
    reason: { key: 'auth_401_no_challenge', params: {} },
  }),
}

const OVERSIZED_PAYLOAD = 'x'.repeat(2_100_000) // > checks.json budget.max_body_bytes (2097152)

export const responseExceedsBudget: Fixture = {
  id: 'response-exceeds-budget',
  description: '一个 modern 实现，server/discover 正常响应；tools/list 返回一个超过 max_body_bytes（2 MiB）预算的巨大 body。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    'PRD 硬规则中最容易判错的一条：超预算必须是 execution_status=ERROR + assertion_status=UNVERIFIED，绝不能是 FAILED。' +
    '超时/超量不等于「这个 server 坏了」——也可能是我们这边的探测节点或网络问题。' +
    '同时证明「已完成的检查保留其结果」：discovery_handshake / protocol_revision / transport_type / latency_profile ' +
    '在 tools/list 撞上预算之前就已经 COMPLETED/VERIFIED 了，中止不应该把它们追溯性地清空——' +
    '「我们验证了协议握手，然后预算耗尽」是一句连贯诚实的陈述。只有真正没跑到、或依赖 tools/list 数据' +
    '（tools_list 本身及其下游）的 check 才退到 SKIPPED/UNVERIFIED，不允许在同一次 run 里对着还没跑到的东西' +
    '断言 VERIFIED 或 FAILED——那样发布出去的证据会自相矛盾。' +
    'T6.9-F 起这条同时是 reachability 位置的主对照：server/discover 拿到了一个完整的 HTTP 响应，' +
    '所以「endpoint 有没有应答」这个问题在预算中止之前就已经有答案了——reachability 是 COMPLETED/VERIFIED，' +
    '不再被后面 tools/list 的预算中止追溯改写。把断言搬回 try 块末尾，这条立刻变红。' +
    '没跑到的那些 check 带的理由也不再是通用的 probe_cascade_incomplete，而是中止本身的原因' +
    '（probe_budget_exhausted_body + 它的数值 params），读者因此能看到「为什么没跑」。',
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsListResponse: (id) => jsonRpcResult(id, { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public', junk: OVERSIZED_PAYLOAD }),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: (() => {
    // probe_budget_exhausted_body, not the generic probe_aborted fallback: this
    // fixture's real abort (an oversized tools/list response body) is our own
    // ProbeAborted(MAX_BODY_BYTES), and packages/checks/src/probe.ts's catch
    // block routes that to its own per-code key with numeric params — never
    // wire.ts's own Chinese prose message (see Task 8 / CLAUDE.md's params-
    // channel rule: params carries third-party diagnostic text only). This
    // fixture's OVERSIZED_PAYLOAD is sized against checks.json's
    // max_body_bytes budget (2097152, see the constant above).
    //
    // T6.9-F: 这同一个 reason 现在也是 cascade 的理由。中止是我们自己的
    // ProbeAborted，params 是一个小的数值记录，逐条挂到没跑到的 check 上既比
    // 通用的 probe_cascade_incomplete 信息量大，也不会把一段长度无上界的第三方
    // 文本复制十三份进签名载荷（那是 probe_aborted 那一支仍然保持通用理由的原因）。
    const abortedReason = { key: 'probe_budget_exhausted_body', params: { maxBodyBytes: 2_097_152 } }
    const verified = (check_id: string): ExpectedAssertion => ({ check_id, execution_status: 'COMPLETED', assertion_status: 'VERIFIED' })
    const skipped = (check_id: string): ExpectedAssertion => ({ check_id, execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: abortedReason })
    return [
      // 握手已经拿到一个完整的 HTTP 响应，reachability 在那一刻就为真；后面的
      // 预算中止只影响还没产出的检查（T6.9-F）。
      verified('reachability'),
      // 这四项在 tools/list 的请求触发预算中止之前就已经完成——必须保留，不能被追溯清空。
      verified('latency_profile'),
      verified('transport_type'),
      verified('protocol_revision'),
      verified('discovery_handshake'),
      // tools/list 本身撞上预算，从未真正完成；它和依赖它数据的 check 仍然是 SKIPPED/UNVERIFIED。
      skipped('tools_list'),
      skipped('error_taxonomy'),
      skipped('redirect_policy'),
      skipped('auth_metadata'),
      skipped('tool_description_hygiene'),
      skipped('toolset_fingerprint'),
      skipped('schema_fingerprint'),
      skipped('toolset_unchanged_vs_approved'),
      skipped('schema_unchanged_vs_approved'),
    ]
  })(),
}

export const redirectCrossHost: Fixture = {
  id: 'redirect-cross-host',
  description:
    `一个 modern 实现：对 ${ENDPOINT} 的 server/discover 返回 302，跳转到不同主机 ${MIRROR_ENDPOINT}。` +
    'MCP wire 协议的每一次调用都是 POST（见 packages/checks/src/protocol.ts），而 sendRequest 对非 GET' +
    '请求从不跟随重定向（P 任务）——这次 302 本身就是 server/discover 这一跳的终态响应，探测器从未真正' +
    '触达 mirror 主机，无论那里配置了什么。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    'redirect_policy：跨主机重定向被观察到就记 OBSERVED_RISK，且这次观察不依赖"是否真的跟过去看了一眼"——' +
    'server/discover 是握手的第一步，没跟随意味着这次握手从未拿到真实结果，discovery_handshake 与依赖它的 ' +
    'protocol_revision 因此是 FAILED，而不是"因为最终看起来没事就当作握手成功"。同一台服务器在同一主机上对 ' +
    'tools/list、tools/call 的正常应答（这条 fixture 特意保留了这一点）证明：重定向不跟随不是"整台服务器都不可用" ' +
    '——它是一次具体请求级别的、独立于其他请求结果的判定，两件事不能互相掩盖。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      onOtherPath: (call) =>
        call.url.hostname === new URL(ENDPOINT).hostname && call.jsonrpcMethod === 'server/discover'
          ? rawResponse(302, { location: MIRROR_ENDPOINT }, null)
          : undefined,
    }),
  // sendRequest 从不跟随非 GET 的重定向（P 任务），所以真实流量就是普通的 modernSampleRun 三连发——
  // discover 拿到 302 当终态，tools/list、tools/call 仍然打在原始 host 上并被正常应答，因为 onOtherPath
  // 只拦截了 server/discover。不再需要手写"跟随跳转到镜像主机"的采样逻辑，那段逻辑描述的是重定向被跟随
  // 时的旧行为，现在从未发生。
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(cleanBaselineAssertions(), [
    failedWith('discovery_handshake', 'handshake_discover_http_error', { status: 302 }),
    revisionMissing(),
    { check_id: 'redirect_policy', execution_status: 'COMPLETED', assertion_status: 'OBSERVED_RISK' },
  ]),
}

// ---- Credential-gate negative controls (the handshake-layer rule's red lines) ----
// The four fixtures below are that rule's acceptance-criteria negative cases
// (b)/(c)/(d) — (a), the droproom cause-5 shape (401, no WWW-Authenticate, JSON
// body), is already covered byte-for-byte by legacy-discover-401-unauthorized
// (positive.ts) and legacy-everything-requires-auth-still-fails (above), so no
// new fixture is added for it.

const CREDENTIAL_GATE_CASCADE_UNVERIFIED_CHECK_IDS = ['toolset_fingerprint', 'schema_fingerprint', 'tool_description_hygiene', 'toolset_unchanged_vs_approved', 'schema_unchanged_vs_approved']

/** T86: every caller is a tools/list that FAILED, so the probe also withholds
 *  its tools/call (it never saw the tool list) — see probeCallWithheld. */
function toolsListInvalidStructureCascade(base: ExpectedAssertion[]): ExpectedAssertion[] {
  const cascade = base
    .filter((a) => !CREDENTIAL_GATE_CASCADE_UNVERIFIED_CHECK_IDS.includes(a.check_id))
    .concat(
      CREDENTIAL_GATE_CASCADE_UNVERIFIED_CHECK_IDS.map(
        (check_id): ExpectedAssertion => ({ check_id, execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key: 'tools_list_invalid_structure', params: {} } }),
      ),
    )
  return withOverrides(cascade, probeCallWithheld('probe_tool_name_unverifiable'))
}

/** T86: the probe's tools/call uses a tool name it reserves for a tool that
 *  should not exist. When the server's tool list names it (collision), or we
 *  could not see the whole list (unverifiable), the call is not sent, and the
 *  two checks that read its one response are SKIPPED with that reason. Keys
 *  spelled out here, not imported from packages/checks, so a drift on either
 *  side turns probe.test.ts red. */
function probeCallWithheld(key: 'probe_tool_name_collision' | 'probe_tool_name_unverifiable'): ExpectedAssertion[] {
  return ['error_taxonomy', 'auth_metadata'].map((check_id): ExpectedAssertion => ({ check_id, execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: { key, params: {} } }))
}

export const forbidden403NotCredentialGated: Fixture = {
  id: 'forbidden-403-not-credential-gated',
  description:
    '一个服务端把每一个请求（server/discover、legacy initialize、tools/list、tools/call）都用 403 拒绝，body 是一段' +
    'JSON 但不是 JSON-RPC 错误形状；同时附带一个原本语法合法的 WWW-Authenticate: Bearer 头。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'credential-gate 规则（握手层）的红线：RFC 9110 没有为 403 定义质询头，403 与 WAF/地域封锁在结构上无法' +
    '区分——即便响应恰好带着一个语法合法的 WWW-Authenticate: Bearer 头（真实世界里这种配置错误确实存在），' +
    'classifyCredentialChallenge 的 status===401 硬约束也必须让它继续走既有的 FAILED 判定，不能被新出口吸收。' +
    '与 legacy-everything-requires-auth-still-fails（同样"全程被拒"但用的是 401）配对，专门证明这条红线只挂在' +
    '状态码上，不是"看到任何认证相关的头就豁免"。',
  createHandler: (): FetchHandler => async () => rawResponse(403, { 'www-authenticate': 'Bearer realm="mcp"' }, JSON.stringify({ error: 'forbidden' })),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 403 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 403 }),
  ]),
}

export const credentialChallengeEmptyHeaderNotExempted: Fixture = {
  id: 'credential-challenge-empty-header-not-exempted',
  description: '一个服务端把每一个请求都用裸 401 拒绝，WWW-Authenticate 头存在，但值是空字符串。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'credential-gate 规则（握手层）的红线之一：一个存在但为空字符串的 WWW-Authenticate 头不满足"至少一个' +
    'auth-scheme token"的判据，classifyCredentialChallenge 必须返回 null。与 legacy-everything-requires-auth-' +
    'still-fails（完全没有这个头）是两种不同的边界——droproom cause-5 修复放宽出的 4xx 回退窗口不能被这种' +
    '"头存在但是空的"半合法形状意外撑开一个新的豁免口，fail-closed 语义必须原样保留。',
  createHandler: (): FetchHandler => async () => rawResponse(401, { 'www-authenticate': '' }, null),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 401 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 401 }),
  ]),
}

export const credentialChallengeMalformedHeaderNotExempted: Fixture = {
  id: 'credential-challenge-malformed-header-not-exempted',
  description: '一个服务端把每一个请求都用裸 401 拒绝，WWW-Authenticate 头存在，但值不以合法的 auth-scheme token 开头（`="foo"`）。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'credential-gate 规则（握手层）的另一条红线：一个不以合法 RFC 9110 §5.6.2 token 开头的 WWW-Authenticate' +
    '值同样不满足判据，classifyCredentialChallenge 必须返回 null，不能被当作"看起来像认证相关"就放行。这条与' +
    '空字符串那条是两种不同的畸形——分别覆盖"头是空的"与"头有内容但语法不对"。',
  createHandler: (): FetchHandler => async () => rawResponse(401, { 'www-authenticate': '="foo"' }, null),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 401 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 401 }),
  ]),
}

/** `Bearer` HTAB `realm="mcp"` — the HTAB is built with String.fromCharCode so
 *  no editor, formatter or shell heredoc can silently turn it into a space and
 *  make this fixture stop testing what it says it tests. */
const HTAB_SEPARATOR_CHALLENGE = 'Bearer' + String.fromCharCode(9) + 'realm="mcp"'

export const credentialChallengeHtabSeparatorNotExempted: Fixture = {
  id: 'credential-challenge-htab-separator-not-exempted',
  description:
    '一个服务端把每一个请求都用裸 401 拒绝，WWW-Authenticate 以一个完全合法的 auth-scheme token 开头，' +
    '但 scheme 与 `realm` 之间用的是一个 HTAB 而不是 SP。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'Codex PR#19（round 11）指出的判据**过宽**的一面，也是这一轮阻塞合并的那一面：RFC 9110 §11.3 的 ' +
    'challenge 里，auth-scheme 与其后那一段之间的分隔符是 1*SP——只有 SP，从来不含 HTAB' +
    '（语法原文只写在 packages/checks 的 auth.ts 的 TCHAR_CLASS 注释里，这里只引用不复述）。' +
    '此前 classifyCredentialChallenge 把 scheme 之后的任何空白（含 HTAB）都当成合法分隔符，于是这条畸形头会拿到' +
    'credential-gated 豁免，把一个真实的 FAILED 换成 UNVERIFIED——正是这条规则的风险与边界情况一节点名的' +
    '"判据写宽"逃逸。判定必须与 credential-challenge-malformed-header-not-exempted 完全一致：' +
    '三条协议检查照旧 FAILED，不豁免。注意 list OWS 那条路径（逗号之前）**允许** HTAB，两者由后面是不是逗号区分——' +
    'credential-challenge-list-ows-before-comma 是那一面的正例。',
  createHandler: (): FetchHandler => async () => rawResponse(401, { 'www-authenticate': HTAB_SEPARATOR_CHALLENGE }, null),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 401 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 401 }),
  ]),
}

/** `Bearer realm="x<0x01>"` — the C0 control is built with String.fromCharCode
 *  for the same reason the HTAB above is: an escape sequence in source is the
 *  one thing an editor, formatter or heredoc can silently rewrite, and this
 *  fixture is entirely about which byte is inside the quoted-string. */
const QDTEXT_CONTROL_CHAR_CHALLENGE = 'Bearer realm="x' + String.fromCharCode(1) + '"'

export const credentialChallengeQdtextControlCharNotExempted: Fixture = {
  id: 'credential-challenge-qdtext-control-char-not-exempted',
  description:
    '一个服务端把每一个请求都用裸 401 拒绝，WWW-Authenticate 的 scheme、分隔符、参数名与等号全部合法，' +
    '只有 `realm` 的 quoted-string 值里夹了一个 C0 控制字符（%x01）。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'Codex PR#19（round 18）指出的判据**过宽**的又一面，与 round 11 的 1*SP 完全同向：quoted-string 的两个分支' +
    '此前写成"除引号和反斜杠外什么都行"和"反斜杠后什么都行"，比 RFC 9110 §5.6.4 的 qdtext / quoted-pair 宽——' +
    '两者都不含 HTAB 以外的 C0 控制字符，也不含 DEL。语法原文只写在 packages/checks 的 auth.ts 的 ' +
    'QUOTED_STRING_Y 注释里（审查纪律 #4），这里只引用不复述。这个形状是真能到达判据的：Headers 的字段值在它能容纳的八位组范围内只拒绝' +
    'NUL / LF / CR，一个 %x01 会原样穿过去。过宽的后果是一条畸形的第一条 challenge 拿到 credential-gated 豁免，' +
    '把一个真实的 FAILED 换成 UNVERIFIED / credential_required。判定必须与 ' +
    'credential-challenge-htab-separator-not-exempted 完全一致：三条协议检查照旧 FAILED，不豁免。',
  createHandler: (): FetchHandler => async () => rawResponse(401, { 'www-authenticate': QDTEXT_CONTROL_CHAR_CHALLENGE }, null),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 401 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 401 }),
  ]),
}

export const credentialChallengeMalformedRemainderNotExempted: Fixture = {
  id: 'credential-challenge-malformed-remainder-not-exempted',
  description:
    '一个服务端把每一个请求都用裸 401 拒绝，WWW-Authenticate 头以一个完全合法的 auth-scheme token 开头，' +
    '但 token 之后的部分是畸形的（`Bearer ???`）——既不是 token68，也不是 auth-param。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'Codex 在 PR#19 上提的 P2（round 6）：判据此前只校验开头的 auth-scheme token，token 之后的内容一概不看，' +
    '于是 `Bearer ???` 这类"开头合法、余下畸形"的头会被当成合法质询，把一个真实的 FAILED 换成 ' +
    'UNVERIFIED（credential_required）——正是 credential-gate 规则的风险与边界情况一节警告的"判据写宽"逃逸。' +
    '既有的两条畸形反例都落在 token 之前（空字符串、`="foo"` 不以合法 token 开头），token **之后**的畸形' +
    '此前没有任何 fixture 或测试覆盖。这条 fixture 是语料级的证据：classifyCredentialChallenge 现在完整校验' +
    '第一条 challenge（scheme 独立成条，或 scheme + 完整 token68，或 scheme + 若干格式完好的 auth-param），' +
    'discovery_handshake / protocol_revision / tools_list 照旧记 FAILED，不豁免。' +
    '与 credential-gated-handshake（同样全程 401，但带一条真正合法的质询）配对，证明这条出口挂的是' +
    '"质询结构完整"，不是"看到 Bearer 这个词"。',
  createHandler: (): FetchHandler => async () => rawResponse(401, { 'www-authenticate': 'Bearer ???' }, null),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 401 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 401 }),
  ]),
}

function recognizedModernErrorResponse(id: unknown): Response {
  return jsonRpcError(id, -32020, 'HeaderMismatchError', { status: 400 })
}

export const recognizedModernErrorCodeUnchanged: Fixture = {
  id: 'recognized-modern-error-code-unchanged',
  description:
    '一个 modern 实现：server/discover、tools/list、tools/call 全部返回 HTTP 400 + 已识别的现代 JSON-RPC 错误码' +
    '-32020（HeaderMismatchError）——2026-07-28 规范为「现代服务器主动拒绝了这次具体请求」保留的三个错误码之一。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'RECOGNIZED_MODERN_ERROR_CODES 分支此前从未被任何 fixture 覆盖过（protocol.ts 自己的注释也这样写：' +
    '"No fixture currently exercises this branch"）。这条 fixture 证明的是分支归属本身：一个被识别为现代错误的' +
    '4xx 不会被误当成 legacy 回退信号（这条分支从不回退）——discovery_handshake / protocol_revision / tools_list' +
    '照旧记 FAILED（credential-gate 规则（握手层）第 4 条："4xx + JSON-RPC 已识别错误码走既有 modern 分支，' +
    '不变"）。**这条 fixture 用的是 HTTP 400，不带 WWW-Authenticate 头，所以它并不能证明"credential-gated 出口' +
    '不会豁免一个已识别的现代错误"——classifyCredentialChallenge 本身就要求 status===401，400 在状态码这一步就已经' +
    '被挡掉，credentialChallenge 从未被计算过，不是"计算出来又被正确忽略"。真正验证那条边界（401 + 合法' +
    'WWW-Authenticate + 已识别错误码同时成立）的是下面的 recognizedModernErrorCodeAt401NotExempted（Lead finding' +
    ' B4，round 3；此前这条 fixture 的说明文字曾经声称覆盖了这个边界，但从未真的验证过，round 3 已改正措辞）。**',
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      discoverResponse: recognizedModernErrorResponse,
      toolsListResponse: recognizedModernErrorResponse,
      toolsCallResponse: recognizedModernErrorResponse,
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_discover_rejected', { status: 400, jsonrpc_error_code: -32020 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_jsonrpc_error', { status: 400, jsonrpc_error_code: -32020 }),
  ]),
}

function recognizedModernErrorResponseChallenged(id: unknown): Response {
  return rawResponse(
    401,
    { 'content-type': 'application/json', 'www-authenticate': 'Bearer realm="mcp"' },
    JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32020, message: 'HeaderMismatchError' } }),
  )
}

export const recognizedModernErrorCodeAt401NotExempted: Fixture = {
  id: 'recognized-modern-error-code-401-not-exempted',
  description:
    '一个 modern 实现：server/discover、tools/list、tools/call 全部返回 HTTP 401 + 已识别的现代 JSON-RPC 错误码' +
    '-32020（HeaderMismatchError），且同时带着一个语法合法的 WWW-Authenticate: Bearer 头。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    'Lead finding B4（round 3）指出的可证伪输入：让 classifyCredentialChallenge 判据的每一个从句都成立——状态码 401、' +
    'WWW-Authenticate 头语法合法、且这条响应确实是决定握手结果的那次响应——同时它的 body 仍然是' +
    'RECOGNIZED_MODERN_ERROR_CODES 里的一个已识别错误码。protocol.ts 的 performHandshake 必须先看 body 认出这是' +
    '"现代服务器主动拒绝了这次具体请求"，再落到既有 modern 分支（不生成 credentialChallenge），discovery_handshake /' +
    'protocol_revision 照旧 FAILED，不是 UNVERIFIED。tools_list 层没有这条 body 层面的豁免——performToolsList 只看' +
    '状态码和头、从不检查 body 里的错误码——但 round 3 的 B6 修复（tools-list-layer 分支要求 handshake.handshakeOk）' +
    '让它在 handshakeOk 已经是 false 的这条路径上同样落回既有的 FAILED 分支，不会被误判成 credential-gated。' +
    '这条 fixture 是这个具体边界（401 + 已识别错误码同时成立）此前完全没有覆盖的真实证据——' +
    'recognized-modern-error-code-unchanged 用的是 400，从未真正到达 classifyCredentialChallenge。',
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      discoverResponse: recognizedModernErrorResponseChallenged,
      toolsListResponse: recognizedModernErrorResponseChallenged,
      toolsCallResponse: recognizedModernErrorResponseChallenged,
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  // T86: tools/list FAILED here, so the tools/call that auth_metadata and
  // error_taxonomy read is never sent (toolsListInvalidStructureCascade).
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_discover_rejected', { status: 401, jsonrpc_error_code: -32020 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_challenge_after_failed_handshake'),
  ]),
}

// ---- T6.9-A1：目标说「稍后再来」时退避 ----
//
// 四条一组，缺一不可：前三条钉住「必须退避」的三种触发形状，第四条钉住
// 「503 不带 Retry-After 不是退避信号」这条同样被裁定过的边界。没有第四条，
// 一个把 503 一律当限流的实现（判定写反）会让前三条全绿。

/** 429 / 带 Retry-After 的 503 一律在第一次响应上就中止：探测器绝不能对一台刚说
 *  「你太快了」的目标回头再发一轮握手（protocol.ts 的 legacy 回退正是这么一轮）。
 *  于是除了无条件先行判定的 tls_certificate 之外，一条 check 都没跑到。 */
function rateLimitedCascade(reason: { key: string; params: Record<string, string | number> }): ExpectedAssertion[] {
  // T6.9-F：没跑到的检查带的是中止本身的理由（probe_rate_limited），不再是通用的
  // probe_cascade_incomplete —— 这是一次我们自己的 ProbeAborted，理由具体且 params
  // 是小的数值记录。这里 reachability 仍然是 ERROR/UNVERIFIED：限流在**第一个**
  // 请求上就中止了，performHandshake 从未返回，所以「endpoint 有没有应答」这个
  // 问题在本轮里确实没有答案。与 response-exceeds-budget 恰好成对——那条的握手
  // 拿到了响应，这条没有。
  const skipped = (check_id: string): ExpectedAssertion => ({
    check_id,
    execution_status: 'SKIPPED',
    assertion_status: 'UNVERIFIED',
    reason,
  })
  return [
    { check_id: 'reachability', execution_status: 'ERROR', assertion_status: 'UNVERIFIED', reason },
    ...[
      'latency_profile',
      'transport_type',
      'protocol_revision',
      'discovery_handshake',
      'tools_list',
      'error_taxonomy',
      'redirect_policy',
      'auth_metadata',
      'tool_description_hygiene',
      'toolset_fingerprint',
      'schema_fingerprint',
      'toolset_unchanged_vs_approved',
      'schema_unchanged_vs_approved',
    ].map(skipped),
  ]
}

const RATE_LIMIT_GUARD_SHARED =
  '这一整组守的是一条当时正在生产上发生的行为：429 落进 performHandshake 的 `status >= 400 && < 500` 通用分支，' +
  '该分支末尾回退到 performLegacyHandshake——也就是对一台刚说「你太快了」的目标，回头再发一轮握手请求。' +
  '中止必须发生在 wire.ts 的 sendRequest 里（本包唯一的出站包装，no-direct-fetch.test.ts 结构性保证了' +
  '这一点），这样「本轮零后续请求」就不是每个调用方各自要记得遵守的约定，而是抛出即成立的事实。' +
  '同时：超预算/被限流一律 execution_status=ERROR + assertion_status=UNVERIFIED，绝不是 FAILED——' +
  '「对方让我们晚点再来」不是「这个 server 坏了」。'

export const rateLimited429NoRetryAfter: Fixture = {
  id: 'rate-limited-429-no-retry-after',
  description: '一个对 server/discover 直接返回裸 HTTP 429（无 body、不带 Retry-After）的目标。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    RATE_LIMIT_GUARD_SHARED +
    '本条专管「429 一律退避」里的**一律**：没有 Retry-After 并不使 429 变得可以继续打——' +
    '缺的只是「多久之后」这个提示，不是「要不要停」这个判断。',
  createHandler: (): FetchHandler => async () => rawResponse(429, {}, null),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: rateLimitedCascade({ key: 'probe_rate_limited', params: { status: 429 } }),
}

export const rateLimited429WithRetryAfter: Fixture = {
  id: 'rate-limited-429-retry-after',
  description: '一个对 server/discover 返回 HTTP 429 且带 `Retry-After: 3600` 的目标。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    RATE_LIMIT_GUARD_SHARED +
    '本条额外钉住 Retry-After 的解析结果确实进了这次 run 的证据里（reason.params.retryAfterSeconds = 3600），' +
    '而不是被读出来用完就丢——调度侧据以顺延 next_run_at 的那个数，必须与签名记录里写着的是同一个。' +
    '3600 秒这个值同时可以直接用作调度侧的红证输入：任何短于 1 小时的正常探测间隔遇到它都必须真的顺延到 ' +
    '≥1 小时之后，而不是照常按原间隔进行。',
  createHandler: (): FetchHandler => async () => rawResponse(429, { 'retry-after': '3600' }, null),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: rateLimitedCascade({ key: 'probe_rate_limited', params: { status: 429, retryAfterSeconds: 3600 } }),
}

export const rateLimited503WithRetryAfter: Fixture = {
  id: 'rate-limited-503-with-retry-after',
  description: '一个对 server/discover 返回 HTTP 503 且带 `Retry-After: 3600` 的目标。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    RATE_LIMIT_GUARD_SHARED +
    '本条钉住裁定的另一半：503 **带** Retry-After 时按 429 同等处理。带上 Retry-After 的 503 已经指名了' +
    '「什么时候回来」，那就是一次限流意图的表达，不再只是一次瞬时故障。与 ' +
    'service-unavailable-503-no-retry-after-not-rate-limited 配对，两条一起把 503 的判据钉成' +
    '「看头，不看状态码」——只有其中一条时，把 503 一律当限流或一律不当限流都能全绿。' +
    'Retry-After 取 3600（与 429 那条同值）是为了让这条 fixture 直接可用作调度侧的红证：' +
    '一个短于任何档位正常探测间隔的 Retry-After，无论套用哪个档位算出来都等于该档位本来的间隔，' +
    '拿它做断言等于什么都没断言。解析值本身不被硬编码这一点，由 wire.test.ts 的 ' +
    'parseRetryAfterSeconds 对照表（3600 / 120 / 30 / 0 / 非法输入）单独钉住。',
  createHandler: (): FetchHandler => async () => rawResponse(503, { 'retry-after': '3600' }, null),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: rateLimitedCascade({ key: 'probe_rate_limited', params: { status: 503, retryAfterSeconds: 3600 } }),
}

export const serviceUnavailable503NoRetryAfterNotRateLimited: Fixture = {
  id: 'service-unavailable-503-no-retry-after-not-rate-limited',
  description:
    '一个对每一个请求（server/discover、tools/list、tools/call）都返回裸 HTTP 503（无 body、**不带** Retry-After）的目标。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    '把 503 的裁定实现反的唯一可证伪输入。规则是「503 只在带 Retry-After 时按 429 处理；不带 ' +
    'Retry-After 的 503 维持现状」——理由是 Service Unavailable 不带 Retry-After 时通常只是瞬时故障，' +
    '不是限流意图。所以这条 fixture 必须**跑完整轮**：reachability 是 COMPLETED/VERIFIED（本轮没有被中止），' +
    '判定照旧落在 discovery_handshake / protocol_revision / tools_list 的 FAILED 上（T86 起 tools/list 失败即不发 ' +
    'tools/call，error_taxonomy / auth_metadata 记 SKIPPED）。一旦有人把退避判据写成' +
    '「429 或 503」，这条立刻变红：reachability 会变成 ERROR/UNVERIFIED。' +
    '这条同时守住调度侧：维持现状意味着 next_run_at 照常按档位推进，不被 Retry-After 顺延。',
  createHandler: (): FetchHandler => async () => rawResponse(503, {}, null),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [
    failedWith('discovery_handshake', 'handshake_discover_http_error', { status: 503 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 503 }),
  ]),
}

// ---- T73: error_taxonomy records WHAT the unknown-tool response was ----

/** The expected error_taxonomy OBSERVED_RISK assertion with its signed reason
 *  ref. Spelled out here from the rule table (packages/checks/src/
 *  error-taxonomy.ts classifyUnknownToolResponse), not imported from
 *  packages/checks, so a drift on either side turns probe.test.ts red. */
function errorTaxonomyRisk(cls: string, status: number, mediaType: string, jsonrpcErrorCode?: number): ExpectedAssertion {
  return {
    check_id: 'error_taxonomy',
    execution_status: 'COMPLETED',
    assertion_status: 'OBSERVED_RISK',
    reason: {
      key: `error_taxonomy_${cls}`,
      params: {
        scenario: 'tools_call_unknown_tool',
        status,
        media_type: mediaType,
        ...(jsonrpcErrorCode === undefined ? {} : { jsonrpc_error_code: jsonrpcErrorCode }),
      },
    },
  }
}

const UNKNOWN_TOOL_IS_ERROR_RESULT = { content: [{ type: 'text', text: 'Unknown tool' }], isError: true }

const ERROR_TAXONOMY_GUARD_SHARED =
  'error_taxonomy 的判定不变（仍是 OBSERVED_RISK，不是 FAILED），变的是签名记录里多了一个有界分类：' +
  '同一个 OBSERVED_RISK 背后是哪一种响应，今后能从记录本身读出来，而不必重新探测。分类只取常量' +
  '（类名、HTTP 状态码、六选一的 media_type、可选的整数 error code），任何第三方原文都不进记录。'

export const errorTaxonomyResultIsErrorJson: Fixture = {
  id: 'error-taxonomy-result-is-error-json',
  description: '一个 modern 实现，调用不存在的工具时以 HTTP 200 + application/json 返回一个普通 result，其中 isError: true。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    ERROR_TAXONOMY_GUARD_SHARED +
    '本条钉住最常见的一类混淆：把「未知工具」当成工具执行错误（result.isError），而规范把它列为协议错误' +
    '（JSON-RPC error）。分类必须是 result_is_error，而不是 result_ok——isError 只认严格布尔 true。',
  tools: CLEAN_TOOLS,
  createHandler: () => createModernHandler(CLEAN_TOOLS, { toolsCallResponse: (id) => jsonRpcResult(id, UNKNOWN_TOOL_IS_ERROR_RESULT) }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('result_is_error', 200, 'application/json')),
}

export const errorTaxonomyResultIsErrorSse: Fixture = {
  id: 'error-taxonomy-result-is-error-sse',
  description: '同上，但响应以 text/event-stream 分帧：一个 event: message 事件，data 里是 isError: true 的 result。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    ERROR_TAXONOMY_GUARD_SHARED +
    '本条钉住分类与判定读的是同一组候选：SSE 分帧的 body 要先拆出 data 载荷再分类。若分类器对整个 body 做 ' +
    'JSON.parse，这里会被误记成 not_json；若它不看 isError，会被误记成 result_ok。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsCallResponse: (id) =>
        rawResponse(
          200,
          { 'content-type': 'text/event-stream' },
          `event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id, result: UNKNOWN_TOOL_IS_ERROR_RESULT })}\n\n`,
        ),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('result_is_error', 200, 'text/event-stream')),
}

export const errorTaxonomyResultOk: Fixture = {
  id: 'error-taxonomy-result-ok',
  description: '一个 modern 实现，对不存在的工具名返回 HTTP 200 + 一个没有 isError 的成功 result。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    ERROR_TAXONOMY_GUARD_SHARED +
    '本条与 error-taxonomy-result-is-error-json 配对：只有其中一条时，把 result_is_error 与 result_ok 合并成一类' +
    '（或把 isError 的判据写成「存在即可」）都能全绿。',
  tools: CLEAN_TOOLS,
  createHandler: () => createModernHandler(CLEAN_TOOLS, { toolsCallResponse: (id) => jsonRpcResult(id, { content: [] }) }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('result_ok', 200, 'application/json')),
}

export const errorTaxonomyNotJsonrpc: Fixture = {
  id: 'error-taxonomy-not-jsonrpc',
  description: '一个 modern 实现，对不存在的工具名返回 HTTP 400 + application/json，body 是一个不含 jsonrpc 字段的普通 JSON 对象。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    ERROR_TAXONOMY_GUARD_SHARED +
    '本条钉住 not_jsonrpc 与 not_json 的分界：body 是合法 JSON，只是不是 JSON-RPC 消息。若分类器把' +
    '「解析器不接受」直接等同于「不是 JSON」，这里会被误记成 not_json。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsCallResponse: () => rawResponse(400, { 'content-type': 'application/json' }, JSON.stringify({ error: 'unknown tool' })),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('not_jsonrpc', 400, 'application/json')),
}

export const errorTaxonomyJsonrpcMalformed: Fixture = {
  id: 'error-taxonomy-jsonrpc-malformed',
  description: '一个 modern 实现，对不存在的工具名返回 jsonrpc "2.0" 的 error 对象，code 是整数 -32602，但缺少必需的 message。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    ERROR_TAXONOMY_GUARD_SHARED +
    '本条钉住 jsonrpc_malformed 及其唯一的可选证据 jsonrpc_error_code：缺 message 的 error 不是格式正确的 ' +
    'JSON-RPC error（判定仍是 OBSERVED_RISK），而它的 code 是安全整数，所以要被记下。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsCallResponse: (id) => rawResponse(200, { 'content-type': 'application/json' }, JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32602 } })),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('jsonrpc_malformed', 200, 'application/json', -32602)),
}

export const errorTaxonomyEventStreamNoData: Fixture = {
  id: 'error-taxonomy-event-stream-no-data',
  description: '一个 modern 实现，对不存在的工具名返回 HTTP 200 + text/event-stream，body 只有一行 ": ping" 注释，没有任何 data 事件。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    ERROR_TAXONOMY_GUARD_SHARED +
    '本条钉住 event_stream_no_data：body 不为空（所以不是 empty_body），但按判定自己的 SSE 规则拆不出任何 data ' +
    '载荷。若分类器在 SSE 下退回去解析整个 body，这里会被误记成 not_json。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsCallResponse: () => rawResponse(200, { 'content-type': 'text/event-stream' }, ': ping\n\n'),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('event_stream_no_data', 200, 'text/event-stream')),
}

export const errorTaxonomyEmptyBody: Fixture = {
  id: 'error-taxonomy-empty-body',
  description: '一个 modern 实现，握手与 tools/list 正常；调用不存在的工具时返回裸 HTTP 503，没有 body，也没有 Content-Type。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    ERROR_TAXONOMY_GUARD_SHARED +
    '本条钉住 empty_body 一类。此前由 service-unavailable-503-no-retry-after-not-rate-limited 顺带钉住；' +
    'T86 起那条的 tools/list 失败、tools/call 不再发送，所以这一类改由本条专门钉住。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(CLEAN_TOOLS, {
      toolsCallResponse: () => rawResponse(503, {}, null),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), errorTaxonomyRisk('empty_body', 503, 'none')),
}

// ---- T73b: every FAILED protocol / fingerprint assertion records WHY ----

/** A FAILED expectation with its signed reason ref. Keys and params are
 *  spelled out here from the rule tables (packages/checks/src/protocol.ts
 *  FailureReason, probe.ts's protocol_revision split, fingerprint.ts), not
 *  imported from packages/checks, so a drift on either side turns
 *  probe.test.ts red. `params: {}` means the signed reason carries none. */
function failedWith(check_id: string, key: string, params: Record<string, number> = {}): ExpectedAssertion {
  return { check_id, execution_status: 'COMPLETED', assertion_status: 'FAILED', reason: { key, params } }
}

/** Every handshake that ends without a version: nothing to compare. */
function revisionMissing(): ExpectedAssertion {
  return failedWith('protocol_revision', 'protocol_revision_missing')
}

const FAILED_REASON_GUARD_SHARED =
  'T73b：判定不变（同一输入仍是同一个 FAILED），变的是签名记录里多了一个有界原因：同一个 FAILED 背后是哪一种' +
  '失败，今后能从记录本身读出来，而不必重新探测。原因只取常量（key、HTTP 状态码、可选的安全整数 error code），' +
  '任何第三方原文都不进记录。'

const HTML_PAGE = '<html><body><h1>MCP endpoint</h1></body></html>'

function modernDiscoverFails(
  id: string,
  description: string,
  guard: string,
  discoverResponse: (rpcId: unknown) => Response,
  handshake: ExpectedAssertion,
): Fixture {
  return {
    id,
    description,
    protocolRevision: null,
    kind: 'negative',
    guardsAgainst: FAILED_REASON_GUARD_SHARED + guard,
    tools: CLEAN_TOOLS,
    createHandler: () => createModernHandler(CLEAN_TOOLS, { discoverResponse }),
    sampleRun: (handler) => modernSampleRun(handler),
    // tools/list still runs after a failed handshake and this server answers it
    // normally, so only the two handshake-derived checks move.
    expectedAssertions: withOverrides(cleanBaselineAssertions(), [handshake, revisionMissing()]),
  }
}

export const handshakeDiscoverNotJsonrpc = modernDiscoverFails(
  'handshake-discover-not-jsonrpc',
  '一个服务器对 server/discover 返回 HTTP 200 + 一张 text/html 页面；其余请求按 modern 正常应答。',
  '本条钉住 200 分支的第一类：响应体根本读不成 JSON-RPC 消息。',
  () => rawResponse(200, { 'content-type': 'text/html' }, HTML_PAGE),
  failedWith('discovery_handshake', 'handshake_discover_not_jsonrpc'),
)

export const handshakeDiscoverJsonrpcError = modernDiscoverFails(
  'handshake-discover-jsonrpc-error',
  '一个 legacy 风格的服务器对 server/discover 返回 HTTP 200 + JSON-RPC error -32601（Method not found）。',
  '本条钉住 200 分支的第二类，也是 TODO 209 那 41 条要回答的形状：200 + JSON-RPC error 不触发回退（回退只在 4xx），' +
    '记下安全整数 error code。若分类器把它并进「不是 JSON-RPC」或「没有 supportedVersions」，这里会红。',
  (rpcId) => jsonRpcError(rpcId, -32601, 'Method not found'),
  failedWith('discovery_handshake', 'handshake_discover_jsonrpc_error', { jsonrpc_error_code: -32601 }),
)

export const handshakeDiscoverNoSupportedVersions = modernDiscoverFails(
  'handshake-discover-no-supported-versions',
  '一个服务器对 server/discover 返回 HTTP 200 + JSON-RPC result，但 supportedVersions 是空数组。',
  '本条钉住 200 分支的第三类：是 JSON-RPC result，只是没有可用的 supportedVersions（空数组的第一项不是字符串）。',
  (rpcId) => jsonRpcResult(rpcId, { resultType: 'complete', supportedVersions: [], capabilities: { tools: {} } }),
  failedWith('discovery_handshake', 'handshake_discover_no_supported_versions'),
)

export const handshakeDiscoverRejected = modernDiscoverFails(
  'handshake-discover-rejected',
  '一个 modern 服务器对 server/discover 返回 HTTP 400 + 已识别的现代错误码 -32022（UnsupportedProtocolVersion）；其余请求正常。',
  '本条钉住 4xx + 已识别错误码这一支：不回退，记下 status 与 error code（这一支的 code 恒为三个已识别码之一）。',
  (rpcId) => jsonRpcError(rpcId, -32022, 'UnsupportedProtocolVersionError', { status: 400 }),
  failedWith('discovery_handshake', 'handshake_discover_rejected', { status: 400, jsonrpc_error_code: -32022 }),
)

export const handshakeDiscoverHttpError = modernDiscoverFails(
  'handshake-discover-http-error',
  '一个服务器对 server/discover 返回 HTTP 202 且没有 body；其余请求按 modern 正常应答。',
  '本条钉住「既不是 200 也不是 4xx」那一支里最容易被漏看的一格：200 以外的 2xx 也落在这里，而不是被当成成功。',
  () => rawResponse(202, {}, null),
  failedWith('discovery_handshake', 'handshake_discover_http_error', { status: 202 }),
)

function legacyInitializeFails(
  id: string,
  description: string,
  guard: string,
  initializeResponse: (rpcId: unknown) => Response,
  handshake: ExpectedAssertion,
): Fixture {
  return {
    id,
    description,
    protocolRevision: null,
    kind: 'negative',
    guardsAgainst: FAILED_REASON_GUARD_SHARED + guard,
    tools: CLEAN_TOOLS,
    // omitSessionId: the failed initialize mints no session, and this server
    // (like mcp.deepwiki.com) does not require one — so tools/list still
    // succeeds and only the two handshake-derived checks move.
    createHandler: () => createLegacyHandler(CLEAN_TOOLS, { omitSessionId: true, initializeResponse }),
    sampleRun: (handler) => legacySampleRun(handler),
    expectedAssertions: withOverrides(cleanBaselineAssertions(), [handshake, revisionMissing()]),
  }
}

export const handshakeInitializeHttpError = legacyInitializeFails(
  'handshake-initialize-http-error',
  '一个 legacy 服务器：server/discover 回 400 触发回退，initialize 本身返回 HTTP 500 纯文本。',
  '本条钉住 initialize 的第一类：状态码不是 200，记下 status（不论 body 长什么样）。',
  () => rawResponse(500, { 'content-type': 'text/plain' }, 'Internal Server Error'),
  failedWith('discovery_handshake', 'handshake_initialize_http_error', { status: 500 }),
)

export const handshakeInitializeNotJsonrpc = legacyInitializeFails(
  'handshake-initialize-not-jsonrpc',
  '一个 legacy 服务器：回退后的 initialize 返回 HTTP 200 + 一张 text/html 页面。',
  '本条钉住 initialize 的第二类：200，但响应体读不成 JSON-RPC 消息。',
  () => rawResponse(200, { 'content-type': 'text/html' }, HTML_PAGE),
  failedWith('discovery_handshake', 'handshake_initialize_not_jsonrpc'),
)

export const handshakeInitializeJsonrpcError = legacyInitializeFails(
  'handshake-initialize-jsonrpc-error',
  '一个 legacy 服务器：回退后的 initialize 返回 HTTP 200 + JSON-RPC error -32602。',
  '本条钉住 initialize 的第三类：200 + JSON-RPC error，记下安全整数 error code。',
  (rpcId) => jsonRpcError(rpcId, -32602, 'Unsupported protocol version'),
  failedWith('discovery_handshake', 'handshake_initialize_jsonrpc_error', { jsonrpc_error_code: -32602 }),
)

export const handshakeInitializeNoProtocolVersion = legacyInitializeFails(
  'handshake-initialize-no-protocol-version',
  '一个 legacy 服务器：回退后的 initialize 返回 HTTP 200 + JSON-RPC result，但 result 里没有 protocolVersion。',
  '本条钉住 initialize 的第四类：是 JSON-RPC result，只是没有字符串类型的 protocolVersion。',
  (rpcId) => jsonRpcResult(rpcId, { capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'notes-mcp', version: '1.4.0' } }),
  failedWith('discovery_handshake', 'handshake_initialize_no_protocol_version'),
)

export const handshakeAckHttpError: Fixture = {
  id: 'handshake-ack-http-error',
  description: '一个 legacy 服务器：initialize 正常（2025-06-18），但对 notifications/initialized 返回 HTTP 400 纯文本。',
  protocolRevision: '2025-06-18',
  kind: 'negative',
  guardsAgainst:
    FAILED_REASON_GUARD_SHARED +
    '本条钉住握手的最后一步：initialize 已给出版本，只有 notifications/initialized 没拿到 2xx。protocol_revision ' +
    '因此仍是 VERIFIED（版本在矩阵里），只有 discovery_handshake 是 FAILED——两者独立。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createLegacyHandler(CLEAN_TOOLS, { initializedNotificationResponse: () => rawResponse(400, { 'content-type': 'text/plain' }, 'Bad Request') }),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), failedWith('discovery_handshake', 'handshake_ack_http_error', { status: 400 })),
}

export const protocolRevisionMissing: Fixture = {
  id: 'protocol-revision-missing',
  description: '一个 modern 服务器：server/discover 成功，但 supportedVersions 的第一项是空字符串 ""。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    FAILED_REASON_GUARD_SHARED +
    '本条钉住 protocol_revision 的「缺失」一支按假值判断，而不是只看 null：握手本身 VERIFIED（第一项是字符串），' +
    '但空字符串不是一个可比对的版本。这是 missing 唯一一个不与握手失败同时出现的格子。',
  tools: CLEAN_TOOLS,
  createHandler: () => createModernHandler(CLEAN_TOOLS, { protocolVersion: '' }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), revisionMissing()),
}

export const protocolRevisionUnknown: Fixture = {
  id: 'protocol-revision-unknown',
  description: '一个 modern 服务器：server/discover 成功，supportedVersions 的第一项是矩阵里没有的 "2099-01-01"。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst:
    FAILED_REASON_GUARD_SHARED +
    '本条钉住 protocol_revision 的「不认识」一支（modern 路径；stale-protocol-version 是 legacy 路径）：' +
    '签名记录里只有 key，声明的版本字符串本身（第三方文本）与其长度都不记。',
  tools: CLEAN_TOOLS,
  createHandler: () => createModernHandler(CLEAN_TOOLS, { protocolVersion: '2099-01-01' }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), failedWith('protocol_revision', 'protocol_revision_unknown')),
}

function toolsListFails(id: string, description: string, guard: string, opts: ModernHandlerOptions, overrides: ExpectedAssertion[]): Fixture {
  return {
    id,
    description,
    protocolRevision: overrides.some((o) => o.check_id === 'discovery_handshake') ? null : '2026-07-28',
    kind: 'negative',
    guardsAgainst: FAILED_REASON_GUARD_SHARED + guard,
    createHandler: () => createModernHandler(CLEAN_TOOLS, opts),
    sampleRun: (handler) => modernSampleRun(handler),
    expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), overrides),
  }
}

export const toolsListChallengeAfterFailedHandshake = toolsListFails(
  'tools-list-challenge-after-failed-handshake',
  '一个服务器：server/discover 返回 HTTP 500；tools/list 返回 401 + 合法的 WWW-Authenticate: Bearer，body 却是一份结构完好的工具列表。',
  '本条钉住 finding B6 那一格：tools/list 的 challenge 只在握手成功时才算凭据门控；握手已失败时它落在 FAILED，' +
    '原因是 challenge 本身，而不是 body（body 在这里甚至是合法的 tools 数组）。',
  {
    discoverResponse: () => rawResponse(500, { 'content-type': 'text/plain' }, 'Internal Server Error'),
    toolsListResponse: (rpcId) =>
      rawResponse(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer realm="mcp"' }, JSON.stringify({ jsonrpc: '2.0', id: rpcId, result: { tools: CLEAN_TOOLS } })),
  },
  [
    failedWith('discovery_handshake', 'handshake_discover_http_error', { status: 500 }),
    revisionMissing(),
    failedWith('tools_list', 'tools_list_challenge_after_failed_handshake'),
  ],
)

export const toolsListNotJsonrpc = toolsListFails(
  'tools-list-not-jsonrpc',
  '一个 modern 服务器：握手正常，tools/list 返回 HTTP 502 + 一张 text/html 页面。',
  '本条钉住 tools/list 的「读不成 JSON-RPC」一支，并记下 status。',
  { toolsListResponse: () => rawResponse(502, { 'content-type': 'text/html' }, '<html><body><h1>Bad Gateway</h1></body></html>') },
  [failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 502 })],
)

export const toolsListJsonrpcError = toolsListFails(
  'tools-list-jsonrpc-error',
  '一个 modern 服务器：握手正常，tools/list 返回 HTTP 200 + JSON-RPC error -32603。',
  '本条钉住 tools/list 的「JSON-RPC error」一支，记下 status 与安全整数 error code。',
  { toolsListResponse: (rpcId) => jsonRpcError(rpcId, -32603, 'Internal error') },
  [failedWith('tools_list', 'tools_list_jsonrpc_error', { status: 200, jsonrpc_error_code: -32603 })],
)

export const toolsListNotArray = toolsListFails(
  'tools-list-not-array',
  '一个 modern 服务器：握手正常，tools/list 返回 HTTP 200 + JSON-RPC result，但 result 里根本没有 tools 字段。',
  '本条钉住 tools/list 的「result 里没有 tools 数组」一支（tools-list-illegal-structure 是 tools 为字符串的同支）。',
  { toolsListResponse: (rpcId) => jsonRpcResult(rpcId, { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public' }) },
  [failedWith('tools_list', 'tools_list_not_array', { status: 200 })],
)

const COMPARISON_UNAVAILABLE = { key: 'fingerprint_comparison_unavailable', params: {} }

const TOOLS_ONE_MISSING_NAME = [
  CLEAN_TOOLS[0],
  { description: 'Archive a note by id.', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
]

export const fingerprintToolMissingName: Fixture = {
  id: 'fingerprint-tool-missing-name',
  description: '一个 modern 服务器：tools/list 结构合法，但其中一个工具没有 name 字段。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    FAILED_REASON_GUARD_SHARED +
    '本条钉住指纹失败的「缺 name」一类（requireToolName 的 TypeError）：两个指纹都 FAILED，都记同一个 key，' +
    '不记工具下标，也不记异常原文。',
  tools: TOOLS_ONE_MISSING_NAME,
  createHandler: () => createModernHandler(TOOLS_ONE_MISSING_NAME),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(cleanBaselineAssertions(), [
    failedWith('toolset_fingerprint', 'fingerprint_tool_missing_name'),
    failedWith('schema_fingerprint', 'fingerprint_tool_missing_name'),
    { check_id: 'toolset_unchanged_vs_approved', execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: COMPARISON_UNAVAILABLE },
    { check_id: 'schema_unchanged_vs_approved', execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: COMPARISON_UNAVAILABLE },
  ]),
}

/** Two property names that are different strings on the wire but the same
 *  string after NFC ("café" precomposed vs. e + combining acute). */
const TOOLS_NFC_DUPLICATE_KEYS = [
  CLEAN_TOOLS[0],
  { name: 'tag_note', description: 'Tag a note.', inputSchema: { type: 'object', properties: { 'café': { type: 'string' }, 'café': { type: 'string' } } } },
]

export const fingerprintCanonicalizeFailed: Fixture = {
  id: 'fingerprint-canonicalize-failed',
  description: '一个 modern 服务器：tools/list 结构合法，但一个工具的 inputSchema 里有两个 NFC 归一后相同的属性名。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    FAILED_REASON_GUARD_SHARED +
    '本条钉住指纹失败的「无法规范化」一类（CanonicalizationError DUPLICATE_KEY_AFTER_NFC）：toolset 层只取 name，' +
    '照样 VERIFIED；schema 层 FAILED。canonicalizer 的错误原文里带着这两个第三方键名，所以绝不能进记录——只记 key。',
  tools: TOOLS_NFC_DUPLICATE_KEYS,
  createHandler: () => createModernHandler(TOOLS_NFC_DUPLICATE_KEYS),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(cleanBaselineAssertions(), [
    failedWith('schema_fingerprint', 'fingerprint_canonicalize_failed'),
    { check_id: 'schema_unchanged_vs_approved', execution_status: 'SKIPPED', assertion_status: 'UNVERIFIED', reason: COMPARISON_UNAVAILABLE },
  ]),
}

// ---- T86: the probe never sends its reserved tool name to a server that may define it ----

const PROBE_TOOL_NAME_GUARD_SHARED =
  'T86：探测用的 tools/call 带一个保留名（本应不存在的工具）。这个名字是公开的，服务器可以真的定义它；' +
  '那样这次调用就会真的执行对方的一个工具，违背「我们从不调用你的工具」。所以只有能排除同名时才发；' +
  '不发时 error_taxonomy / auth_metadata（两者都只读这一次响应）记 SKIPPED/UNVERIFIED 并带原因，其余检查不变。'

export const probeToolNameCollision: Fixture = {
  id: 'probe-tool-name-collision',
  description: '一个 modern 服务器：握手与 tools/list 正常，tools/list 的第一页里就有一个与探测保留名逐字相同的工具，调用它会真的执行。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    PROBE_TOOL_NAME_GUARD_SHARED +
    '本条钉住「首页精确同名」一支（原因 probe_tool_name_collision）：请求序列里不得出现 tools/call；' +
    'tools_list、指纹与 hygiene 照常基于这份清单判定。',
  tools: TOOLS_WITH_RESERVED_NAME,
  createHandler: () => createModernHandler(TOOLS_WITH_RESERVED_NAME),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(cleanBaselineAssertions(), probeCallWithheld('probe_tool_name_collision')),
}

export const probeToolNameUnverifiableNextCursor: Fixture = {
  id: 'probe-tool-name-unverifiable-next-cursor',
  description:
    '一个 modern 服务器：tools/list 的第一页只列出两个普通工具，并带 nextCursor；保留名的那个工具在后面的页里，调用它会真的执行。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    PROBE_TOOL_NAME_GUARD_SHARED +
    '本条钉住「清单不完整」一支（原因 probe_tool_name_unverifiable）：第一页没有同名不能证明整份清单没有，' +
    '而我们不翻页（每轮请求数有公开上限）。第一页本身照常判定。',
  tools: CLEAN_TOOLS,
  createHandler: () =>
    createModernHandler(TOOLS_WITH_RESERVED_NAME, {
      toolsListResponse: (id) => jsonRpcResult(id, { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public', tools: CLEAN_TOOLS, nextCursor: 'page-2' }),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(cleanBaselineAssertions(), probeCallWithheld('probe_tool_name_unverifiable')),
}

export const probeToolNameUnverifiableToolsListFailed: Fixture = {
  id: 'probe-tool-name-unverifiable-tools-list-failed',
  description:
    '一个 modern 服务器：握手正常，tools/list 返回 HTTP 500 + 一张 text/html 页面；它其实定义了保留名的那个工具，调用它会真的执行。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    PROBE_TOOL_NAME_GUARD_SHARED +
    '本条钉住「tools/list 失败」一支（原因 probe_tool_name_unverifiable）：没有看到清单就排除不了同名。' +
    'tools_list 照旧 FAILED 并带 T73b 的原因；凭据门控的两支不在此列（见 credential-gated-* 正例）。',
  createHandler: () =>
    createModernHandler(TOOLS_WITH_RESERVED_NAME, {
      toolsListResponse: () => rawResponse(500, { 'content-type': 'text/html' }, '<html><body><h1>Internal Server Error</h1></body></html>'),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverrides(toolsListInvalidStructureCascade(cleanBaselineAssertions()), [failedWith('tools_list', 'tools_list_not_jsonrpc', { status: 500 })]),
}

/** T86 R2: a legacy server whose handshake is credential-gated (initialize is
 *  401 + a valid Bearer challenge) but whose tools/list still answers without
 *  credentials. The list is readable, so the gate no longer vouches that an
 *  unauthenticated tools/call reaches no tool. */
function gatedHandshakeReadableList(opts: { toolsListResponse?: (id: unknown) => Response } = {}): FetchHandler {
  return createLegacyHandler(TOOLS_WITH_RESERVED_NAME, {
    omitSessionId: true,
    initializeResponse: () => rawResponse(401, { 'www-authenticate': 'Bearer realm="mcp"' }, null),
    ...opts,
  })
}

const GATED_HANDSHAKE_READABLE_LIST_GUARD =
  '握手被凭据门控（initialize 401 + 合法 challenge），tools/list 却无凭据就返回了可读的清单（T86 R2）：' +
  '「门控服务器上未认证调用执行不到工具」这一前提已破，所以照样按清单判 a / b，不发 tools/call。' +
  '握手层门控本身的判定不变：discovery_handshake / protocol_revision / tools_list 记 UNVERIFIED/credential_required，不算指纹。'

export const probeToolNameCollisionGatedHandshake: Fixture = {
  id: 'probe-tool-name-collision-gated-handshake',
  description: '一个 legacy 服务器：initialize 返回 401 + Bearer challenge；tools/list 无凭据可读，其中有与探测保留名逐字相同的工具，调用它会真的执行。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst: PROBE_TOOL_NAME_GUARD_SHARED + GATED_HANDSHAKE_READABLE_LIST_GUARD + '本条钉住门控握手下的「首页精确同名」（probe_tool_name_collision）。',
  createHandler: () => gatedHandshakeReadableList(),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(credentialGatedCascadeAssertions(['discovery_handshake', 'protocol_revision', 'tools_list']), probeCallWithheld('probe_tool_name_collision')),
}

export const probeToolNameUnverifiableGatedHandshake: Fixture = {
  id: 'probe-tool-name-unverifiable-gated-handshake',
  description: '一个 legacy 服务器：initialize 返回 401 + Bearer challenge；tools/list 无凭据可读，第一页只有两个普通工具并带 nextCursor，保留名的那个工具在后面的页里。',
  protocolRevision: null,
  kind: 'negative',
  guardsAgainst: PROBE_TOOL_NAME_GUARD_SHARED + GATED_HANDSHAKE_READABLE_LIST_GUARD + '本条钉住门控握手下的「清单不完整」（probe_tool_name_unverifiable）。',
  createHandler: () =>
    gatedHandshakeReadableList({
      toolsListResponse: (id) => jsonRpcResult(id, { tools: CLEAN_TOOLS, nextCursor: 'page-2' }),
    }),
  sampleRun: (handler) => legacySampleRun(handler),
  expectedAssertions: withOverrides(credentialGatedCascadeAssertions(['discovery_handshake', 'protocol_revision', 'tools_list']), probeCallWithheld('probe_tool_name_unverifiable')),
}
