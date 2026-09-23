/**
 * Locale-aware render catalog for probe-run-level reader copy (packages/checks
 * assigns a stable key + optional params to every reason it produces;
 * the web frontend's build scripts and packages/checks itself never build prose directly).
 * Same single-source-of-truth discipline as checks.json, but for run-level
 * copy (why THIS assertion has THIS reason) rather than check-level copy
 * (what THIS check_id tests) — checks.json's own no_baseline_reason_en/_zh
 * stays the source for that one specific case; this file never duplicates it.
 *
 * HARD CONSTRAINT: this module must never import ./probe.ts, ./wire.ts, or
 * ./protocol.ts (or anything that transitively does) — the web frontend pulls
 * it in via the @mcpcheckup/checks/reason-messages subpath specifically so
 * its Cloudflare Workers bundle never has to include runProbe's network-calling
 * dependency tree. See reason-messages-bundle.test.ts (Step 4) and the
 * ./checks.json subpath export this mirrors.
 */

export type ReasonParams = Record<string, string | number>
export type ReasonRenderer = (params?: ReasonParams) => string

function requireParam(params: ReasonParams | undefined, key: string): string | number {
  if (!params || !(key in params)) throw new Error(`reason-messages: missing required param "${key}"`)
  return params[key]!
}

/** Like requireParam, but for a param that is genuinely allowed to be absent
 *  (currently only hygiene_risk_detected's totalCount — see that entry's
 *  comment below for why). Returns undefined instead of throwing when the
 *  key is missing; every OTHER param in this file still goes through
 *  requireParam and still throws, unchanged. */
function optionalParam(params: ReasonParams | undefined, key: string): string | number | undefined {
  if (!params || !(key in params)) return undefined
  return params[key]!
}

export const REASON_MESSAGES: Record<string, { en: ReasonRenderer; zh: ReasonRenderer }> = {
  tls_certificate_out_of_scope: {
    en: () => 'This check requires a TLS-terminating container executor to validate the certificate chain — out of scope for this fetch-based prober.',
    zh: () => '此检查由 container executor 校验证书链，不在本探测器（fetch-based prober）的执行范围内',
  },
  stdio_out_of_scope: {
    en: () => 'stdio transport is out of scope for this prober (remote-only — see README).',
    zh: () => 'stdio 传输不在本探测器当前范围内（remote-only，见 README）',
  },
  fingerprint_comparison_unavailable: {
    en: () => 'The current fingerprint could not be computed — there is nothing to compare against a baseline.',
    zh: () => '对应的指纹未能算出，没有可比对的当前值',
  },
  no_baseline_reason_generic: {
    en: () => 'No approved baseline exists.',
    zh: () => '不存在已批准基线',
  },
  fingerprint_baseline_mismatch: {
    en: () => 'The current fingerprint does not match the approved baseline.',
    zh: () => '当前指纹与已批准基线不一致',
  },
  tools_list_invalid_structure: {
    en: () => 'tools/list returned a structurally invalid response — there is no usable tool data to compute this from.',
    zh: () => 'tools/list 返回的结构不合法，没有可用的工具数据可供计算',
  },
  redirect_cross_host_observed: {
    en: () => 'A cross-host redirect was observed during this probe.',
    zh: () => '探测过程中观察到跨主机重定向',
  },
  probe_aborted: {
    en: (p) => `This run was aborted before completing (budget exceeded or an error occurred) — later checks did not run: ${requireParam(p, 'message')}`,
    zh: (p) => `本次 run 因预算耗尽或探测中止而未能完整完成，后续检查未执行：${requireParam(p, 'message')}`,
  },
  probe_cascade_incomplete: {
    en: () => 'This run was aborted before completing (budget exceeded or an error occurred) — this check did not run.',
    zh: () => '本次 run 因预算耗尽或探测中止而未能完整完成，后续检查未执行',
  },
  probe_budget_exhausted_requests: {
    en: (p) => `This run was aborted after reaching its budget of ${requireParam(p, 'maxRequests')} requests — later checks did not run.`,
    zh: (p) => `本次 run 因达到 ${requireParam(p, 'maxRequests')} 次请求的预算而中止——后续检查未执行`,
  },
  probe_budget_exhausted_duration: {
    en: (p) => `This run was aborted after exceeding its ${requireParam(p, 'maxDurationMs')}ms time budget — later checks did not run.`,
    zh: (p) => `本次 run 因超过 ${requireParam(p, 'maxDurationMs')}ms 的时间预算而中止——后续检查未执行`,
  },
  probe_budget_exhausted_redirects: {
    en: (p) => `This run was aborted after exceeding its budget of ${requireParam(p, 'maxRedirects')} redirects — later checks did not run.`,
    zh: (p) => `本次 run 因重定向跳数超过 ${requireParam(p, 'maxRedirects')} 的预算而中止——后续检查未执行`,
  },
  probe_budget_exhausted_body: {
    en: (p) => `This run was aborted after a response body exceeded its ${requireParam(p, 'maxBodyBytes')}-byte budget — later checks did not run.`,
    zh: (p) => `本次 run 因响应体超过 ${requireParam(p, 'maxBodyBytes')} 字节的预算而中止——后续检查未执行`,
  },
  // Deliberately renders no params, even though this reason's params do carry
  // the observed status (and the parsed Retry-After, when there was one): the
  // approved sentence names both triggers in prose, and the numbers are
  // evidence for the signed record rather than something the reader is asked
  // to interpret. Keeping the renderer param-free also keeps this key in the
  // "renders without params" group every consumer already handles.
  probe_rate_limited: {
    en: () => 'The server told us to come back later (HTTP 429, or 503 with Retry-After), so we stopped this round before finishing the checks.',
    zh: () => '对方要求我们稍后再来（HTTP 429，或带 Retry-After 的 503），我们在完成检查前停止了本轮。',
  },
  check_not_implemented: {
    en: (p) => `This prober has not implemented check_id=${requireParam(p, 'check_id')} — this is an implementation gap, not a probe result.`,
    zh: (p) => `本探测器未实现 check_id=${requireParam(p, 'check_id')}，这是实现缺口，不是探测结果`,
  },
  disqualified_dns_rebind: {
    en: () => "This run observed the target hostname's DNS resolution change mid-probe (possible DNS rebinding) — the result cannot enter the publication flow and is recorded as risk evidence only.",
    zh: () => '探测过程中观察到目标主机名的 DNS 解析结果发生变化（可能的 DNS rebinding），本次结果不得进入发布流程，仅作为风险证据记录',
  },
  hygiene_risk_detected: {
    // totalCount is optional, not required-via-requireParam, for one specific
    // reason: legacy pre-migration rows (backfilled by
    // scripts/backfill-reason-keys.mjs) only ever encoded hitCount in their
    // flat-text reason — the old Chinese sentence never included the tool
    // total, and assertions.details (the only other place a total could in
    // principle have been recovered from) is confirmed dead/always [] (see
    // that script's report). So totalCount truly cannot be recovered for
    // those rows, and requiring it unconditionally would make every
    // backfilled hygiene_risk_detected row throw at render time. New rows
    // (post-migration) always pass both hitCount and totalCount (see
    // packages/checks/src/hygiene.ts) — this branch only ever actually omits
    // the "of M" clause for legacy-backfilled data.
    en: (p) => {
      const hitCount = requireParam(p, 'hitCount')
      const totalCount = optionalParam(p, 'totalCount')
      return totalCount === undefined
        ? `Suspicious patterns were observed in ${hitCount} tools' names or descriptions; this does not mean the server is malicious.`
        : `Suspicious patterns were observed in ${hitCount} of ${totalCount} tools' names or descriptions; this does not mean the server is malicious.`
    },
    zh: (p) => `${requireParam(p, 'hitCount')} 个工具的名称或描述中观察到可疑模式；这不意味着该 server 有恶意`,
  },
  hygiene_no_risk: {
    en: (p) => `No hidden characters or injection patterns were observed across ${requireParam(p, 'totalCount')} tools' names and descriptions.`,
    zh: (p) => `${requireParam(p, 'totalCount')} 个工具的名称与描述未观察到隐藏字符或注入模式`,
  },
  // No longer emitted since T73 (the seven error_taxonomy_* keys below replaced
  // it); kept because historical rows and signed envelopes still carry it.
  error_taxonomy_risk: {
    en: () => 'The triggered safety error scenario did not return a protocol-shaped JSON-RPC error.',
    zh: () => '触发的安全错误场景没有返回协议定义形状的 JSON-RPC 错误',
  },
  // T73: the bounded classification of the unknown-tool response
  // (packages/checks/src/error-taxonomy.ts classifyUnknownToolResponse). Every
  // one of these reasons carries scenario / status / media_type (and, for
  // jsonrpc_malformed only, sometimes jsonrpc_error_code) as signed evidence;
  // like probe_rate_limited above, the renderers deliberately read only what
  // the approved sentence names — `status` for five keys, nothing for the two
  // result_* keys. The other params are for the signed record, not the reader.
  error_taxonomy_result_is_error: {
    en: () => 'We called tools/call with a tool name that does not exist. The server answered with an ordinary result marked isError instead of a JSON-RPC error object.',
    zh: () => '我们用一个不存在的工具名调用了 tools/call。服务器返回的是带 isError 标记的普通 result，而不是 JSON-RPC error 对象。',
  },
  error_taxonomy_result_ok: {
    en: () => 'We called tools/call with a tool name that does not exist. The server answered with a successful result.',
    zh: () => '我们用一个不存在的工具名调用了 tools/call。服务器返回了一个成功的 result。',
  },
  error_taxonomy_jsonrpc_malformed: {
    en: (p) => `We called tools/call with a tool name that does not exist. The server answered HTTP ${requireParam(p, 'status')} with a JSON-RPC message that has neither a result nor a well-formed error object.`,
    zh: (p) => `我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP ${requireParam(p, 'status')}，消息自称 JSON-RPC，但既没有 result，也没有格式正确的 error 对象。`,
  },
  error_taxonomy_not_jsonrpc: {
    en: (p) => `We called tools/call with a tool name that does not exist. The server answered HTTP ${requireParam(p, 'status')} with JSON that is not a JSON-RPC message.`,
    zh: (p) => `我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP ${requireParam(p, 'status')}，内容是 JSON，但不是 JSON-RPC 消息。`,
  },
  error_taxonomy_not_json: {
    en: (p) => `We called tools/call with a tool name that does not exist. The server answered HTTP ${requireParam(p, 'status')} with a body that is not JSON.`,
    zh: (p) => `我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP ${requireParam(p, 'status')}，响应体不是 JSON。`,
  },
  error_taxonomy_empty_body: {
    en: (p) => `We called tools/call with a tool name that does not exist. The server answered HTTP ${requireParam(p, 'status')} with an empty body.`,
    zh: (p) => `我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP ${requireParam(p, 'status')}，响应体为空。`,
  },
  // Phrased as "we found no data events", not "it carried none": protocol.ts's
  // extractSseDataPayloads splits lines only on \r?\n, so a stream framed with
  // lone CR (legal in WHATWG SSE) can carry data we do not see. Fixing the
  // extractor would change verdicts, so the sentence states only our finding;
  // and it says the Content-Type "names" an event stream because detection is
  // isSseContentType, a substring match (e.g. `application/json;
  // profile=text/event-stream` also qualifies); and it says "non-empty" data
  // events because extractSseDataPayloads drops zero-length payloads, while
  // WHATWG still dispatches an event whose data is empty (e.g. `data:\n\n`).
  error_taxonomy_event_stream_no_data: {
    en: (p) => `We called tools/call with a tool name that does not exist. The server answered HTTP ${requireParam(p, 'status')} with a response whose Content-Type names an event stream, in which we found no non-empty data events.`,
    zh: (p) => `我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP ${requireParam(p, 'status')}，响应的 Content-Type 声明为事件流，但我们在其中没有找到任何非空的 data 事件。`,
  },
  auth_401_no_challenge: {
    en: () => 'A 401 was received with no credentials, but no WWW-Authenticate challenge was observable.',
    zh: () => '无凭据时收到 401，但没有 WWW-Authenticate challenge 可供观察',
  },
  auth_challenge_no_metadata_url: {
    en: () => 'The WWW-Authenticate challenge does not point to any verifiable resource metadata document.',
    zh: () => 'WWW-Authenticate challenge 未指向任何可核实的 resource metadata 文档',
  },
  auth_metadata_http_error: {
    en: (p) => `The metadata document referenced by the challenge returned HTTP ${requireParam(p, 'status')}, not a usable 200.`,
    zh: (p) => `challenge 指向的 metadata 文档返回 HTTP ${requireParam(p, 'status')}，不是可用的 200`,
  },
  auth_metadata_invalid_json: {
    en: () => 'The metadata document referenced by the challenge is not valid JSON.',
    zh: () => 'challenge 指向的 metadata 文档不是合法 JSON',
  },
  auth_metadata_not_json_object: {
    en: () => 'The metadata document referenced by the challenge is not a JSON object.',
    zh: () => 'challenge 指向的 metadata 文档不是一个 JSON 对象',
  },
  auth_scope_contradiction: {
    en: () => "The scope claimed by WWW-Authenticate contradicts its own metadata document's scopes_supported.",
    zh: () => 'WWW-Authenticate 声明的 scope 与其自身 metadata 文档的 scopes_supported 矛盾',
  },
  credential_required: {
    en: (p) =>
      `This check requires credentials to complete — the server responded 401 with a "${requireParam(p, 'scheme')}" authentication challenge. We never send credentials of our own, so we can't verify what's behind it; this looks like a deliberate access-control choice, not a broken implementation.`,
    zh: (p) =>
      `此检查需要凭据才能完成——服务端返回 401 并附带 "${requireParam(p, 'scheme')}" 认证 challenge。我们从不发送任何凭据，因此无法验证背后的行为；这看起来是有意的访问控制选择，不是实现故障。`,
  },
  disqualified_no_protocol_revision: {
    en: () => 'No protocol_revision was ever observed, so a schema-valid attestation payload could not be assembled.',
    zh: () => '未观察到 protocol_revision，无法组装符合 schema 的 attestation payload',
  },
  disqualified_no_fingerprint: {
    en: () => 'toolset_fingerprint/schema_fingerprint could not be computed — an attestation payload could not be assembled.',
    zh: () => 'toolset_fingerprint/schema_fingerprint 未能计算，无法组装 attestation payload',
  },
  disqualified_signer_call_failed: {
    en: (p) => `The signer call failed — this result could not be signed: ${requireParam(p, 'message')}`,
    zh: (p) => `signer 调用失败，本次结果无法签名：${requireParam(p, 'message')}`,
  },
}

export type ReasonKey = keyof typeof REASON_MESSAGES
