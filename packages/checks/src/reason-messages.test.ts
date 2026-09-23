import { strict as assert } from 'node:assert'
import { REASON_MESSAGES } from './reason-messages.ts'

// 与本包其余 *.test.ts 同一个约定：计数 + 末尾一行 "N passed, M failed" +
// process.exitCode。round 18 之前这里是 fail-fast（catch 里 rethrow），于是这个
// 文件从不打印汇总行——任何按汇总行统计断言数的人都会**静默漏掉**这 8 条。
let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log(`  ok   ${name}`) }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${(e as Error).stack}`) }
}

const EXPECTED_KEYS = [
  'tls_certificate_out_of_scope', 'stdio_out_of_scope', 'fingerprint_comparison_unavailable',
  'no_baseline_reason_generic', 'fingerprint_baseline_mismatch', 'tools_list_invalid_structure',
  'redirect_cross_host_observed', 'probe_aborted', 'probe_cascade_incomplete',
  'probe_budget_exhausted_requests', 'probe_budget_exhausted_duration',
  'probe_budget_exhausted_redirects', 'probe_budget_exhausted_body', 'probe_rate_limited', 'check_not_implemented',
  'disqualified_dns_rebind', 'hygiene_risk_detected', 'hygiene_no_risk', 'error_taxonomy_risk',
  'auth_401_no_challenge', 'auth_challenge_no_metadata_url', 'auth_metadata_http_error',
  'auth_metadata_invalid_json', 'auth_metadata_not_json_object', 'auth_scope_contradiction',
  'credential_required',
  'disqualified_no_protocol_revision', 'disqualified_no_fingerprint', 'disqualified_signer_call_failed',
  'error_taxonomy_result_is_error', 'error_taxonomy_result_ok', 'error_taxonomy_jsonrpc_malformed',
  'error_taxonomy_not_jsonrpc', 'error_taxonomy_not_json', 'error_taxonomy_empty_body',
  'error_taxonomy_event_stream_no_data',
]

async function main() {
  console.log('reason-messages: catalog structure + en/zh parity + escaping safety')

  await t('every expected key exists in REASON_MESSAGES, no extras', () => {
    const actual = Object.keys(REASON_MESSAGES).sort()
    assert.deepEqual(actual, [...EXPECTED_KEYS].sort())
  })

  await t('every entry has both en and zh render functions', () => {
    for (const key of Object.keys(REASON_MESSAGES)) {
      assert.equal(typeof REASON_MESSAGES[key]!.en, 'function', `${key}: missing en`)
      assert.equal(typeof REASON_MESSAGES[key]!.zh, 'function', `${key}: missing zh`)
    }
  })

  // Sixteen keys require params (requireParam throws if omitted — that's the
  // load-bearing safety net catching a future emitter bug that forgets to
  // pass one; see reason-messages.ts). This test isn't the place to exercise
  // that throw — it's a smoke test that every entry renders non-empty text —
  // so it feeds each of those sixteen a minimal representative params object and
  // leaves every param-free key on a genuine zero-arg call.
  const MINIMAL_PARAMS: Partial<Record<string, Record<string, string | number>>> = {
    probe_aborted: { message: 'x' },
    probe_budget_exhausted_requests: { maxRequests: 8 },
    probe_budget_exhausted_duration: { maxDurationMs: 10_000 },
    probe_budget_exhausted_redirects: { maxRedirects: 3 },
    probe_budget_exhausted_body: { maxBodyBytes: 2_097_152 },
    check_not_implemented: { check_id: 'x' },
    hygiene_risk_detected: { hitCount: 1, totalCount: 2 },
    hygiene_no_risk: { totalCount: 2 },
    auth_metadata_http_error: { status: 404 },
    credential_required: { scheme: 'bearer' },
    disqualified_signer_call_failed: { message: 'x' },
    error_taxonomy_jsonrpc_malformed: { status: 200 },
    error_taxonomy_not_jsonrpc: { status: 400 },
    error_taxonomy_not_json: { status: 500 },
    error_taxonomy_empty_body: { status: 503 },
    error_taxonomy_event_stream_no_data: { status: 200 },
  }

  await t('MINIMAL_PARAMS lists exactly the keys whose renderer throws with no params (derived from the table, not hand-kept)', () => {
    const needsParams = Object.keys(REASON_MESSAGES).filter((key) => {
      try { REASON_MESSAGES[key]!.en(); return false } catch { return true }
    })
    assert.deepEqual(needsParams.sort(), Object.keys(MINIMAL_PARAMS).sort())
    assert.equal(needsParams.length, 16)
  })

  await t('every entry renders non-empty text (zero-arg for param-free keys, minimal params for the sixteen that require them)', () => {
    for (const key of Object.keys(REASON_MESSAGES)) {
      const params = MINIMAL_PARAMS[key]
      assert.ok(REASON_MESSAGES[key]!.en(params).length > 0, `${key}: en() is empty`)
      assert.ok(REASON_MESSAGES[key]!.zh(params).length > 0, `${key}: zh() is empty`)
    }
  })

  await t('SECURITY: the sixteen param-taking keys throw (not silently render blank) when required params are omitted', () => {
    for (const key of Object.keys(MINIMAL_PARAMS)) {
      assert.throws(() => REASON_MESSAGES[key]!.en(), /missing required param/, `${key}: en() should throw with no params`)
      assert.throws(() => REASON_MESSAGES[key]!.zh(), /missing required param/, `${key}: zh() should throw with no params`)
    }
  })

  await t('params-taking keys render distinct text for different params', () => {
    const r1 = REASON_MESSAGES.auth_metadata_http_error!.en({ status: 404 })
    const r2 = REASON_MESSAGES.auth_metadata_http_error!.en({ status: 500 })
    assert.notEqual(r1, r2)
    assert.ok(r1.includes('404'))
  })

  await t('probe_budget_exhausted_requests/_duration/_redirects/_body: render with their required numeric param, throw when it is missing', () => {
    const cases: [string, Record<string, number>, number][] = [
      ['probe_budget_exhausted_requests', { maxRequests: 8 }, 8],
      ['probe_budget_exhausted_duration', { maxDurationMs: 10_000 }, 10_000],
      ['probe_budget_exhausted_redirects', { maxRedirects: 3 }, 3],
      ['probe_budget_exhausted_body', { maxBodyBytes: 2_097_152 }, 2_097_152],
    ]
    for (const [key, params, expectedNumber] of cases) {
      const en = REASON_MESSAGES[key]!.en(params)
      const zh = REASON_MESSAGES[key]!.zh(params)
      assert.ok(en.includes(String(expectedNumber)), `${key}: en() should include ${expectedNumber}, got: ${en}`)
      assert.ok(zh.includes(String(expectedNumber)), `${key}: zh() should include ${expectedNumber}, got: ${zh}`)
      assert.throws(() => REASON_MESSAGES[key]!.en(), /missing required param/, `${key}: en() should throw with no params`)
      assert.throws(() => REASON_MESSAGES[key]!.zh(), /missing required param/, `${key}: zh() should throw with no params`)
    }
  })

  await t('hygiene_risk_detected renders without a totalCount param (legacy-row backfill case): omits the "of M" clause instead of throwing', () => {
    // hitCount is still required — this only exercises the totalCount-absent
    // path, not a call with zero params at all (that's covered by the
    // "SECURITY: ... throw when required params are omitted" test above,
    // which still expects hygiene_risk_detected to throw with truly no params
    // since hitCount alone remains mandatory).
    const en = REASON_MESSAGES.hygiene_risk_detected!.en({ hitCount: 3 })
    const zh = REASON_MESSAGES.hygiene_risk_detected!.zh({ hitCount: 3 })
    assert.ok(en.includes('3'), 'en should include hitCount')
    assert.ok(!en.includes(' of '), 'en should omit the "of M" clause when totalCount is absent')
    assert.ok(zh.includes('3'), 'zh should include hitCount')
    // Sanity: the totalCount-present path still renders the "of M" clause.
    const enWithTotal = REASON_MESSAGES.hygiene_risk_detected!.en({ hitCount: 3, totalCount: 11 })
    assert.ok(enWithTotal.includes(' of 11 '), 'en should include the "of M" clause when totalCount is present')
  })

  await t('SECURITY: params values are interpolated as plain text, never as markup', () => {
    const malicious = '<script>alert(1)</script> [click me](javascript:alert(1)) **bold**'
    const en = REASON_MESSAGES.probe_aborted!.en({ message: malicious })
    const zh = REASON_MESSAGES.probe_aborted!.zh({ message: malicious })
    // The renderer must not strip/escape here (that's the DOM layer's job at
    // render time in the web frontend) — it must simply pass the string through
    // unchanged, never wrap it in html/parse it as markdown itself.
    assert.ok(en.includes(malicious))
    assert.ok(zh.includes(malicious))
    // Negative check: the renderer itself must never contain html-construction
    // helpers — a static source scan, not a runtime behavior we can assert
    // from here. See Step 4 below for the dedicated source-scan test.
  })

  // ---- T73: the seven error_taxonomy_* keys. The approved sentences are pinned
  // verbatim (with {status} = 503 substituted), so a reword cannot land without
  // this file changing too. ----
  const ERROR_TAXONOMY_COPY: Record<string, { en: string; zh: string }> = {
    error_taxonomy_result_is_error: {
      en: 'We called tools/call with a tool name that does not exist. The server answered with an ordinary result marked isError instead of a JSON-RPC error object.',
      zh: '我们用一个不存在的工具名调用了 tools/call。服务器返回的是带 isError 标记的普通 result，而不是 JSON-RPC error 对象。',
    },
    error_taxonomy_result_ok: {
      en: 'We called tools/call with a tool name that does not exist. The server answered with a successful result.',
      zh: '我们用一个不存在的工具名调用了 tools/call。服务器返回了一个成功的 result。',
    },
    error_taxonomy_jsonrpc_malformed: {
      en: 'We called tools/call with a tool name that does not exist. The server answered HTTP 503 with a JSON-RPC message that has neither a result nor a well-formed error object.',
      zh: '我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP 503，消息自称 JSON-RPC，但既没有 result，也没有格式正确的 error 对象。',
    },
    error_taxonomy_not_jsonrpc: {
      en: 'We called tools/call with a tool name that does not exist. The server answered HTTP 503 with JSON that is not a JSON-RPC message.',
      zh: '我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP 503，内容是 JSON，但不是 JSON-RPC 消息。',
    },
    error_taxonomy_not_json: {
      en: 'We called tools/call with a tool name that does not exist. The server answered HTTP 503 with a body that is not JSON.',
      zh: '我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP 503，响应体不是 JSON。',
    },
    error_taxonomy_empty_body: {
      en: 'We called tools/call with a tool name that does not exist. The server answered HTTP 503 with an empty body.',
      zh: '我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP 503，响应体为空。',
    },
    error_taxonomy_event_stream_no_data: {
      en: 'We called tools/call with a tool name that does not exist. The server answered HTTP 503 with a response whose Content-Type names an event stream, in which we found no non-empty data events.',
      zh: '我们用一个不存在的工具名调用了 tools/call。服务器返回 HTTP 503，响应的 Content-Type 声明为事件流，但我们在其中没有找到任何非空的 data 事件。',
    },
  }
  const FULL_ERROR_TAXONOMY_PARAMS = { scenario: 'tools_call_unknown_tool', status: 503, media_type: 'application/json', jsonrpc_error_code: -32000 }

  await t('T73: the seven error_taxonomy_* keys render exactly the approved en/zh sentences, whatever else the signed params carry', () => {
    for (const [key, copy] of Object.entries(ERROR_TAXONOMY_COPY)) {
      assert.equal(REASON_MESSAGES[key]!.en(FULL_ERROR_TAXONOMY_PARAMS), copy.en, `${key}/en`)
      assert.equal(REASON_MESSAGES[key]!.zh(FULL_ERROR_TAXONOMY_PARAMS), copy.zh, `${key}/zh`)
    }
  })

  await t('T73: renderers read exactly the params the sentence names: status for five keys, none for result_is_error / result_ok (scenario, media_type, jsonrpc_error_code are signed evidence only)', () => {
    const READS: Record<string, string[]> = {
      error_taxonomy_result_is_error: [],
      error_taxonomy_result_ok: [],
      error_taxonomy_jsonrpc_malformed: ['status'],
      error_taxonomy_not_jsonrpc: ['status'],
      error_taxonomy_not_json: ['status'],
      error_taxonomy_empty_body: ['status'],
      error_taxonomy_event_stream_no_data: ['status'],
    }
    for (const [key, want] of Object.entries(READS)) {
      for (const locale of ['en', 'zh'] as const) {
        const touched = new Set<string>()
        const spy = new Proxy({} as Record<string, string | number>, {
          has: (_t, prop) => { if (typeof prop === 'string') touched.add(prop); return true },
          get: (_t, prop) => { if (typeof prop === 'string') touched.add(prop); return 0 },
        })
        REASON_MESSAGES[key]![locale](spy)
        assert.deepEqual([...touched].sort(), want, `${key}/${locale} read ${JSON.stringify([...touched])}`)
      }
    }
  })

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exitCode = fail ? 1 : 0
}

main().catch((e) => { console.error(e); process.exit(1) })
