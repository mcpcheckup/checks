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

  // Ten keys require params (requireParam throws if omitted — that's the
  // load-bearing safety net catching a future emitter bug that forgets to
  // pass one; see reason-messages.ts). This test isn't the place to exercise
  // that throw — it's a smoke test that every entry renders non-empty text —
  // so it feeds each of those ten a minimal representative params object and
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
  }

  await t('every entry renders non-empty text (zero-arg for param-free keys, minimal params for the six that require them)', () => {
    for (const key of Object.keys(REASON_MESSAGES)) {
      const params = MINIMAL_PARAMS[key]
      assert.ok(REASON_MESSAGES[key]!.en(params).length > 0, `${key}: en() is empty`)
      assert.ok(REASON_MESSAGES[key]!.zh(params).length > 0, `${key}: zh() is empty`)
    }
  })

  await t('SECURITY: the eleven param-taking keys throw (not silently render blank) when required params are omitted', () => {
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

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exitCode = fail ? 1 : 0
}

main().catch((e) => { console.error(e); process.exit(1) })
