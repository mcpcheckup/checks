import assert from 'node:assert'
import { CHECKS_REGISTRY, isKnownCheckId, getCheckIds } from './registry.ts'
import type { ChecksRegistry } from './registry.ts'
import frozen0140Checks from './frozen/suite-0.14.0/checks.json' with { type: 'json' }
import frozen0150Checks from './frozen/suite-0.15.0/checks.json' with { type: 'json' }
import frozen0160Checks from './frozen/suite-0.16.0/checks.json' with { type: 'json' }
import frozen0170Checks from './frozen/suite-0.17.0/checks.json' with { type: 'json' }
import frozen0180Checks from './frozen/suite-0.18.0/checks.json' with { type: 'json' }

/** Registry 0.13.0, the one suite 0.14.0 shipped with. */
const FROZEN_0130_REGISTRY: Pick<ChecksRegistry, 'registry_version' | 'checks'> = frozen0140Checks
/** Registry 0.14.0, the one suite 0.15.0 shipped with. */
const FROZEN_0140_REGISTRY: Pick<ChecksRegistry, 'registry_version' | 'checks'> = frozen0150Checks
/** Registry 0.15.0, the one suite 0.16.0 shipped with. */
const FROZEN_0150_REGISTRY: Pick<ChecksRegistry, 'registry_version' | 'checks'> = frozen0160Checks
/** Registry 0.16.0, the one suite 0.17.0 shipped with. */
const FROZEN_0160_REGISTRY: Pick<ChecksRegistry, 'registry_version' | 'checks'> = frozen0170Checks
/** Registry 0.17.0, the one suite 0.18.0 shipped with. */
const FROZEN_0170_REGISTRY: Pick<ChecksRegistry, 'registry_version' | 'checks'> = frozen0180Checks

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('registry: checks.json 是单一事实来源')

t('CHECKS_REGISTRY 加载出真实内容（suite_id / checks 数组）', () => {
  assert.equal(CHECKS_REGISTRY.suite_id, 'remote-baseline-v0.1')
  assert.ok(Array.isArray(CHECKS_REGISTRY.checks))
  assert.ok(CHECKS_REGISTRY.checks.length >= 15)
})

t('getCheckIds() 返回全部 check_id，且包含已知的几个', () => {
  const ids = getCheckIds()
  for (const id of ['reachability', 'protocol_revision', 'discovery_handshake', 'tools_list', 'tool_description_hygiene', 'toolset_fingerprint', 'schema_fingerprint']) {
    assert.ok(ids.includes(id), `缺少 ${id}`)
  }
})

t('isKnownCheckId：真实存在的 check_id 返回 true', () => {
  assert.equal(isKnownCheckId('auth_metadata'), true)
})

t('isKnownCheckId：拼写错误的 check_id 返回 false（反例，防止 fixtures 用错字的 check_id 静默通过）', () => {
  assert.equal(isKnownCheckId('toolset_fingreprint'), false)
  assert.equal(isKnownCheckId('not_a_real_check'), false)
})

t('每个 check 条目的 _en 字段与 _zh 字段一一对称——O-19：不允许漏译', () => {
  for (const def of CHECKS_REGISTRY.checks) {
    assert.equal(typeof def.predicate_en, 'string', `${def.check_id}: predicate_en 缺失或不是 string`)
    assert.ok(def.predicate_en.length > 0, `${def.check_id}: predicate_en 是空字符串`)
    assert.equal(typeof def.explain.what_en, 'string', `${def.check_id}: explain.what_en 缺失`)
    assert.ok(def.explain.what_en.length > 0, `${def.check_id}: explain.what_en 是空字符串`)
    assert.equal(typeof def.explain.how_en, 'string', `${def.check_id}: explain.how_en 缺失`)
    assert.ok(def.explain.how_en.length > 0, `${def.check_id}: explain.how_en 是空字符串`)
    assert.equal(typeof def.explain.cannot_en, 'string', `${def.check_id}: explain.cannot_en 缺失`)
    assert.ok(def.explain.cannot_en.length > 0, `${def.check_id}: explain.cannot_en 是空字符串`)
    if (def.no_baseline_reason_zh !== undefined) {
      assert.equal(typeof def.no_baseline_reason_en, 'string', `${def.check_id}: 有 no_baseline_reason_zh 但缺 no_baseline_reason_en`)
    }
    if (def.p0_note_zh !== undefined) {
      assert.equal(typeof def.p0_note_en, 'string', `${def.check_id}: 有 p0_note_zh 但缺 p0_note_en`)
    }
  }
})

t('每个 group 的 description_en 与 description_zh 都存在', () => {
  for (const g of CHECKS_REGISTRY.groups) {
    assert.equal(typeof g.description_en, 'string', `${g.key}: description_en 缺失`)
    assert.ok(g.description_en.length > 0, `${g.key}: description_en 是空字符串`)
  }
})

t('failure_status 为 null 的 check：predicate / what / how 不得声称会记 OBSERVED_RISK 或 FAILED（说明文字不许承诺代码没有的结论）', () => {
  for (const def of CHECKS_REGISTRY.checks) {
    if (def.failure_status !== null) continue
    for (const k of ['predicate_zh', 'predicate_en'] as const) assert.doesNotMatch(def[k], /OBSERVED_RISK|FAILED/, `${def.check_id}.${k}`)
    for (const k of ['what_zh', 'what_en', 'how_zh', 'how_en'] as const) assert.doesNotMatch(def.explain[k], /OBSERVED_RISK|FAILED/, `${def.check_id}.explain.${k}`)
  }
})

t('transport_type：说明如实——不与声明的传输比对，也不声称握手成功；握手结果与 VERIFIED 无关（那是 discovery_handshake 的判定）', () => {
  const def = CHECKS_REGISTRY.checks.find((c) => c.check_id === 'transport_type')!
  assert.equal(def.failure_status, null)
  // predicate / what / how 都不得说「握手完成」（probe.ts 在握手失败、被凭据门控时同样记 VERIFIED），也不得承诺比对。
  for (const text of [def.predicate_zh, def.predicate_en, def.explain.what_zh, def.explain.what_en, def.explain.how_zh, def.explain.how_en]) {
    assert.doesNotMatch(text, /handshake (completed|completes|is completed)|握手[^，。；（]{0,8}完成/i, `transport_type 声称握手完成：${text}`)
  }
  for (const text of [def.predicate_zh, def.predicate_en, def.explain.what_zh, def.explain.what_en]) {
    assert.doesNotMatch(text, /matches (the )?declar|compared against|符合声明|做比对/i, `transport_type 仍承诺比对：${text}`)
  }
  assert.match(def.explain.how_en, /VERIFIED/)
  assert.match(def.explain.how_en, /whether or not the handshake itself succeeds/)
  assert.match(def.explain.how_en, /not compared against any transport the server declares/)
  assert.match(def.explain.how_zh, /VERIFIED/)
  assert.match(def.explain.how_zh, /无论握手本身是否成功/)
  assert.match(def.explain.how_zh, /不会与 server 声明的传输做比对/)
})

// Approved copy: the four `how` strings pinned verbatim. Each states what probe.ts does on every branch —
// VERIFIED once performHandshake returns (whatever the handshake's own verdict), and on any stop before that the
// catch block writes reachability ERROR/UNVERIFIED and cascades the rest SKIPPED/UNVERIFIED with the abort's reason.
const how = (id: string) => CHECKS_REGISTRY.checks.find((c) => c.check_id === id)!.explain

t('transport_type.how_en 与签字原文逐字相同', () => {
  assert.equal(how('transport_type').how_en, `Recorded as VERIFIED when our handshake exchange over that transport finishes with an HTTP response from the endpoint, whether or not the handshake itself succeeds — that is discovery_handshake's verdict. If the probe stops before the exchange finishes — for example because the endpoint asks us to back off, a response is over the probe's size limit, or one of the probe's budgets runs out — this check is not recorded as VERIFIED, and the reason is recorded with it. It is not compared against any transport the server declares.`)
})

t('transport_type.how_zh 与签字原文逐字相同', () => {
  assert.equal(how('transport_type').how_zh, `我们经该传输的握手交换以端点的 HTTP 回应结束时，记 VERIFIED，无论握手本身是否成功（那由 discovery_handshake 判定）。如果探测在交换结束前停下——例如端点要求我们稍后再来、某个回应超出探测的大小上限、或探测的某项预算用尽——本项不记 VERIFIED，并同时记下原因。不会与 server 声明的传输做比对。`)
})

t('reachability.how_en 与签字原文逐字相同', () => {
  assert.equal(how('reachability').how_en, `Recorded as VERIFIED when our handshake exchange finishes with an HTTP response from the endpoint, whatever its status. If the probe stops before the exchange finishes — for example because the endpoint asks us to back off (429, or 503 with Retry-After), a response is over the size limit, the connection fails, or one of the probe's budgets runs out — this check is UNVERIFIED, with that reason, even if the endpoint had already answered an earlier request. The whole probe, handshake included, runs under hard caps: 8 requests and 10s in total, and 2MB per response. Reading the further pages of a long tool list adds at most 9 requests to the 8; they share the same 10s and the 2MB limit per response.`)
})

t('reachability.how_zh 与签字原文逐字相同', () => {
  assert.equal(how('reachability').how_zh, `我们的握手交换以 endpoint 的 HTTP 回应结束时（任何状态码都算），记 VERIFIED。如果探测在交换结束前停下——例如 endpoint 要求我们稍后再来（429，或带 Retry-After 的 503）、某个回应超出大小上限、连接出错、或探测的某项预算用尽——本项记 UNVERIFIED 并附上原因，即使 endpoint 已经答复过之前的请求。整次探测（含握手）都在硬上限内进行：总共 8 个请求、10 s，每个回应 2 MB。读取较长工具列表的后续页，最多在 8 个请求之外再加 9 个，同样受 10 s 和每个回应 2 MB 的限制。`)
})

t('reachability.how 里写的预算数字等于 checks.json 的 budget 字段（文案不许和合同数字漂移）', () => {
  const b = CHECKS_REGISTRY.budget
  assert.equal(b.max_requests, 8)
  assert.equal(b.max_duration_ms, 10_000)
  assert.equal(b.max_body_bytes, 2 * 1024 * 1024)
  // "at most 9 requests" on top of the 8: every page after the first.
  assert.equal(b.max_tools_list_pages, 10)
  assert.equal(b.max_tools_list_pages - 1, 9)
})

// Suite 0.15.0 (registry 0.14.0): seven more checks' how text gains exactly one
// sentence, about reading every tools/list page and what an incomplete list
// records. Each text is the registry 0.13.0 text (frozen/suite-0.14.0/checks.json)
// plus that sentence, verbatim, so nothing else in it moved.
const HOW_APPENDED_0140: Record<string, { en: string; zh: string }> = {
  tools_list: {
    en: ' When the server splits its list into pages, we follow nextCursor and read every page, up to 10 pages or 5,000 tools in one run. Pages after the first do not count toward the 8-request limit; the 10s time limit and the 2MB limit per response still apply. If the list is longer than that, or a later page runs out of the time limit, goes over the 2MB limit (in its request or its response) or is not a readable tool list, we stop reading pages there: this check is still judged on the first page, and nothing that depends on the whole list is recorded as VERIFIED (see each check). Any other failure on a later page (for example the server asking us to back off, or a failed connection) ends the run, as it would on any other request.',
    zh: '服务器把列表分页时，我们沿 nextCursor 读取每一页，一次 run 最多读 10 页或 5,000 个工具。第一页之后的页不计入 8 个请求的上限；10 s 的时间上限和每个回应 2 MB 的上限照样适用。列表超出这个范围，或后面某一页超时、请求或回应超过 2 MB、或读不出工具列表时，我们就停在那里不再翻页：本项仍按第一页判定，依赖完整列表的结论都不记为 VERIFIED（见各项检查）。后面某一页遇到其他失败（例如服务器要求我们稍后再来，或连接失败）时，和其他请求一样，本次 run 就此结束。',
  },
  toolset_fingerprint: {
    en: ' It is computed over every page of the tool list. If we could not read the whole list (see tools_list), no fingerprint is computed and this check is UNVERIFIED.',
    zh: '指纹按工具列表的全部页计算；没能读完整份列表时（见 tools_list）不计算指纹，本项记 UNVERIFIED。',
  },
  schema_fingerprint: {
    en: ' It is computed over every page of the tool list, and is UNVERIFIED when we could not read the whole list.',
    zh: '按工具列表的全部页计算；没能读完整份列表时记 UNVERIFIED。',
  },
  tool_description_hygiene: {
    en: ' We read every page of the tool list. If we could not read the whole list, a hit in the tools we did read is still OBSERVED_RISK, but no hit is UNVERIFIED rather than VERIFIED: the tools we did not see were not checked.',
    zh: '我们读取工具列表的全部页。没能读完整份列表时，已读到的工具里有命中仍记 OBSERVED_RISK；没有命中则记 UNVERIFIED 而不是 VERIFIED，因为没读到的工具没有检查过。',
  },
  toolset_unchanged_vs_approved: {
    en: ' If we could not read the whole tool list, there is nothing to compare and this check is UNVERIFIED.',
    zh: '没能读完整份工具列表时没有可比对的内容，记 UNVERIFIED。',
  },
  schema_unchanged_vs_approved: {
    en: ' If we could not read the whole tool list, it is UNVERIFIED.',
    zh: '没能读完整份工具列表时记 UNVERIFIED。',
  },
  error_taxonomy: {
    en: ' If we could not read the whole tool list (see tools_list), we do not send this call, since the name we would call could belong to a tool we did not see; this check is then UNVERIFIED with reason probe_tool_name_unverifiable, or probe_tool_name_collision when a page we did read lists that name.',
    zh: '没能读完整份工具列表时（见 tools_list），我们不发这次调用，因为要调用的名字可能属于一个没读到的工具；本项记 UNVERIFIED，原因 probe_tool_name_unverifiable；若已读到的某一页列出了这个名字，原因则是 probe_tool_name_collision。',
  },
}

t('suite 0.15.0：七项检查的 how_en / how_zh = registry 0.13.0 的原文 + 恰好一句（逐字固定），其余 explain / predicate 文字一字不动', () => {
  for (const [id, added] of Object.entries(HOW_APPENDED_0140)) {
    const before = FROZEN_0130_REGISTRY.checks.find((c) => c.check_id === id)!
    // Registry 0.15.0 still carries this text for all seven; registry 0.16.0 rewords
    // tool_description_hygiene.how (pinned below).
    const now = FROZEN_0150_REGISTRY.checks.find((c) => c.check_id === id)!
    assert.equal(now.explain.how_en, before.explain.how_en + added.en, `${id}.how_en`)
    assert.equal(now.explain.how_zh, before.explain.how_zh + added.zh, `${id}.how_zh`)
    for (const field of ['what_en', 'what_zh', 'cannot_en', 'cannot_zh'] as const) assert.equal(now.explain[field], before.explain[field], `${id}.${field}`)
    assert.equal(now.predicate_en, before.predicate_en, `${id}.predicate_en`)
    assert.equal(now.predicate_zh, before.predicate_zh, `${id}.predicate_zh`)
  }
})

// Registry 0.16.0 (suite 0.17.0): tool_description_hygiene.how gains the zero-width and the
// injection sentences, inserted after the first sentence; nothing else in checks.json moves
// but that check's docs_version (pinned below). The anomalous-length wording is unchanged.
const HYGIENE_INSERTED_0160 = {
  en: ' A ZWNJ or ZWJ between two characters of one script that uses it in ordinary spelling (Arabic, Devanagari and the other scripts we list), combining marks skipped, is not a hit; nor is a ZWJ directly between two pictographic (emoji) characters, though a ZWJ after a skin-tone modifier still is. "Do not tell the user" (or inform, mention, reveal, show) counts only when followed by "about", "that you", "what you", "how you", "anything", "any of", one of . , ; : ! ) or the end of the text; "system prompt" or "developer prompt" counts only after "your" or after one of reveal, print, output, repeat, disclose, leak, ignore, override, disregard or forget (optionally followed by the, any or all).',
  zh: '夹在同一种文字的两个字符之间（跳过组合附加符号）、属于正常拼写的 ZWNJ / ZWJ（适用于阿拉伯文、天城文等我们列出的文字）不算命中；直接夹在两个图形符号（emoji）字符之间的 ZWJ 也不算，但跟在肤色修饰符后面的 ZWJ 仍算。「do not tell the user」（以及 inform、mention、reveal、show）只在后面紧跟 about、that you、what you、how you、anything、any of、. , ; : ! ) 之一或文本结尾时才算；「system prompt」「developer prompt」只在前面是 your，或是 reveal、print、output、repeat、disclose、leak、ignore、override、disregard、forget 之一（中间可隔 the、any 或 all）时才算。',
}

t('suite 0.17.0：tool_description_hygiene.how_en / how_zh = registry 0.15.0 的原文在第一句后插入两句（逐字固定）；其余检查与其余字段一字不动', () => {
  const before = FROZEN_0150_REGISTRY.checks.find((c) => c.check_id === 'tool_description_hygiene')!
  // Registry 0.16.0 still carries this text; registry 0.17.0 rewrites it (pinned below).
  const now = FROZEN_0160_REGISTRY.checks.find((c) => c.check_id === 'tool_description_hygiene')!
  const enCut = before.explain.how_en.indexOf(' We read every page')
  const zhCut = before.explain.how_zh.indexOf('我们读取工具列表的全部页')
  assert.ok(enCut > 0 && zhCut > 0)
  assert.equal(now.explain.how_en, before.explain.how_en.slice(0, enCut) + HYGIENE_INSERTED_0160.en + before.explain.how_en.slice(enCut))
  assert.equal(now.explain.how_zh, before.explain.how_zh.slice(0, zhCut) + HYGIENE_INSERTED_0160.zh + before.explain.how_zh.slice(zhCut))
  assert.ok(now.explain.how_en.includes('anomalous length') && now.explain.how_zh.includes('异常长度'), 'the length wording stays (deferred to 0.18.0)')
  assert.deepStrictEqual({ ...now, docs_version: before.docs_version, explain: { ...now.explain, how_en: before.explain.how_en, how_zh: before.explain.how_zh } }, before)
  const others = (r: Pick<ChecksRegistry, 'checks'>) => r.checks.filter((c) => c.check_id !== 'tool_description_hygiene')
  assert.deepStrictEqual(others(FROZEN_0160_REGISTRY), others(FROZEN_0150_REGISTRY))
  for (const text of Object.values(HYGIENE_INSERTED_0160)) assert.doesNotMatch(text, /certified|secure|safe|trusted|评分|健康度|通过率/i)
})

// Registry 0.17.0 (suite 0.18.0): tool_description_hygiene.how names the unconfirmed_spending
// signal in its first sentence and replaces the injection sentences with the restored forms
// and the spending phrases and guards; nothing else in checks.json moves but that check's
// docs_version (pinned below). The anomalous-length wording is unchanged (demotion is 0.19.0).
/** Applies each [from, to] pair to `text`, each `from` occurring exactly once. */
const apply = (text: string, pairs: [string, string][]) => pairs.reduce((acc, [from, to]) => {
  assert.equal(acc.split(from).length - 1, 1, `exactly one occurrence of: ${from}`)
  return acc.replace(from, () => to)
}, text)

const HYGIENE_REPLACED_0170: { en: [string, string][]; zh: [string, string][] } = {
  en: [
    ["imperative phrasing directed at an assistant — any hit is recorded as OBSERVED_RISK.",
     "imperative phrasing directed at an assistant, spending or sending identity data without per-action confirmation — any hit is recorded as OBSERVED_RISK."],
    ["\"Do not tell the user\" (or inform, mention, reveal, show) counts only when followed by \"about\", \"that you\", \"what you\", \"how you\", \"anything\", \"any of\", one of . , ; : ! ) or the end of the text; \"system prompt\" or \"developer prompt\" counts only after \"your\" or after one of reveal, print, output, repeat, disclose, leak, ignore, override, disregard or forget (optionally followed by the, any or all).",
     "\"Do not tell the user\" (or inform, mention, reveal, show; \"the\" optional, \"human\" for \"user\") counts when followed by \"about\", \"that you\", \"what you\", \"how you\", \"anything\", \"any of\", one of . , ; : ! ) or the end of the text; it also counts when followed by 's, a spaced hyphen, an en or em dash, a line break, or one of that, what, why, where, how, this or any, unless the rest of that clause has until, unless, yet, before, after, otherwise, once, while, if or when. \"System prompt\" or \"developer prompt\" counts after \"your\" or \"your new\"; after one of reveal, print, output, repeat, disclose, leak, ignore, override, disregard, forget, show, return, display, replace, dump, echo or act as, optionally followed in turn by out, by the, any, all or your, by previous, prior, above, earlier, original or contents of, and by the or your; or at the start of a line (after only spaces, #, *, >, [ or -) when followed by a colon or by \"override\". Spending or sending identity data without per-action confirmation is one of these phrases: \"pay\" followed by \"by default\" in the same sentence within 40 characters; \"no approval\" or \"no confirmation\" followed by needed or required (optionally after \"is\"); \"need not ask\"; \"zero questions\"; \"without asking\", unless never, not or a word ending in n't comes within 30 characters before it in the same sentence, or for or us follows it; \"does not\" or \"doesn't\" \"require\" per-change, per-action, per-call, per-purchase or per-payment \"approval\"; \"the\" grant, allowance or delegation \"is\" the or your permission, approval or consent; accept or approve, then all, every or any, then up to two words, then prompts, confirmations, dialogs or requests; continues, repeats or recurs \"automatically\"; the, your or this \"agent loop\"; \"git config\", then user.email (options such as --get may come between); \"never ask\" (optionally followed by \"the user\") \"before\" charging, paying, buying, purchasing, spending, billing, renewing or subscribing; 无需确认 or 无需另行确认; 视为同意 or 视为用户同意. It counts only when a money or identity word is within 200 characters of it (pay, payer, payment, paid, charge, credit, wallet, USDC, invoice, purchase, buy, subscribe, subscription, renew, bill, cost, fee, refund, spend, money, identity, email, a $ amount, or 扣费, 续费, 费用, 支付, 付款, 购买, 订阅, 钱包, 邮箱, 身份), and no cap, capped, limit, ceiling, max, maximum, policy, mandate, allowlist, whitelist, threshold or quota (or 上限, 额度, 限额, 策略, 白名单) is in the 120 characters before it. A money or identity word does not count when its own clause says it costs nothing or is not sent: \"cost\" or \"costs\" followed by \"nothing\" (up to two words between), \"free\", \"no charge\", \"no cost\" or \"no fee\" (or their plurals), does not, doesn't, do not, don't, never, will not or won't followed by send, collect, store or share (or sends, collects, stores, shares), or 免费 or 不收费; \"free\" right after \"feel\" does not count. A clause ends at . ! or ? followed by a space, at , ; or a line break, or at ，。！？；, and reaches at most 200 characters either side of the word; the same words in another clause change nothing. A phrase does not count when its own clause has \"no purchase\" (or \"no purchases\"), \"read-only\" (or \"read only\"), \"does not\" or \"doesn't\" followed by buy, purchase, register or charge, \"what it costs\" or \"how much\"; the same words in a money or identity word's own clause stop that word from counting, and in any other clause they change nothing."],
  ],
  zh: [
    ["指向助手的祈使句式；命中记 OBSERVED_RISK。",
     "指向助手的祈使句式、未经逐次确认的花费或身份信息发送；命中记 OBSERVED_RISK。"],
    ["「do not tell the user」（以及 inform、mention、reveal、show）只在后面紧跟 about、that you、what you、how you、anything、any of、. , ; : ! ) 之一或文本结尾时才算；「system prompt」「developer prompt」只在前面是 your，或是 reveal、print、output、repeat、disclose、leak、ignore、override、disregard、forget 之一（中间可隔 the、any 或 all）时才算。",
     "「do not tell the user」（以及 inform、mention、reveal、show；the 可省略，user 也可以是 human）在后面紧跟 about、that you、what you、how you、anything、any of、. , ; : ! ) 之一或文本结尾时算；后面紧跟 's、前有空格的连字符、en 或 em 破折号、换行，或 that、what、why、where、how、this、any 之一时也算，除非这个从句余下部分出现 until、unless、yet、before、after、otherwise、once、while、if、when 之一。「system prompt」「developer prompt」在前面是 your 或 your new 时算；前面是 reveal、print、output、repeat、disclose、leak、ignore、override、disregard、forget、show、return、display、replace、dump、echo、act as 之一时算，其后可依次隔 out，the、any、all 或 your，previous、prior、above、earlier、original 或 contents of，以及 the 或 your；位于行首（前面只有空格、#、*、>、[ 或 -）且后面紧跟冒号或 override 时也算。「未经逐次确认的花费或身份信息发送」指出现以下短语之一：pay 后面同一句内 40 个字符以内接 by default；no approval 或 no confirmation 后接 needed 或 required（中间可有 is）；need not ask；zero questions；without asking，但同一句内它前面 30 个字符以内有 never、not 或以 n't 结尾的词，或者它后面接 for 或 us 时不算；does not 或 doesn't require per-change、per-action、per-call、per-purchase 或 per-payment approval；the grant、allowance 或 delegation is the 或 your permission、approval 或 consent；accept 或 approve 后接 all、every 或 any，再隔至多两个词接 prompts、confirmations、dialogs 或 requests；continues、repeats 或 recurs automatically；the、your 或 this agent loop；git config 后接 user.email（中间可以有 --get 之类的选项）；never ask（中间可以有 the user）before 后接 charging、paying、buying、purchasing、spending、billing、renewing 或 subscribing；无需确认或无需另行确认；视为同意或视为用户同意。只有当它前后 200 个字符以内出现花费或身份类的词（pay、payer、payment、paid、charge、credit、wallet、USDC、invoice、purchase、buy、subscribe、subscription、renew、bill、cost、fee、refund、spend、money、identity、email、$ 加金额，或扣费、续费、费用、支付、付款、购买、订阅、钱包、邮箱、身份），并且它前面 120 个字符以内没有 cap、capped、limit、ceiling、max、maximum、policy、mandate、allowlist、whitelist、threshold、quota 或上限、额度、限额、策略、白名单时才算。花费或身份类的词所在的从句如果同时写明不花钱或不发送，这个词就不算：cost 或 costs 后接 nothing（中间至多两个词），free，no charge、no cost 或 no fee（含复数），does not、doesn't、do not、don't、never、will not 或 won't 后接 send、collect、store 或 share（含加 s 的形式），或者免费、不收费；紧跟在 feel 后面的 free 不算。从句在后面跟空格的 . ! ?、在 , ; 或换行、以及在，。！？；处结束，并且向这个词两侧各最多延伸 200 个字符；同样的词出现在别的从句里不起作用。短语所在的从句如果出现 no purchase（或 no purchases）、read-only（或 read only）、does not 或 doesn't 后接 buy、purchase、register 或 charge、what it costs 或 how much，这个短语就不算；这些词出现在某个花费或身份类的词自己的从句里时，那个词不算；出现在其他从句里不起作用。"],
  ],
}

t('suite 0.18.0：tool_description_hygiene.how_en / how_zh = registry 0.16.0 的原文恰好替换两处（逐字固定）；其余检查与其余字段一字不动', () => {
  const before = FROZEN_0160_REGISTRY.checks.find((c) => c.check_id === 'tool_description_hygiene')!
  // Registry 0.17.0 still carries this text; registry 0.18.0 rewrites it (pinned below).
  const now = FROZEN_0170_REGISTRY.checks.find((c) => c.check_id === 'tool_description_hygiene')!
  assert.equal(now.explain.how_en, apply(before.explain.how_en, HYGIENE_REPLACED_0170.en))
  assert.equal(now.explain.how_zh, apply(before.explain.how_zh, HYGIENE_REPLACED_0170.zh))
  assert.ok(now.explain.how_en.includes('spending or sending identity data without per-action confirmation'), 'the approved note wording, en')
  assert.ok(now.explain.how_zh.includes('未经逐次确认的花费或身份信息发送'), 'the approved note wording, zh')
  assert.ok(now.explain.how_en.includes('anomalous length') && now.explain.how_zh.includes('异常长度'), 'the length wording stays (demotion deferred to 0.19.0)')
  assert.deepStrictEqual({ ...now, docs_version: before.docs_version, explain: { ...now.explain, how_en: before.explain.how_en, how_zh: before.explain.how_zh } }, before)
  const others = (r: Pick<ChecksRegistry, 'checks'>) => r.checks.filter((c) => c.check_id !== 'tool_description_hygiene')
  assert.deepStrictEqual(others(FROZEN_0170_REGISTRY), others(FROZEN_0160_REGISTRY))
  for (const [, to] of [...HYGIENE_REPLACED_0170.en, ...HYGIENE_REPLACED_0170.zh]) assert.doesNotMatch(to, /certified|secure|safe|trusted|评分|健康度|通过率/i)
})

// Registry 0.18.0 (suite 0.19.0): tool_description_hygiene.how drops anomalous length from the
// list of risks and says length alone no longer counts; names the unprompted_continuation signal
// and its phrases; adds the resale spending form; and states the boundaries the code uses
// (TODO 1316), and (R14/R15) the conceal-outcome, raise-own-limit and pays-from-owner forms and
// the limit rule's exception. Nothing else in checks.json moves but that check's docs_version (pinned below).
const HYGIENE_REPLACED_0180: { en: [string, string][]; zh: [string, string][] } = {
  en: [
    ["Zero-width characters, Unicode Tag block, bidi override characters, anomalous length, imperative phrasing directed at an assistant, spending or sending identity data without per-action confirmation — any hit is recorded as OBSERVED_RISK.",
     "Zero-width characters, Unicode Tag block, bidi override characters, imperative phrasing directed at an assistant, spending or sending identity data without per-action confirmation, continuing without another user prompt — any hit is recorded as OBSERVED_RISK. A description over 2,048 characters is still listed as anomalous length, but length alone no longer counts as a risk."],
    ["it also counts when followed by 's, a spaced hyphen, an en or em dash, a line break, or one of that, what, why, where, how, this or any, unless the rest of that clause has until, unless, yet, before, after, otherwise, once, while, if or when.",
     "it also counts when followed by 's or ’s, a hyphen with a space or tab before it, an en or em dash, a line break, or one of that, what, why, where, how, this or any, unless the text after it (after a line break, the next line) has until, unless, yet, before, after, otherwise, once, while, if or when before the next . , ; ! ? or line break or ，。！？；."],
    ["or at the start of a line (after only spaces, #, *, >, [ or -) when followed by a colon or by \"override\".",
     "or at the start of a line (after only spaces, tabs, #, *, >, [ or -) when followed, after optional whitespace, by a colon or by \"override\". \"Never\", \"do not\" or \"don't\" (either apostrophe) followed by say, mention, tell, disclose, reveal or state also counts when missing, not verified, unverified, failed or absent comes after it in the same clause, unless because, when, if, unless, since, as or so comes between them."],
    ["\"pay\" followed by \"by default\" in the same sentence within 40 characters;",
     "\"pay\" followed by \"by default\" in the same sentence (ended by . ! ? a line break or 。！？) within 40 characters;"],
    ["\"without asking\", unless never, not or a word ending in n't comes within 30 characters before it in the same sentence,",
     "\"without asking\", unless never, not or a word ending in n't (ASCII apostrophe) comes within 30 characters before it in the same sentence (ended by . ! ? a line break or 。！？),"],
    ["\"require\" per-change, per-action, per-call, per-purchase or per-payment \"approval\";",
     "\"require\" per-change, per-action, per-call, per-purchase or per-payment (or \"per\" and a space) \"approval\";"],
    ["then up to two words, then prompts, confirmations, dialogs or requests;",
     "then up to two words, then prompt, confirmation, dialog or request (or their plurals);"],
    ["视为同意 or 视为用户同意. It counts only when",
     "视为同意 or 视为用户同意; sell, sells, selling, sellable, resell, resells, reselling or resellable, then \"entrusted\" or \"lent\", optionally \"to\", and \"you\", in the same sentence within 80 characters; raise, increase, disable or \"turn off\", optionally the or your, then spendControls (optionally followed by a dot and a name), maxAmountPerPayment, \"spend\" or \"spending\" and limit, limits, cap or caps, or \"payment\" and cap or caps; \"set\", optionally the or your, then one of those, optionally \":\", \"=\" or \"to\", then false or 0 (not followed by a dot, letter, digit or underscore); pays, charges or spends, then within 40 characters in the same sentence \"from\" your owner's, the user's, your human's or the human's (either apostrophe), then credit, credits, balance, wallet or funds, unless that sentence or the next has confirm, confirms, confirmed, confirming, confirmation, confirmations, approve, approves, approved, approving, approval or approvals, or ask, asks, asked or asking followed within 40 characters in the same sentence by \"permission\" (for this form a sentence ends at . ! or ? followed by whitespace or the end of the text, at a line break, or at 。！？, and the two sentences reach at most 400 characters before the start of the phrase and 800 after it). It counts only when"],
    ["(pay, payer, payment, paid, charge, credit, wallet, USDC, invoice, purchase, buy, subscribe, subscription, renew, bill, cost, fee, refund, spend, money, identity, email, a $ amount,",
     "(pay, pays, paid, paying, payer, payment, payments, charge, charges, charged, charging, credit, credits, wallet, wallets, USDC, invoice, invoices, purchase, purchases, purchased, purchasing, buy, buys, buying, subscribe, subscribes, subscribed, subscribing, subscription, subscriptions, renew, renews, renewed, renewal, renewals, bill, bills, billed, billing, cost, costs, fee, fees, refund, refunds, refunded, refundable, spend, spends, spending, money, identity, email, emails, e-mail, e-mails, a $ amount,"],
    ["and no cap, capped, limit, ceiling, max, maximum, policy, mandate, allowlist, whitelist, threshold or quota (or",
     "and no cap, caps, capped, limit, limits, ceiling, ceilings, max, maximum, policy, policies, mandate, mandates, allowlist, allowlisted, whitelist, whitelisted (each also with a hyphen: allow-list, white-list), threshold, thresholds, quota or quotas (or"],
    ["does not, doesn't, do not, don't, never, will not or won't followed by",
     "does not, doesn't, do not, don't, never, will not or won't (ASCII apostrophe) followed by"],
    ["A clause ends at . ! or ? followed by a space, at , ; or a line break, or at ，。！？；, and reaches at most 200 characters either side of the word;",
     "A clause ends at . ! or ? followed by whitespace or the end of the text, at , ; or a line break, or at ，。！？；, and reaches at most 200 characters either side of the first character of the word;"],
    ["We read every page of the tool list.",
     "Continuing without another user prompt is \"without\", optionally \"waiting for\", then another, a further, any further, further, a new, a second, an additional or additional, then user or human, then prompt, message, request, turn or reply (or their plurals). We read every page of the tool list."],
    ["is in the 120 characters before it. A money or identity word does not count",
     "is in the 120 characters before it (this does not apply to raising or switching off a limit). A money or identity word does not count"],
  ],
  zh: [
    ["零宽字符、Unicode Tag 区、双向覆盖符、异常长度、指向助手的祈使句式、未经逐次确认的花费或身份信息发送；命中记 OBSERVED_RISK。",
     "零宽字符、Unicode Tag 区、双向覆盖符、指向助手的祈使句式、未经逐次确认的花费或身份信息发送、不等用户再次提出就继续工作；命中记 OBSERVED_RISK。超过 2,048 个字符的描述仍会列为异常长度，但仅凭长度不再算作风险。"],
    ["后面紧跟 's、前有空格的连字符、en 或 em 破折号、换行，或 that、what、why、where、how、this、any 之一时也算，除非这个从句余下部分出现 until、unless、yet、before、after、otherwise、once、while、if、when 之一。",
     "后面紧跟 's 或 ’s、前有空格或制表符的连字符、en 或 em 破折号、换行，或 that、what、why、where、how、this、any 之一时也算，除非在它之后（如果是换行，就是下一行）到下一个 . , ; ! ?、换行或，。！？；之前出现 until、unless、yet、before、after、otherwise、once、while、if、when 之一。"],
    ["位于行首（前面只有空格、#、*、>、[ 或 -）且后面紧跟冒号或 override 时也算。",
     "位于行首（前面只有空格、制表符、#、*、>、[ 或 -）且后面（可隔空白）是冒号或 override 时也算。「never」「do not」或「don't」（两种撇号均可）后接 say、mention、tell、disclose、reveal 或 state，并且同一从句里它后面出现 missing、not verified、unverified、failed 或 absent 时也算，除非两者之间出现 because、when、if、unless、since、as 或 so。"],
    ["pay 后面同一句内 40 个字符以内接 by default；",
     "pay 后面同一句内（句子在 . ! ?、换行或。！？处结束）40 个字符以内接 by default；"],
    ["without asking，但同一句内它前面 30 个字符以内有 never、not 或以 n't 结尾的词，",
     "without asking，但同一句内（句子在 . ! ?、换行或。！？处结束）它前面 30 个字符以内有 never、not 或以 n't（ASCII 撇号）结尾的词，"],
    ["require per-change、per-action、per-call、per-purchase 或 per-payment approval；",
     "require per-change、per-action、per-call、per-purchase 或 per-payment approval（per 后面也可以是空格）；"],
    ["再隔至多两个词接 prompts、confirmations、dialogs 或 requests；",
     "再隔至多两个词接 prompt、confirmation、dialog 或 request（单复数均可）；"],
    ["视为同意或视为用户同意。只有当它",
     "视为同意或视为用户同意；sell、sells、selling、sellable、resell、resells、reselling 或 resellable，同一句内 80 个字符以内再接 entrusted 或 lent、可选的 to 和 you；raise、increase、disable 或 turn off，可隔 the 或 your，再接 spendControls（其后可带一个点和名称）、maxAmountPerPayment、spend 或 spending 加 limit、limits、cap 或 caps，或 payment 加 cap 或 caps；set，可隔 the 或 your，再接上述之一，可再接 :、= 或 to，再接 false 或 0（后面不能紧跟点、字母、数字或下划线）；pays、charges 或 spends 后面同一句内 40 个字符以内接 from，再接 your owner's、the user's、your human's 或 the human's（两种撇号均可），再接 credit、credits、balance、wallet 或 funds，但这一句或下一句里出现 confirm、confirms、confirmed、confirming、confirmation、confirmations、approve、approves、approved、approving、approval 或 approvals，或 ask、asks、asked 或 asking 后面同一句内 40 个字符以内接 permission 时不算（这一种里，句子在后面跟空白或位于文本结尾的 . ! ?、换行或。！？处结束，两句合计从短语起点向前最多 400 个字符、向后最多 800 个字符）。只有当它"],
    ["（pay、payer、payment、paid、charge、credit、wallet、USDC、invoice、purchase、buy、subscribe、subscription、renew、bill、cost、fee、refund、spend、money、identity、email、$ 加金额，",
     "（pay、pays、paid、paying、payer、payment、payments、charge、charges、charged、charging、credit、credits、wallet、wallets、USDC、invoice、invoices、purchase、purchases、purchased、purchasing、buy、buys、buying、subscribe、subscribes、subscribed、subscribing、subscription、subscriptions、renew、renews、renewed、renewal、renewals、bill、bills、billed、billing、cost、costs、fee、fees、refund、refunds、refunded、refundable、spend、spends、spending、money、identity、email、emails、e-mail、e-mails、$ 加金额，"],
    ["没有 cap、capped、limit、ceiling、max、maximum、policy、mandate、allowlist、whitelist、threshold、quota 或",
     "没有 cap、caps、capped、limit、limits、ceiling、ceilings、max、maximum、policy、policies、mandate、mandates、allowlist、allowlisted、whitelist、whitelisted（也可带连字符：allow-list、white-list）、threshold、thresholds、quota、quotas 或"],
    ["does not、doesn't、do not、don't、never、will not 或 won't 后接",
     "does not、doesn't、do not、don't、never、will not 或 won't（ASCII 撇号）后接"],
    ["从句在后面跟空格的 . ! ?、在 , ; 或换行、以及在，。！？；处结束，并且向这个词两侧各最多延伸 200 个字符；",
     "从句在后面跟空白或位于文本结尾的 . ! ?、在 , ; 或换行、以及在，。！？；处结束，并且从这个词的第一个字符起向两侧各最多延伸 200 个字符；"],
    ["我们读取工具列表的全部页。",
     "「不等用户再次提出就继续工作」指 without 后面（可隔 waiting for）接 another、a further、any further、further、a new、a second、an additional 或 additional，再接 user 或 human，再接 prompt、message、request、turn 或 reply（单复数均可）。我们读取工具列表的全部页。"],
    ["上限、额度、限额、策略、白名单时才算。",
     "上限、额度、限额、策略、白名单时才算（提高或关闭上限的那一种不受这一条限制）。"],
  ],
}
t('suite 0.19.0：tool_description_hygiene.how_en / how_zh = registry 0.17.0 的原文恰好替换十四处（逐字固定）；其余检查与其余字段一字不动', () => {
  const before = FROZEN_0170_REGISTRY.checks.find((c) => c.check_id === 'tool_description_hygiene')!
  const now = CHECKS_REGISTRY.checks.find((c) => c.check_id === 'tool_description_hygiene')!
  assert.equal(now.explain.how_en, apply(before.explain.how_en, HYGIENE_REPLACED_0180.en))
  assert.equal(now.explain.how_zh, apply(before.explain.how_zh, HYGIENE_REPLACED_0180.zh))
  assert.ok(now.explain.how_en.includes('length alone no longer counts as a risk') && now.explain.how_zh.includes('仅凭长度不再算作风险'), 'the demotion is stated')
  assert.ok(!now.explain.how_en.includes('bidi override characters, anomalous length,') && !now.explain.how_zh.includes('双向覆盖符、异常长度、'), 'anomalous length is no longer in the list of risks')
  assert.deepStrictEqual({ ...now, docs_version: before.docs_version, explain: { ...now.explain, how_en: before.explain.how_en, how_zh: before.explain.how_zh } }, before)
  const others = (r: Pick<ChecksRegistry, 'checks'>) => r.checks.filter((c) => c.check_id !== 'tool_description_hygiene')
  assert.deepStrictEqual(others(CHECKS_REGISTRY), others(FROZEN_0170_REGISTRY))
  for (const [, to] of [...HYGIENE_REPLACED_0180.en, ...HYGIENE_REPLACED_0180.zh]) assert.doesNotMatch(to, /\b(certified|secure|safe|trusted)\b|评分|健康度|通过率|付费/i) // whole words: the quoted phrase "entrusted" is not "trusted"
})

t('no_baseline_reason：两项基线检查的「没有基线」原因逐字固定，且不把「未认领」当作原因（已认领但未确认基线的 target 也走这条）', () => {
  const withReason = CHECKS_REGISTRY.checks.filter((c) => c.no_baseline_reason_en !== undefined || c.no_baseline_reason_zh !== undefined)
  assert.deepEqual(withReason.map((c) => c.check_id).sort(), ['schema_unchanged_vs_approved', 'toolset_unchanged_vs_approved'])
  for (const c of withReason) {
    assert.equal(c.no_baseline_reason_en, 'No approved baseline exists for this target.', c.check_id)
    assert.equal(c.no_baseline_reason_zh, '该 target 没有已批准基线', c.check_id)
    assert.doesNotMatch(`${c.no_baseline_reason_en} ${c.no_baseline_reason_zh}`, /unclaimed|未认领|未被认领/i, c.check_id)
  }
})

// redirect_policy (registry 0.10.0): only auth.ts's metadata GET follows redirects
// (wire.ts sendRequest, `method === 'GET'`, up to budget.maxRedirects); a protocol POST's
// 3xx is that call's terminal response, with the cross-host Location still recorded.
// Suite 0.15.0 (registry 0.14.0, TODO 779 / 797): plus one sentence — a cross-host
// redirect seen before an abort is still recorded (probe.ts's catch).
t('redirect_policy.how_en 与签字原文逐字相同', () => {
  assert.equal(how('redirect_policy').how_en, `A cross-host redirect is recorded as OBSERVED_RISK. Only the GET for authorization metadata follows redirects, for at most 3 hops; a protocol POST that gets a redirect is recorded, not followed. A cross-host redirect is recorded even when the run stops afterwards, for example at the hop limit, at another host we do not connect to, or because the server asked us to back off.`)
})

t('redirect_policy.how_zh 与签字原文逐字相同', () => {
  assert.equal(how('redirect_policy').how_zh, `跨主机重定向记 OBSERVED_RISK。只有读取授权元数据的 GET 会跟随重定向，最多 3 跳；协议 POST 收到重定向时只记录，不跟随。即使 run 在这之后停止（例如超过跳数上限、遇到我们不连接的另一个主机，或服务器要求我们稍后再来），已观察到的跨主机重定向也照样记录。`)
})

t('redirect_policy.how 不再写「所有请求都跟随」的旧说法，写的跳数等于 checks.json 的 budget.max_redirects', () => {
  const h = how('redirect_policy')
  assert.doesNotMatch(h.how_en, /Followed for at most/)
  assert.doesNotMatch(h.how_zh, /最多跟 3 跳。/)
  assert.equal(CHECKS_REGISTRY.budget.max_redirects, 3)
})

// docs_version enters every signed assertion (probe.ts docsVersionFor), and moves when
// that one check changes (README). Registry 0.14.0 (suite 0.15.0) moves the ten checks
// whose conclusions or how text changed: reachability (how: the further tools/list pages),
// tools_list, the two fingerprints, tool_description_hygiene, the two baseline checks and
// error_taxonomy (an incomplete tool list), redirect_policy (recorded before an abort), and
// auth_metadata (the reserved-name call now goes out on a complete list of several pages,
// where suite 0.14.0 withheld it on a first-page nextCursor).
// Every other value is registry 0.13.0's (frozen/suite-0.14.0/checks.json).
// Registry 0.15.0 (suite 0.16.0) moves latency_profile alone (v0.3.0: it is measured);
// every other value is registry 0.14.0's (frozen/suite-0.15.0/checks.json).
// Registry 0.16.0 (suite 0.17.0) moves tool_description_hygiene alone (v0.3.0: the zero-width
// and injection rules narrow); every other value is registry 0.15.0's
// (frozen/suite-0.16.0/checks.json).
// Registry 0.17.0 (suite 0.18.0) moves tool_description_hygiene alone (v0.4.0: unconfirmed_spending
// and the restored injection forms); every other value is registry 0.16.0's
// (frozen/suite-0.17.0/checks.json).
// Registry 0.18.0 (suite 0.19.0) moves tool_description_hygiene alone (v0.5.0: length alone no
// longer counts, unprompted_continuation, the resale form, TODO 1316); every other value is
// registry 0.17.0's (frozen/suite-0.18.0/checks.json). A later bump of any check updates these
// tables in the same change, deliberately.
t('docs_version：registry 0.18.0 只动 tool_description_hygiene（v0.5.0），其余 14 项与 registry 0.17.0 的 checks.json 逐条相同', () => {
  const previousRegistry = Object.fromEntries(FROZEN_0170_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0170_REGISTRY.registry_version, '0.17.0')
  assert.equal(CHECKS_REGISTRY.registry_version, '0.18.0')
  const now = Object.fromEntries(CHECKS_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(CHECKS_REGISTRY.checks.length, Object.keys(now).length, 'check_id 不得重复')
  assert.deepStrictEqual(now, { ...previousRegistry, tool_description_hygiene: 'v0.5.0' })
  assert.equal(previousRegistry.tool_description_hygiene, 'v0.4.0')
})

t('docs_version：registry 0.17.0 只动 tool_description_hygiene（v0.4.0），其余 14 项与 registry 0.16.0 的 checks.json 逐条相同', () => {
  const previousRegistry = Object.fromEntries(FROZEN_0160_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0160_REGISTRY.registry_version, '0.16.0')
  assert.equal(FROZEN_0170_REGISTRY.registry_version, '0.17.0')
  const now = Object.fromEntries(FROZEN_0170_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0170_REGISTRY.checks.length, Object.keys(now).length, 'check_id 不得重复')
  assert.deepStrictEqual(now, { ...previousRegistry, tool_description_hygiene: 'v0.4.0' })
  assert.equal(previousRegistry.tool_description_hygiene, 'v0.3.0')
})

t('docs_version：registry 0.16.0 只动 tool_description_hygiene（v0.3.0），其余 14 项与 registry 0.15.0 的 checks.json 逐条相同', () => {
  const previousRegistry = Object.fromEntries(FROZEN_0150_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0150_REGISTRY.registry_version, '0.15.0')
  assert.equal(FROZEN_0160_REGISTRY.registry_version, '0.16.0')
  const now = Object.fromEntries(FROZEN_0160_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0160_REGISTRY.checks.length, Object.keys(now).length, 'check_id 不得重复')
  assert.deepStrictEqual(now, { ...previousRegistry, tool_description_hygiene: 'v0.3.0' })
  assert.equal(previousRegistry.tool_description_hygiene, 'v0.2.0')
})

t('docs_version：registry 0.15.0 只动 latency_profile（v0.3.0），其余 14 项与 registry 0.14.0 的 checks.json 逐条相同', () => {
  const previousRegistry = Object.fromEntries(FROZEN_0140_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0140_REGISTRY.registry_version, '0.14.0')
  assert.equal(FROZEN_0150_REGISTRY.registry_version, '0.15.0')
  const now = Object.fromEntries(FROZEN_0150_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0150_REGISTRY.checks.length, Object.keys(now).length, 'check_id 不得重复')
  assert.deepStrictEqual(now, { ...previousRegistry, latency_profile: 'v0.3.0' })
  assert.equal(previousRegistry.latency_profile, 'v0.2.0')
})

t('docs_version：registry 0.14.0 动了十项检查（各升一个次版本），其余 5 项与 registry 0.13.0 的 checks.json 逐条相同', () => {
  const previousRegistry = Object.fromEntries(FROZEN_0130_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0130_REGISTRY.registry_version, '0.13.0')
  assert.equal(FROZEN_0140_REGISTRY.registry_version, '0.14.0')
  const now = Object.fromEntries(FROZEN_0140_REGISTRY.checks.map((c) => [c.check_id, c.docs_version]))
  assert.equal(FROZEN_0140_REGISTRY.checks.length, Object.keys(now).length, 'check_id 不得重复')
  assert.deepStrictEqual(now, {
    ...previousRegistry,
    reachability: 'v0.5.0',
    tools_list: 'v0.3.0',
    error_taxonomy: 'v0.3.0',
    redirect_policy: 'v0.3.0',
    auth_metadata: 'v0.3.0',
    tool_description_hygiene: 'v0.2.0',
    toolset_fingerprint: 'v0.2.0',
    schema_fingerprint: 'v0.2.0',
    toolset_unchanged_vs_approved: 'v0.2.0',
    schema_unchanged_vs_approved: 'v0.2.0',
  })
  assert.deepStrictEqual(previousRegistry, {
    reachability: 'v0.4.0', latency_profile: 'v0.2.0', transport_type: 'v0.2.0', protocol_revision: 'v0.2.0', discovery_handshake: 'v0.3.0',
    tools_list: 'v0.2.0', error_taxonomy: 'v0.2.0', tls_certificate: 'v0.1.0', redirect_policy: 'v0.2.0', auth_metadata: 'v0.2.0',
    tool_description_hygiene: 'v0.1.0', toolset_fingerprint: 'v0.1.0', schema_fingerprint: 'v0.1.0', toolset_unchanged_vs_approved: 'v0.1.0', schema_unchanged_vs_approved: 'v0.1.0',
  })
})

// latency_profile (registry 0.15.0, suite 0.16.0, docs v0.3.0): measured, time to response
// headers, no verdict. Pinned verbatim, so a copy swap is one exact-once replacement. Registry
// 0.11.0's "not measured yet" text is frozen/suite-0.15.0/checks.json's.
t('latency_profile（v0.3.0）：predicate / what / how / cannot 逐字固定；不设阈值、不排名、无禁用词', () => {
  const def = CHECKS_REGISTRY.checks.find((c) => c.check_id === 'latency_profile')!
  assert.equal(def.docs_version, 'v0.3.0')
  assert.equal(def.observation_only, true)
  assert.equal(def.failure_status, null)
  assert.equal(def.predicate_en, 'p50 / p95 response time of our requests, measured from our probe node')
  assert.equal(def.predicate_zh, '从我们探测节点测得的请求响应时间 p50 / p95')
  assert.equal(def.explain.what_en, 'Within one run: the median (p50) and 95th-percentile (p95) time from sending a request to this endpoint to receiving its response headers, and how many requests were timed (n).')
  assert.equal(def.explain.what_zh, '单次 run 内，我们发往该 endpoint 的请求从发出到收到响应头的耗时：中位数（p50）、第 95 百分位（p95），以及计时的请求数 n。')
  assert.equal(def.explain.how_en, '**No verdict is made.** VERIFIED means the time was measured, not that it was fast: we set no threshold and do not rank servers by speed. Every request to the endpoint in the run that got an HTTP response is timed, whatever its status; a request that got none is not. The timer runs from just before the request is sent until the response headers arrive, so our own DNS checks and the download of the body are not included. p50 and p95 are nearest-rank values over the n timed requests; with fewer than 20 requests, p95 is the slowest of them. A run that stops at an authentication challenge during the handshake records no time. With no timed request, this check is UNVERIFIED.')
  assert.equal(def.explain.how_zh, '**不做判定。** VERIFIED 只表示测到了，不表示快：我们不设阈值，也不按速度给 server 排名。本轮中发往该 endpoint、收到 HTTP 回应的每个请求都计时，不论状态码；没收到回应的不计。计时从请求发出前开始，到收到响应头为止，不含我们自己的 DNS 校验，也不含响应体的下载。p50、p95 按最近秩取自 n 个计时请求；少于 20 个请求时，p95 就是其中最慢的一个。握手阶段就停在认证质询的运行不记录时间。一个计时请求都没有时，本项记 UNVERIFIED。')
  assert.equal(def.explain.cannot_en, 'This is what our probe node observed, not what your users see. It includes the network between our node and your endpoint, setting up the connection, and any wait inside our own Worker.')
  assert.equal(def.explain.cannot_zh, '这是我们探测节点看到的值，不代表你的用户看到的值。其中包含我们节点到你 endpoint 之间的网络、建立连接的时间，以及在我们自己 Worker 里的等待。')
  const prev = FROZEN_0140_REGISTRY.checks.find((c) => c.check_id === 'latency_profile')!
  assert.equal(prev.predicate_en, 'p50 / p95 request latency (not measured yet)')
  for (const text of [def.predicate_en, def.predicate_zh, ...Object.values(def.explain)]) {
    assert.doesNotMatch(text, /certified|secure|safe|trusted|评分|健康度|通过率/i, text)
    assert.doesNotMatch(text, /not measured yet|尚未测量|observable within budget|在预算内可观测/, text)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
