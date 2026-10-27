/**
 * tool_description_hygiene — PRD v1.4 §5.2 检查 13
 *
 * 只报告观察到的信号，不推断意图。命中 → OBSERVED_RISK，绝不是 FAILED。
 * 输入是 server 完全可控的自由文本；本模块自身不得对其做任何解析或求值。
 */

export type HygieneFlag =
  | 'zero_width_chars'
  | 'unicode_tag_chars'
  | 'bidi_override'
  | 'private_use_area'
  | 'excessive_length'
  | 'injection_imperative'
  | 'pseudo_system_delimiter'
  | 'embedded_markup'
  | 'non_ascii_tool_name'
  | 'unconfirmed_spending'

export interface HygieneHit {
  flag: HygieneFlag
  /** 面向人的一句话，会进 assertion.details，带 Warn: 前缀 */
  note: string
  /** 命中位置（字符下标），便于在 UI 上锚定 */
  at?: number
  /** 命中的原文片段，已截断；渲染时必须转义 */
  sample?: string
}

const MAX_DESCRIPTION_LEN = 2048

// 不可见 / 格式控制字符
const ZERO_WIDTH = /[​-‏⁠-⁤﻿᠎]/u
// Unicode Tag 区：可完整编码一段隐藏 ASCII 文本
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/u
// 双向覆盖：可让显示顺序与实际字节顺序不一致
const BIDI = /[‪-‮⁦-⁩]/u
const PUA = /[\u{E000}-\u{F8FF}\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}]/u

/*
 * Suite 0.17.0: a ZWNJ (U+200C) or ZWJ (U+200D) is not a signal where ordinary
 * orthography puts it. In these scripts the Unicode Standard uses the two
 * characters for spelling, not for hiding text: cursive joining control in
 * Arabic and Syriac, and Indic conjunct and half-form control in the Brahmic
 * scripts listed (Sinhala included). Thaana is listed because it is written
 * with Arabic-script punctuation and ZWNJ appears inside it in the same way.
 * Both neighbours (combining marks skipped) must share one of these scripts.
 * A ZWJ between two Extended_Pictographic characters is an emoji ZWJ sequence.
 * Everything else still counts: every other zero-width character, a ZWNJ/ZWJ at
 * either end, next to another zero-width character, between ASCII, between two
 * different scripts, or next to an unassigned (Cn) code point. The Cn rule
 * keeps an engine whose Unicode data is older from treating a character it
 * does not know as compliant.
 */
const ORTHOGRAPHIC_SCRIPTS: RegExp[] = [
  /\p{Script_Extensions=Arabic}/u, /\p{Script_Extensions=Devanagari}/u, /\p{Script_Extensions=Bengali}/u,
  /\p{Script_Extensions=Gurmukhi}/u, /\p{Script_Extensions=Gujarati}/u, /\p{Script_Extensions=Oriya}/u,
  /\p{Script_Extensions=Tamil}/u, /\p{Script_Extensions=Telugu}/u, /\p{Script_Extensions=Kannada}/u,
  /\p{Script_Extensions=Malayalam}/u, /\p{Script_Extensions=Sinhala}/u, /\p{Script_Extensions=Syriac}/u,
  /\p{Script_Extensions=Thaana}/u,
]
const MARK = /\p{M}/u
const UNASSIGNED = /\p{Cn}/u
const PICTOGRAPHIC = /\p{Extended_Pictographic}/u
const ZWNJ = 0x200c
const ZWJ = 0x200d

/** The code point ending just before UTF-16 index `end`, combining marks skipped. */
function letterBefore(text: string, end: number): string | undefined {
  let i = end
  while (i > 0) {
    const lowAt = i - 1
    const start = lowAt > 0 && /[\uDC00-\uDFFF]/.test(text[lowAt]!) && /[\uD800-\uDBFF]/.test(text[lowAt - 1]!) ? lowAt - 1 : lowAt
    const ch = String.fromCodePoint(text.codePointAt(start)!)
    if (!MARK.test(ch)) return ch
    i = start
  }
  return undefined
}

/** The code point starting at UTF-16 index `start` or later, combining marks skipped. */
function letterAfter(text: string, start: number): string | undefined {
  let i = start
  while (i < text.length) {
    const ch = String.fromCodePoint(text.codePointAt(i)!)
    if (!MARK.test(ch)) return ch
    i += ch.length
  }
  return undefined
}

/** Whether the zero-width character at `at` sits where ordinary orthography puts it. */
function orthographicJoiner(text: string, at: number): boolean {
  const cp = text.charCodeAt(at)
  if (cp !== ZWNJ && cp !== ZWJ) return false
  // A run of two or more always counts: neither raw neighbour may be zero-width.
  if ((at > 0 && ZERO_WIDTH.test(text[at - 1]!)) || (at + 1 < text.length && ZERO_WIDTH.test(text[at + 1]!))) return false
  const before = letterBefore(text, at)
  const after = letterAfter(text, at + 1)
  if (before === undefined || after === undefined || UNASSIGNED.test(before) || UNASSIGNED.test(after)) return false
  if (cp === ZWJ && PICTOGRAPHIC.test(before) && PICTOGRAPHIC.test(after)) return true
  return ORTHOGRAPHIC_SCRIPTS.some((script) => script.test(before) && script.test(after))
}

/** The first zero-width character that is a signal, or null. */
function zeroWidthSignal(text: string): { index: number; char: string } | null {
  const all = new RegExp(ZERO_WIDTH.source, 'gu')
  for (let m = all.exec(text); m !== null; m = all.exec(text)) {
    if (!orthographicJoiner(text, m.index)) return { index: m.index, char: m[0] }
  }
  return null
}

/** 指向助手而非描述工具本身的祈使句式 */
const IMPERATIVES: [RegExp, string][] = [
  [/\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\b/i, '包含「ignore previous」类指令'],
  [/\bdisregard\s+(all\s+|any\s+)?(previous|prior|above|the)\b/i, '包含「disregard previous」类指令'],
  // Suite 0.17.0: only when what follows "the user" makes it concealment from the
  // user (about…, that you…, what you…, anything, or the clause ends there).
  // "Do not tell the user X until Y" is an ordinary flow instruction and no
  // longer counts.
  // Suite 0.18.0 also counts 's, a spaced dash, a line break, or that / what / why /
  // where / how / this / any next, unless the clause that follows has a flow
  // word (until, unless, yet, before, after, otherwise, once, while, if, when).
  // Every alternative is suite 0.16.0's pattern followed by a lookahead, so it
  // can only flag what 0.16.0 flagged.
  [/\bdo\s+not\s+(tell|inform|mention|reveal|show)\s+(the\s+)?(user|human)\b(?=\s*([.,;:!)]|$|(about|that\s+you|what\s+you|how\s+you|anything|any\s+of)\b)|(['’]s\b|[ \t]+-|[ \t]*[–—]|[ \t]*\r?\n|\s+(that|what|why|where|how|this|any)\b)(?![^.;!?\n]*?\b(until|unless|yet|before|after|otherwise|once|while|if|when)\b))/i,
   '要求对用户隐瞒信息'],
  // Suite 0.17.0: only the prompt of the assistant reading this ("your system
  // prompt"), or one being extracted or overridden. A system_prompt parameter, an
  // agent's configured prompt, or "never treat it as a system prompt" no longer counts.
  // Suite 0.18.0 widens the verbs (show, return, display, replace, dump, echo,
  // act as), allows out / previous / prior / above / earlier / original /
  // contents of between, and counts "your new …" and a line that starts with
  // "system prompt:" or "system prompt override". Each alternative contains
  // suite 0.16.0's whole pattern, so it can only flag what 0.16.0 flagged.
  [/\byour\s+(new\s+)?(system|developer)\s+prompt\b|\b(reveal|print|output|repeat|disclose|leak|ignore|override|disregard|forget|show|return|display|replace|dump|echo|act\s+as)\s+(out\s+)?(the\s+|any\s+|all\s+|your\s+)?((previous|prior|above|earlier|original|contents\s+of)\s+)?(the\s+|your\s+)?(system|developer)\s+prompt\b|(?<=^|\n)[ \t#*>[-]*(system|developer)\s+prompt\b\s*(:|override\b)/i,
   '提及 system / developer prompt'],
  [/\byou\s+(must|should|shall)\s+(always|never)\b/i, '对助手下达绝对指令'],
  [/\bbefore\s+(using|calling)\s+any\s+other\s+tool\b/i, '试图抢占其他工具的调用顺序'],
  // 只匹配「动词 + 具体的敏感文件路径」。刻意不匹配 secret / api key 等普通词——
  // 否则会把合法的密钥管理类 MCP 全部误报，而误报是这条检查最大的风险。
  [/\b(read|send|upload|post|exfiltrate|dump|cat)\b[\s\S]{0,40}(\.env\b|~\/\.ssh|\bid_rsa\b|\.aws\/credentials|\bnetrc\b|\.npmrc\b)/i,
   '提及读取或外发具体的凭据文件'],
]

/** 伪造的系统边界标记 */
const PSEUDO_DELIM = /<\/?(system|instructions?|important|assistant|user)\s*>|\[\/?INST\]|<\|[a-z_]+\|>/i
/** 可能被下游渲染器执行的标记 */
const EMBEDDED_MARKUP = /<script\b|<iframe\b|\bon(error|load|click)\s*=|javascript:/i

/*
 * Suite 0.18.0: unconfirmed_spending — text that steers the assistant to spend,
 * or to send identity data, without a confirmation for each action. A phrase
 * counts only where it is about money or identity and not inside a limit the
 * user set: a SPEND_OR_IDENTITY word must occur within 200 characters either
 * side of it, and no LIMIT word in the 120 characters before it (spending under
 * the user's own cap, allowlist or policy is not a missing confirmation). A
 * money or identity word does not count when its own clause says it costs
 * nothing or is not sent (NO_COST_OR_NOT_SENT); a "free" in another clause
 * changes nothing. A no-spend action or a price question (NO_SPEND_ACTION) in
 * the phrase's own clause cancels the phrase, and in a money or identity
 * word's clause cancels that word.
 */
export const UNCONFIRMED_SPENDING_PHRASES: readonly RegExp[] = [
  /\bpay\b[^.!?\n]{0,40}?\bby\s+default\b/i,
  /\bno\s+(approval|confirmation)\s+(is\s+)?(needed|required)\b/i,
  /\bneed\s+not\s+ask\b|\bzero\s+questions\b/i,
  // Not after never / not / don't ("never buy without asking"), and not asking
  // for something or asking us.
  /\bwithout(?<!\b(never|not|\w+n't)\b[^.!?\n]{0,30}without)\s+asking\b(?!\s+(for|us)\b)/i,
  /\bdoes(\s+not|n't)\s+require\s+per[- ](change|action|call|purchase|payment)\s+approval\b/i,
  /\bthe\s+(grant|allowance|delegation)\s+is\s+(the|your)\s+(permission|approval|consent)\b/i,
  /无需(另行)?确认|视为(用户)?同意/,
  // Accepting every prompt on the user's behalf; an action that keeps going on
  // its own; an agent loop that calls again; reading the local git identity.
  /\b(accept|approve)\s+(all|every|any)\s+(\w+\s+){0,2}?(prompts?|confirmations?|dialogs?|requests?)\b/i,
  /\b(continues|repeats|recurs)\s+automatically\b/i,
  /\b(the|your|this)\s+agent\s+loop\b/i,
  /\bgit\s+config\s+(--\w+\s+)*user\.email\b/i,
  // "Never ask (the user) before charging" and the other spending verbs.
  /\bnever\s+ask\s+(the\s+user\s+)?before\s+(charging|paying|buying|purchasing|spending|billing|renewing|subscribing)\b/i,
]
/** Money and identity words: pay, charge, credit, wallet, USDC, invoice, purchase, subscription, renew, bill, cost, fee, refund, identity, email. */
const SPEND_OR_IDENTITY = /\b(pay|pays|paid|paying|payer|payments?|charg(e|es|ed|ing)|credits?|wallets?|usdc|invoices?|purchas(e|es|ed|ing)|buy(s|ing)?|subscri(be|bes|bed|bing|ption|ptions)|renew(s|ed|al|als)?|bill(s|ed|ing)?|costs?|fees?|refund(s|ed|able)?|spend(s|ing)?|money|identity|e-?mails?)\b|\$\s?\d|扣费|续费|费用|支付|付款|购买|订阅|钱包|邮箱|身份/i
/** Cap, limit, policy and allowlist words. */
const LIMIT = /\b(caps?|capped|limits?|ceilings?|max|maximum|polic(y|ies)|mandates?|allow-?list(ed)?|white-?list(ed)?|thresholds?|quotas?)\b|上限|额度|限额|策略|白名单/i
/** No-cost and not-sent phrases: a money or identity word in the same clause does not count. */
const NO_COST_OR_NOT_SENT = /\bcosts?\s+(\w+\s+){0,2}?nothing\b|(?<!\bfeel\s+)\bfree\b|\bno\s+(charges?|costs?|fees?)\b|\b(does\s+not|doesn't|do\s+not|don't|never|will\s+not|won't)\s+(send|collect|store|share)s?\b|免费|不收费/i
/** No-spend actions and price questions: in the phrase's clause they cancel the phrase; in a money or identity word's clause, that word. */
const NO_SPEND_ACTION = /\bno\s+purchases?\b|\bread[- ]only\b|\b(does\s+not|doesn't)\s+(buy|purchase|register|charge)\b|\bwhat\s+it\s+costs\b|\bhow\s+much\b/i
/** A clause ends at . ! ? followed by whitespace or the end, at , ; or a line break, or at ，。！？；. */
const isClauseEnd = (text: string, i: number) =>
  /[,;\n，。！？；]/.test(text[i]!) || (/[.!?]/.test(text[i]!) && (i + 1 === text.length || /\s/.test(text[i + 1]!)))

/** The clause around index `at`, at most 200 characters either side of it. */
function clauseAt(text: string, at: number): string {
  let start = at, end = at
  while (start > 0 && at - start < 200 && !isClauseEnd(text, start - 1)) start--
  while (end < text.length && end - at < 200 && !isClauseEnd(text, end)) end++
  return text.slice(start, end)
}

/** Whether a money or identity word in text[from, to) sits in a clause with no no-cost, not-sent or no-spend phrase. */
function spendOrIdentityNear(text: string, from: number, to: number): boolean {
  const words = new RegExp(SPEND_OR_IDENTITY.source, 'gi')
  const near = text.slice(from, to)
  for (let w = words.exec(near); w !== null; w = words.exec(near)) {
    const clause = clauseAt(text, from + w.index)
    if (!NO_COST_OR_NOT_SENT.test(clause) && !NO_SPEND_ACTION.test(clause)) return true
  }
  return false
}

/** The earliest phrase of UNCONFIRMED_SPENDING_PHRASES that the guards let through, or null. */
function unconfirmedSpending(text: string): number | null {
  let first: number | null = null
  for (const pattern of UNCONFIRMED_SPENDING_PHRASES) {
    const all = new RegExp(pattern.source, pattern.flags + 'g')
    for (let m = all.exec(text); m !== null && (first === null || m.index < first); m = all.exec(text)) {
      if (NO_SPEND_ACTION.test(clauseAt(text, m.index))) continue
      const near = spendOrIdentityNear(text, Math.max(0, m.index - 200), m.index + m[0].length + 200)
      if (near && !LIMIT.test(text.slice(Math.max(0, m.index - 120), m.index))) first = m.index
    }
  }
  return first
}

function snippet(s: string, at: number): string {
  return s.slice(Math.max(0, at - 20), at + 40).replace(/\s+/g, ' ')
}

function scanText(text: string, where: string, out: HygieneHit[]): void {
  const z = zeroWidthSignal(text)
  if (z) out.push({ flag: 'zero_width_chars', note: `${where} 含零宽 / 不可见字符`, at: z.index,
                    sample: JSON.stringify(z.char) })
  const checks: [RegExp, HygieneFlag, string][] = [
    [TAG_CHARS, 'unicode_tag_chars', '含 Unicode Tag 区字符（可编码隐藏文本）'],
    [BIDI, 'bidi_override', '含双向覆盖控制符（显示顺序可与实际内容不一致）'],
    [PUA, 'private_use_area', '含私用区字符'],
  ]
  for (const [re, flag, note] of checks) {
    const m = re.exec(text)
    if (m) out.push({ flag, note: `${where} ${note}`, at: m.index,
                      sample: JSON.stringify(m[0]) })
  }
  for (const [re, note] of IMPERATIVES) {
    const m = re.exec(text)
    if (m) out.push({ flag: 'injection_imperative', note: `${where} ${note}`,
                      at: m.index, sample: snippet(text, m.index) })
  }
  const s = unconfirmedSpending(text)
  if (s !== null) out.push({ flag: 'unconfirmed_spending', note: `${where} 未经逐次确认的花费或身份信息发送`,
                             at: s, sample: snippet(text, s) })
  const d = PSEUDO_DELIM.exec(text)
  if (d) out.push({ flag: 'pseudo_system_delimiter', note: `${where} 含伪造的系统边界标记`,
                    at: d.index, sample: snippet(text, d.index) })
  const e = EMBEDDED_MARKUP.exec(text)
  if (e) out.push({ flag: 'embedded_markup', note: `${where} 含可执行标记`,
                    at: e.index, sample: snippet(text, e.index) })
}

export function checkTool(tool: { name: string; description?: string }): HygieneHit[] {
  const out: HygieneHit[] = []
  scanText(tool.name, `工具名 '${tool.name}'`, out)
  if (/[^\x20-\x7E]/.test(tool.name)) {
    out.push({ flag: 'non_ascii_tool_name',
               note: `工具名 '${tool.name}' 含非 ASCII 字符（可能是同形字冒充）` })
  }
  const desc = tool.description ?? ''
  if (desc.length > MAX_DESCRIPTION_LEN) {
    out.push({ flag: 'excessive_length',
               note: `工具 '${tool.name}' 的 description 长度 ${desc.length} 超过 ${MAX_DESCRIPTION_LEN}` })
  }
  scanText(desc, `工具 '${tool.name}' 的 description`, out)
  return out
}

export interface HygieneResult {
  assertion_status: 'VERIFIED' | 'OBSERVED_RISK'
  reason: { key: string; params?: Record<string, string | number> }
  details: string[]
  flags_by_tool: Record<string, HygieneFlag[]>
}

export function runHygieneCheck(tools: { name: string; description?: string }[]): HygieneResult {
  const flags_by_tool: Record<string, HygieneFlag[]> = {}
  const details: string[] = []
  let hitTools = 0
  for (const t of tools) {
    const hits = checkTool(t)
    if (hits.length) {
      hitTools++
      flags_by_tool[t.name] = [...new Set(hits.map(h => h.flag))]
      for (const h of hits) details.push(`Warn: ${h.note}`)
    }
  }
  details.push(`Info: 共扫描 ${tools.length} 个工具，${tools.length - hitTools} 个未命中任何信号`)
  return {
    // 只报告信号，不推断意图 —— 因此永远不是 FAILED
    assertion_status: hitTools ? 'OBSERVED_RISK' : 'VERIFIED',
    reason: hitTools
      ? { key: 'hygiene_risk_detected', params: { hitCount: hitTools, totalCount: tools.length } }
      : { key: 'hygiene_no_risk', params: { totalCount: tools.length } },
    details,
    flags_by_tool,
  }
}
