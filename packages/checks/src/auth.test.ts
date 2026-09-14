import assert from 'node:assert'
import { parseBearerChallenge, judgeAuthMetadata, classifyCredentialChallenge } from './auth.ts'
import { performHandshake, performUnknownToolCall } from './protocol.ts'
import { createProbeContext } from './wire.ts'
import {
  modernBaselineClean,
  noCredentialsUnverifiableAuth,
  authChallengeScopeContradictsMetadata,
  authMetadataIllegalStructure,
  jwksMultipleKeysNotFlagged,
} from '@mcpcheckup/fixtures'
import type { ProbeBudget } from '@mcpcheckup/ssrf-guard'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const BUDGET: ProbeBudget = { maxRedirects: 3, maxDurationMs: 10_000, maxBodyBytes: 2_097_152, maxRequests: 8 }
let seq = 0
const newId = () => `probe-${++seq}`
const ENDPOINT = 'https://notes-mcp.example.com/mcp'

console.log('parseBearerChallenge')

await t('解析 resource_metadata 与 scope', () => {
  const c = parseBearerChallenge('Bearer resource_metadata="https://notes-mcp.example.com/.well-known/oauth-protected-resource", scope="notes:read notes:write"')
  assert.equal(c.resourceMetadataUrl, 'https://notes-mcp.example.com/.well-known/oauth-protected-resource')
  assert.equal(c.scope, 'notes:read notes:write')
})

await t('反例：没有 resource_metadata 参数时为 null', () => {
  const c = parseBearerChallenge('Bearer realm="example"')
  assert.equal(c.resourceMetadataUrl, null)
})

console.log('\nclassifyCredentialChallenge（credential-gate classification, ruling L1）')

function headersWith(wwwAuthenticate: string | undefined): Headers {
  const h = new Headers()
  if (wwwAuthenticate !== undefined) h.set('www-authenticate', wwwAuthenticate)
  return h
}

await t('401 + Bearer realm="mcp" → { scheme: "bearer" }', () => {
  const c = classifyCredentialChallenge(401, headersWith('Bearer realm="mcp"'))
  assert.deepEqual(c, { scheme: 'bearer' })
})

await t('401 + Basic → { scheme: "basic" }', () => {
  const c = classifyCredentialChallenge(401, headersWith('Basic'))
  assert.deepEqual(c, { scheme: 'basic' })
})

await t('401 + Basic realm="x", Bearer realm="y" → 第一个合法 scheme 胜出（basic）', () => {
  const c = classifyCredentialChallenge(401, headersWith('Basic realm="x", Bearer realm="y"'))
  assert.deepEqual(c, { scheme: 'basic' })
})

await t('反例：401 + 无 WWW-Authenticate 头 → null', () => {
  const c = classifyCredentialChallenge(401, headersWith(undefined))
  assert.equal(c, null)
})

await t('反例：401 + 空字符串 → null', () => {
  const c = classifyCredentialChallenge(401, headersWith(''))
  assert.equal(c, null)
})

await t('反例：401 + 仅空白 → null', () => {
  const c = classifyCredentialChallenge(401, headersWith('   '))
  assert.equal(c, null)
})

await t('反例：401 + \'="foo"\'（不以合法 token 开头）→ null', () => {
  const c = classifyCredentialChallenge(401, headersWith('="foo"'))
  assert.equal(c, null)
})

await t('反例：403 + 合法 Bearer 头 → null（403 从不豁免）', () => {
  const c = classifyCredentialChallenge(403, headersWith('Bearer realm="mcp"'))
  assert.equal(c, null)
})

await t('反例：200 + 合法 Bearer 头 → null', () => {
  const c = classifyCredentialChallenge(200, headersWith('Bearer realm="mcp"'))
  assert.equal(c, null)
})

await t('输入边界：scheme 长度恰好等于 MAX_SCHEME_LEN（64）时仍被接受', () => {
  const boundary = 'x'.repeat(64)
  const c = classifyCredentialChallenge(401, headersWith(boundary))
  assert.ok(c)
  assert.equal(c!.scheme, boundary)
})

await t('输入边界（Lead finding B3, round 2）：一个没有任何空白/逗号的畸长 tchar-only 头值——scheme 超过 MAX_SCHEME_LEN（64）——被显式拒绝为 null，而不是截断后当作真实 scheme 放行；防止目标控制的无界字符串进入 Reason.params/signed attestation', () => {
  const pathological = 'x'.repeat(5000)
  const c = classifyCredentialChallenge(401, headersWith(pathological))
  assert.equal(c, null)
})

await t('输入边界：scheme 恰好比 MAX_SCHEME_LEN 多一个字符（65）也被拒绝为 null', () => {
  const overByOne = 'x'.repeat(65)
  const c = classifyCredentialChallenge(401, headersWith(overByOne))
  assert.equal(c, null)
})

console.log('\nclassifyCredentialChallenge：第一条 challenge 必须被完整校验（Codex PR#19 P2，round 6）')

// 这一组的每一条在 round 6 之前都是被**接受**的：旧实现只校验了开头的
// auth-scheme token，token 之后的任何内容一概不看，于是一个真实的 FAILED
// 会被替换成 UNVERIFIED（credential_required）。

await t('反例：401 + \'Bearer ???\'（scheme 合法但余下部分既不是 token68 也不是 auth-param）→ null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer ???')), null)
})

await t('反例：401 + \'Bearer real m="x"\'（参数名被空格截断，`real` 之后不是 "="）→ null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer real m="x"')), null)
})

// 歧义边界（round 7，推翻 round 6）：`realm=` 同时是一个合法的 token68
// （base `realm` + 一个 padding "="）和一个被截断的 auth-param（有名字有等号
// 没有值）——两种读法是同一个字符串，分支顺序分不开。判据按 RFC 9110 §11.2
// 的语法裁定：它**是**一条结构合法的质询，因此豁免成立。round 6 曾用一条
// base64 padding 长度规则把它判掉，那让代码比 RFC 更严，而对外发布的文案
// 承诺的正是 RFC 的结构合法性——凡是 RFC 认为合法而我们拒绝的形状，都是文案
// 宽于代码，正是这条分支反复出过的缺陷类型。
await t('歧义边界：401 + "Bearer realm="（既是合法 token68，又是被截断的 auth-param）→ 按 RFC 语法判为合法质询 { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm=')), { scheme: 'bearer' })
})

await t('反例：401 + \'Bearer "unquoted-open\'（引号未闭合，不是合法 quoted-string）→ null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer "unquoted-open')), null)
})

await t('反例：401 + \'Bearer realm="mcp\'（quoted-string 缺右引号）→ null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="mcp')), null)
})

await t('反例：401 + \'Bearer realm="mcp" garbage\'（一条完整 auth-param 之后粘了不带逗号的垃圾）→ null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="mcp" garbage')), null)
})

await t('反例：401 + \'Bearer=x\'（scheme token 直接粘着别的东西，不在 token 边界结束）→ null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer=x')), null)
})

await t('正例：401 + \'Bearer abc123==\'（完整的 token68，padding 长度与 base64 一致）→ { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer abc123==')), { scheme: 'bearer' })
})

await t('正例：401 + \'Negotiate YWJjZGVm\'（无 padding 的 token68，任意长度都接受）→ { scheme: "negotiate" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Negotiate YWJjZGVm')), { scheme: 'negotiate' })
})

await t('正例：401 + "Bearer abcd="（token68 的 *"=" 不限个数，判据不对 base 长度做任何算术）→ { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer abcd=')), { scheme: 'bearer' })
})

await t('正例：401 + "Bearer AB======"（base32 的 padding 可以到六个 "="——§11.2 点名了 base32，所以不能只按 base64 的长度判）→ { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer AB======')), { scheme: 'bearer' })
})

await t('回归正例：401 + corpus 里 credential-gated fixture 实际使用的那条头（realm + resource_metadata，值里含 :// 与 .）仍然解析通过', () => {
  const header = 'Bearer realm="mcp", resource_metadata="https://notes-mcp.example.com/.well-known/oauth-protected-resource"'
  assert.deepEqual(classifyCredentialChallenge(401, headersWith(header)), { scheme: 'bearer' })
})

await t('多质询边界：\'Basic realm="x", Bearer realm="y"\' 仍然取第一个 scheme（basic）——第二条 challenge 起不再校验，这正是本函数声称的范围', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Basic realm="x", Bearer realm="y"')), { scheme: 'basic' })
})

await t('多质询边界：第一条 challenge 完整时，第二条即使畸形也不影响判定（`Basic realm="x", ???`）——刻意不校验第二条', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Basic realm="x", ???')), { scheme: 'basic' })
})

await t('多质询边界：反过来，第一条 challenge 畸形时，后面有一条合法 challenge 也救不回来（`Bearer ???, Basic realm="x"`）→ null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer ???, Basic realm="x"')), null)
})

await t('正例：\'Bearer realm=mcp\'（未加引号的 token 形式的值，RFC 允许）→ { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm=mcp')), { scheme: 'bearer' })
})

await t('正例：BWS——\'Bearer realm = "mcp"\'（等号两侧有空白，RFC 的 BWS 允许）→ { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm = "mcp"')), { scheme: 'bearer' })
})

await t('正例：\'Basic, Bearer realm="x"\'（裸 scheme 以逗号结束，也是一条完整 challenge）→ { scheme: "basic" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Basic, Bearer realm="x"')), { scheme: 'basic' })
})

await t('引号内的逗号不被当成列表分隔符：\'Bearer realm="a,b", scope="x"\' → { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a,b", scope="x"')), { scheme: 'bearer' })
})

await t('转义引号被当作一个字符消费，不会被误认为闭合引号：\'Bearer realm="a\\\\"b"\' → { scheme: "bearer" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a\\"b"')), { scheme: 'bearer' })
})

async function callResultFor(fixture: { createHandler: () => import('@mcpcheckup/fixtures').FetchHandler }) {
  const fetchImpl = fixture.createHandler()
  const ctx = createProbeContext(Date.now())
  const handshake = await performHandshake({ fetchImpl, endpoint: ENDPOINT, budget: BUDGET, ctx, newId })
  const callResult = await performUnknownToolCall({ fetchImpl, budget: BUDGET, ctx, newId, handshake, toolName: '__mcpcheckup_probe_nonexistent_tool__' })
  return { fetchImpl, ctx, callResult }
}

console.log('\nclassifyCredentialChallenge：list OWS 与 challenge 自己的 1*SP 分隔符必须区分开（Codex PR#19，round 11）')

// ---- Codex PR#19（round 11），两条 P2、同一个缺陷的两面：scheme token 之后的
// 那段空白此前被直接当成 challenge 自己的分隔符，于是判据同时**过宽**（把 HTAB
// 当成合法分隔符——RFC 9110 §11.3 里 challenge 用来分隔的是 1*SP，只允许 SP；
// 语法原文只写在 auth.ts 的 TCHAR_CLASS 注释里，这里只引用不复述）和**过窄**
// （把 `Basic , Bearer realm="x"` 这种合法的两条 challenge
// 列表判成 null，因为逗号前的 list OWS 被读成了"空参数段"）。过宽那一面是阻塞
// 合并的一面：给畸形头发豁免，就是把一个真实的 FAILED 换成 UNVERIFIED。
// 用 String.fromCharCode 显式构造 SP/HTAB，不靠源码里的转义字符——这样测试名和
// 断言用的是同一个字节，不会因为编辑器或 heredoc 改写转义而悄悄测了别的东西。 ----

const SP_CHAR = String.fromCharCode(32)
const HTAB_CHAR = String.fromCharCode(9)

await t('自检：SP_CHAR / HTAB_CHAR 确实是 U+0020 / U+0009，且拼接出的头值与字面量逐字节相同——否则下面整组测试测的是别的输入', () => {
  assert.equal(SP_CHAR.charCodeAt(0), 32)
  assert.equal(HTAB_CHAR.charCodeAt(0), 9)
  assert.equal('Bearer' + SP_CHAR + 'realm="mcp"', 'Bearer realm="mcp"')
})

// 过宽那一面：1*SP 只有 SP，HTAB 永远不是合法的 challenge 分隔符。

await t('反例（round 11 改判）：401 + Bearer<HTAB>realm="mcp" → null——1*SP 不接受 HTAB，畸形头不得豁免', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer' + HTAB_CHAR + 'realm="mcp"')), null)
})

await t('反例（round 11 改判）：401 + Bearer<SP><HTAB>realm="mcp" → null——分隔符里混进一个 HTAB 就不再是 1*SP', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer' + SP_CHAR + HTAB_CHAR + 'realm="mcp"')), null)
})

await t('反例（round 11 改判）：401 + Bearer<HTAB><HTAB>realm="mcp" → null', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer' + HTAB_CHAR + HTAB_CHAR + 'realm="mcp"')), null)
})

await t('反例（round 11 改判）：401 + Bearer<HTAB>token68abc → null——shape 2 的分隔符同样是 1*SP', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer' + HTAB_CHAR + 'token68abc')), null)
})

await t('正例：401 + Bearer<SP>token68abc → { scheme: "bearer" }——同一个输入只把 HTAB 换成 SP 就必须通过，证明上面钉的是"HTAB 不合法"而不是"token68 分支坏了"', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer' + SP_CHAR + 'token68abc')), { scheme: 'bearer' })
})

await t('正例：401 + Bearer<SP><SP>realm="mcp" → { scheme: "bearer" }——1*SP 是"一个或多个"，多个空格仍然合法', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer' + SP_CHAR + SP_CHAR + 'realm="mcp"')), { scheme: 'bearer' })
})

// 过窄那一面：逗号前的 list OWS（§5.6.1，OWS 允许 HTAB）说明裸 scheme 本身
// 已经是完整的第一条 challenge。

await t('正例（round 11 改判）：401 + Basic<SP>,<SP>Bearer realm="x" → { scheme: "basic" }——逗号前的空白是 list OWS，不是空参数段；第一条 challenge 说了算', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Basic' + SP_CHAR + ', Bearer realm="x"')), { scheme: 'basic' })
})

await t('正例（round 11 改判）：401 + Basic<SP><SP>,<SP>Bearer realm="x" → { scheme: "basic" }', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Basic' + SP_CHAR + SP_CHAR + ', Bearer realm="x"')), { scheme: 'basic' })
})

await t('正例（round 11 改判）：401 + Basic<HTAB>,<SP>Bearer realm="x" → { scheme: "basic" }——list OWS 允许 HTAB，这条路径上不做 1*SP 检查', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Basic' + HTAB_CHAR + ', Bearer realm="x"')), { scheme: 'basic' })
})

await t('正例（round 11 改判）：401 + Basic<SP>, → { scheme: "basic" }——#rule 容忍列表末尾的空元素，第一条 challenge 依然完整', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Basic' + SP_CHAR + ',')), { scheme: 'basic' })
})

console.log('\nclassifyCredentialChallenge：quoted-string 的两个分支都必须是语法自己的字符集（Codex PR#19 3921389312，round 18）')

// ---- Codex PR#19（round 18）：QUOTED_STRING_Y 的两个分支此前写成"除了引号和
// 反斜杠什么都行"（`[^"\\]`）和"反斜杠后面什么都行"（`\\[\s\S]`），都比语法宽。
// 判据文本只写在 auth.ts 的 QUOTED_STRING_Y 注释里（审查纪律 #4），这里只引用、
// 不复述：那两个字符集都不含 HTAB 以外的 C0 控制字符，也不含 DEL。
// 过宽的后果与 round 11 的 1*SP 完全同向：一个畸形的第一条 challenge 拿到
// credential-gated 豁免，真实的 FAILED 被换成 UNVERIFIED / credential_required。
// 控制字符构造一律走 String.fromCharCode——源码里的转义序列会被编辑器、格式化
// 工具或 heredoc 悄悄改写，而这一组测的就是具体是哪个字节。 ----

const SOH_CHAR = String.fromCharCode(1)    // %x01
const VT_CHAR = String.fromCharCode(11)    // %x0B
const US_CHAR = String.fromCharCode(31)    // %x1F
const DEL_CHAR = String.fromCharCode(127)  // %x7F
const BS_CHAR = String.fromCharCode(92)    // "\" —— quoted-pair 的引导字符
const OBS_TEXT_CHAR = String.fromCharCode(0xe9)    // é = %xE9，一个 obs-text 八位组
const X23_CHAR = String.fromCharCode(0x23)         // "#" —— %x23-5B 的下端点
const X5B_CHAR = String.fromCharCode(0x5b)         // "[" —— %x23-5B 的上端点
const ABOVE_BYTESTRING_CHAR = String.fromCharCode(0x4e2d)  // 中 = U+4E2D，超出 0xFF 的码元

await t('自检：本组用到的每个字符都是它名字所说的那个码元，且 Headers 会原样带着它到达判据——否则下面整组测试测的是别的输入', () => {
  assert.equal(SOH_CHAR.charCodeAt(0), 1)
  assert.equal(VT_CHAR.charCodeAt(0), 11)
  assert.equal(US_CHAR.charCodeAt(0), 31)
  assert.equal(DEL_CHAR.charCodeAt(0), 127)
  assert.equal(BS_CHAR.charCodeAt(0), 92)
  assert.equal(OBS_TEXT_CHAR.charCodeAt(0), 0xe9)
  assert.equal(X23_CHAR.charCodeAt(0), 0x23)
  assert.equal(X5B_CHAR.charCodeAt(0), 0x5b)
  assert.equal(ABOVE_BYTESTRING_CHAR.charCodeAt(0), 0x4e2d)
  // 这条自检是整组的前提：如果 Headers 在这一步就把控制字符挡掉或改写掉，
  // 下面的反例证明的就不是判据收紧了，而是运行时替判据挡了一道。
  for (const c of [SOH_CHAR, VT_CHAR, US_CHAR, DEL_CHAR, OBS_TEXT_CHAR]) {
    const raw = 'Bearer realm="x' + c + '"'
    assert.equal(headersWith(raw).get('www-authenticate'), raw)
  }
})

await t('边界事实：Headers 的字段值是 ByteString，超过 0xFF 的码元根本进不来（U+4E2D 抛错）——所以经由真实 Headers 到达判据的 obs-text 实际只有 %x80-FF；auth.ts 里把上界写到 \\uFFFF 是为了不预设某一种解码，而不是因为更高的码元可达', () => {
  assert.throws(() => headersWith('Bearer realm="' + ABOVE_BYTESTRING_CHAR + '"'), TypeError)
})

// 反例：qdtext 分支。HTAB 以外的 C0 控制字符与 DEL 都不是 qdtext。

await t('反例（round 18 改判）：401 + Bearer realm="x<0x01>" → null——qdtext 不含 HTAB 以外的 C0 控制字符', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="x' + SOH_CHAR + '"')), null)
})

await t('反例（round 18 改判）：401 + Bearer realm="x<0x0B>" → null——VT 同样不是 qdtext', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="x' + VT_CHAR + '"')), null)
})

await t('反例（round 18 改判）：401 + Bearer realm="x<0x1F>" → null——US 是 C0 区间的最后一个字符，边界也不放过', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="x' + US_CHAR + '"')), null)
})

await t('反例（round 18 改判）：401 + Bearer realm="x<0x7F>" → null——DEL 落在 %x5D-7E 之外，不是 qdtext', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="x' + DEL_CHAR + '"')), null)
})

await t('反例（round 18 改判）：401 + Bearer realm="x<0x01>", Basic realm="y" → null——第一条 challenge 畸形时后面有一条合法 challenge 也救不回来，与 round 6 的 `Bearer ???, Basic realm="x"` 同一条规则', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="x' + SOH_CHAR + '", Basic realm="y"')), null)
})

// 反例：quoted-pair 分支。反斜杠后面只能跟 HTAB / SP / VCHAR / obs-text，
// 控制字符与 DEL 不因为被转义就变得合法。

await t('反例（round 18 改判）：401 + Bearer realm="x\\<0x01>" → null——quoted-pair 不能转义一个 C0 控制字符', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="x' + BS_CHAR + SOH_CHAR + '"')), null)
})

await t('反例（round 18 改判）：401 + Bearer realm="x\\<0x7F>" → null——quoted-pair 也不能转义 DEL', () => {
  assert.equal(classifyCredentialChallenge(401, headersWith('Bearer realm="x' + BS_CHAR + DEL_CHAR + '"')), null)
})

// 正例：收紧的方向必须只切掉控制字符。以下每一条在 round 18 之前就通过，
// 它们钉的不是这次修复引入的行为，而是这次修复**不得**引入的行为。
//
// 逐个突变实测过（round 18，十段逐一删，十次全绿→红）：把 qdtext 的六段
// （HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text）或 quoted-pair 的四段
// （HTAB / SP / VCHAR / obs-text）**任意删掉一段**，下面这一组里都至少有一条转红。
// 「这一组里」是字面意思：%x23-5B 那一段原本只被本文件更靠前的
// 「引号内的逗号不被当成列表分隔符」那条（靠值里的 0x2C 逗号）抓住，这一组自己
// 一条都不红——所以下面补了一条专门带 %x23-5B 字符的正例，让这一组自足。
//
// 唯一一件这里钉不住的事，明说出来，不要含糊过去：obs-text 的**上界**。把两个
// 分支的 \u0080-\uFFFF 同时换成 \x80-\xFF，本文件与 packages/checks、
// packages/fixtures 的全部测试一条都不红。原因是本文件上面那条「边界事实」已经
// 钉住的：Headers 的字段值是 ByteString，0xFF 以上的码元根本进不来；而
// QUOTED_STRING_Y 是模块私有的，classifyCredentialChallenge 只收 Headers。
// 也就是说那个上界经由任何公开面都**不可观测**，因此**没有任何断言在守它**——
// 它是给未来某个会解码的调用方留的保险，不是守卫。不要为了让这句话听起来更好
// 而补一条假断言（守卫设计原则 #5/#6）；auth.ts 的 QUOTED_STRING_Y 注释里写着
// 同一件事。

await t('正例：401 + Bearer realm="a<HTAB>b" → { scheme: "bearer" }——HTAB 是 qdtext 明确列出的一个字符（与 1*SP 分隔符那条路径不同，别混起来）', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a' + HTAB_CHAR + 'b"')), { scheme: 'bearer' })
})

await t('正例：401 + Bearer realm="a b~!" → { scheme: "bearer" }——SP 与 VCHAR 两端（%x21 的 "!" 与 %x7E 的 "~"）都在 qdtext 里', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a b~!"')), { scheme: 'bearer' })
})

await t('正例：401 + Bearer realm="<0x23>mcp<0x5B>" → { scheme: "bearer" }——%x23-5B 是 qdtext 里最大的一段（57 个字符），这里钉的是它的两个端点；在这条之前，删掉这一整段在本组里一条都不红', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="' + X23_CHAR + 'mcp' + X5B_CHAR + '"')), { scheme: 'bearer' })
})

await t('正例：401 + Bearer realm="a\\\\b"（转义反斜杠）→ { scheme: "bearer" }——"\\" 是 VCHAR，quoted-pair 允许', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a' + BS_CHAR + BS_CHAR + 'b"')), { scheme: 'bearer' })
})

await t('正例：401 + Bearer realm="<0xE9>"（qdtext 分支的 obs-text）→ { scheme: "bearer" }——收紧的目标是控制字符，不是非 ASCII：一个合法的非 ASCII realm 不能因为这次收紧而被判死', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="' + OBS_TEXT_CHAR + '"')), { scheme: 'bearer' })
})

// quoted-pair 分支的另外三段。round 18 的 reviewer 实测指出：在补上这三条之前，
// 把 \\[...] 里的 HTAB / SP / obs-text 各删一段，全仓没有一条断言转红——那一半
// 字符集是靠注释在守的，不是靠测试。三个字符都 ≤ 0xFF，Headers 会原样带进来，
// 所以它们全都构造得出来，没有理由只用注释代替。

await t('正例：401 + Bearer realm="a\\<HTAB>b"（转义 HTAB）→ { scheme: "bearer" }——quoted-pair 的第一段就是 HTAB', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a' + BS_CHAR + HTAB_CHAR + 'b"')), { scheme: 'bearer' })
})

await t('正例：401 + Bearer realm="a\\<SP>b"（转义 SP）→ { scheme: "bearer" }——quoted-pair 允许 SP，且它与 qdtext 里那个 SP 是两条不同的路径', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a' + BS_CHAR + SP_CHAR + 'b"')), { scheme: 'bearer' })
})

await t('正例：401 + Bearer realm="a\\<0xE9>b"（转义 obs-text）→ { scheme: "bearer" }——obs-text 在 quoted-pair 里也是合法的一段，与 qdtext 那条各自独立', () => {
  assert.deepEqual(classifyCredentialChallenge(401, headersWith('Bearer realm="a' + BS_CHAR + OBS_TEXT_CHAR + 'b"')), { scheme: 'bearer' })
})

console.log('\njudgeAuthMetadata：针对真实 fixture handler')

await t('modern-baseline-clean：没有 401，未观察到任何 challenge → VERIFIED（没什么好标记的）', async () => {
  const { fetchImpl, ctx, callResult } = await callResultFor(modernBaselineClean)
  const v = await judgeAuthMetadata({ fetchImpl, budget: BUDGET, ctx, callResult })
  assert.equal(v.status, 'VERIFIED')
})

await t('no-credentials-unverifiable-auth：裸 401 无 WWW-Authenticate → UNVERIFIED', async () => {
  const { fetchImpl, ctx, callResult } = await callResultFor(noCredentialsUnverifiableAuth)
  assert.equal(callResult.status, 401)
  const v = await judgeAuthMetadata({ fetchImpl, budget: BUDGET, ctx, callResult })
  assert.equal(v.status, 'UNVERIFIED')
  if (v.status !== 'UNVERIFIED') throw new Error('unreachable')
  assert.deepEqual(v.reason, { key: 'auth_401_no_challenge' })
})

await t('auth-challenge-scope-contradicts-metadata：challenge 的 scope 与其自身 metadata 文档矛盾 → OBSERVED_RISK', async () => {
  const { fetchImpl, ctx, callResult } = await callResultFor(authChallengeScopeContradictsMetadata)
  const v = await judgeAuthMetadata({ fetchImpl, budget: BUDGET, ctx, callResult })
  assert.equal(v.status, 'OBSERVED_RISK')
  if (v.status !== 'OBSERVED_RISK') throw new Error('unreachable')
  assert.deepEqual(v.reason, { key: 'auth_scope_contradiction' })
})

await t('auth-metadata-illegal-structure：challenge 指向的 metadata 文档解析不了 → OBSERVED_RISK', async () => {
  const { fetchImpl, ctx, callResult } = await callResultFor(authMetadataIllegalStructure)
  const v = await judgeAuthMetadata({ fetchImpl, budget: BUDGET, ctx, callResult })
  assert.equal(v.status, 'OBSERVED_RISK')
  if (v.status !== 'OBSERVED_RISK') throw new Error('unreachable')
  assert.deepEqual(v.reason, { key: 'auth_metadata_invalid_json' })
})

await t('jwks-multiple-keys-not-flagged：metadata 合法、scope 一致，即便 JWKS 有两把 key 也 → VERIFIED', async () => {
  const { fetchImpl, ctx, callResult } = await callResultFor(jwksMultipleKeysNotFlagged)
  const v = await judgeAuthMetadata({ fetchImpl, budget: BUDGET, ctx, callResult })
  assert.equal(v.status, 'VERIFIED')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
