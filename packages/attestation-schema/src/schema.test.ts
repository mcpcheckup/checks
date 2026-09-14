import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import { attestationSchemaForPayloadType } from './index.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const schema = JSON.parse(readFileSync(new URL('../schema/attestation.schema.json', import.meta.url), 'utf8'))
const sample = JSON.parse(readFileSync(new URL('../test/fixtures/attestation.sample.json', import.meta.url), 'utf8'))
const schemaV01 = JSON.parse(readFileSync(new URL('../schema/attestation-payload-v0.1.json', import.meta.url), 'utf8'))
const schemaV02 = JSON.parse(readFileSync(new URL('../schema/attestation-payload-v0.2.json', import.meta.url), 'utf8'))
// v0.2 形状的真实样例。归档 schema 一律用它来驱动，而不是把当前 sample（已经是 v0.3）
// 就地改造——否则 “sample 是 v0.3” 和 “归档 schema 校验的是历史形状” 两件事会互相干扰。
const sampleV02 = JSON.parse(readFileSync(new URL('../test/fixtures/attestation-v0.2.sample.json', import.meta.url), 'utf8'))

function makeValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true })
  addFormats(ajv)
  return ajv.compile(schema)
}

function makeV02Validator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true })
  addFormats(ajv)
  return ajv.compile(schemaV02)
}

function makeV01Validator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true })
  addFormats(ajv)
  return ajv.compile(schemaV01)
}

function deepClone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v))
}

function withField(obj: Record<string, unknown>, path: string[], value: unknown): Record<string, unknown> {
  const clone = deepClone(obj)
  let cursor: any = clone
  for (let i = 0; i < path.length - 1; i++) cursor = cursor[path[i]!]
  if (value === '__DELETE__') delete cursor[path[path.length - 1]!]
  else cursor[path[path.length - 1]!] = value
  return clone
}

console.log('attestation.schema.json：元层面')

t('schema 声明 draft 2020-12', () => {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema')
})

t('schema 自身通过 2020-12 meta-schema 校验（不是一份格式错误的 JSON Schema）', () => {
  const ajv = new Ajv2020({ strict: true })
  addFormats(ajv)
  assert.doesNotThrow(() => ajv.compile(schema))
})

console.log('\nattestation.schema.json：正例')

t('完整合法样例通过校验', () => {
  const validate = makeValidator()
  const ok = validate(sample)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

t('launch_config_digest 为 sha256 摘要（stdio 场景）也应通过', () => {
  const validate = makeValidator()
  const stdioSample = withField(sample, ['launch_config_digest'], 'sha256:821d1053a632c5076dd4a55446d1e3409bece9cebe09c3d44620f138d72459f7')
  const withDnsField = withField(stdioSample, ['probe_dns_answer_changed'], null)
  const withStdioTarget = withField(withDnsField, ['target'], {
    provider: 'example-notes-co',
    name: 'notes-mcp-stdio',
    transport: 'stdio',
    endpoint_url: null,
    package_ref: '@example-notes/mcp-server@1.2.3', // scan-secrets-allow: npm scope/name@version shape, not an email
  })
  const ok = validate(withStdioTarget)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

console.log('\nattestation.schema.json：additionalProperties 反例')

t('顶层出现未声明字段 → 拒绝', () => {
  const validate = makeValidator()
  const withExtra = { ...deepClone(sample), unexpected_field: 'x' }
  assert.equal(validate(withExtra), false)
})

t('target 出现未声明字段 → 拒绝', () => {
  const validate = makeValidator()
  const withExtra = withField(sample, ['target'], { ...deepClone(sample).target, extra: 'x' })
  assert.equal(validate(withExtra), false)
})

t('assertions[] 元素出现未声明字段 → 拒绝', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[0].extra = 'x'
  assert.equal(validate(clone), false)
})

t('run 出现未声明字段 → 拒绝（additionalProperties:false 要在每一层都验证，不能只查了 root/target/assertions 就假设其它对象也一样）', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['run'], { ...deepClone(sample).run, extra: 'x' })
  assert.equal(validate(clone), false)
})

console.log('\nattestation.schema.json：必填版本字段——「缺一不可」，每个字段各一个反例')

const REQUIRED_VERSION_FIELDS = [
  'canonicalization',
  'suite_id',
  'suite_version',
  'suite_digest',
  'suite_commit',
  'registry_version',
  'toolset_projection_version',
  'protocol_revision',
  'launch_config_digest',
]

for (const field of REQUIRED_VERSION_FIELDS) {
  t(`缺少 "${field}" → 拒绝`, () => {
    const validate = makeValidator()
    const clone = deepClone(sample)
    delete clone[field]
    const ok = validate(clone)
    assert.equal(ok, false, `${field} 缺失时应当被拒绝，但校验通过了`)
  })
}

t('canonicalization 值不是 "nfc-jcs/v1" → 拒绝（这是唯一允许的值，不是任意字符串）', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['canonicalization'], 'rfc8785')
  assert.equal(validate(clone), false)
})

console.log('\nattestation.schema.json：必填版本字段——「非空」，每个有格式约束的字段各一个"存在但是空/不合法值"的反例')

const EMPTY_OR_INVALID_VERSION_VALUES: Record<string, unknown> = {
  suite_id: '',
  suite_version: '',
  suite_digest: '',
  suite_commit: '',
  registry_version: '',
  toolset_projection_version: '',
  protocol_revision: '',
}

for (const [field, badValue] of Object.entries(EMPTY_OR_INVALID_VERSION_VALUES)) {
  t(`"${field}" 存在但是空字符串 → 拒绝（不只是"缺失"，"空值"也不行）`, () => {
    const validate = makeValidator()
    const clone = withField(sample, [field], badValue)
    assert.equal(validate(clone), false, `${field}="" 应当被拒绝，但校验通过了`)
  })
}

t('protocol_revision 形状对但日历上不存在（月 13、日 40）→ 拒绝（format:"date" 做真实日历校验，不只是数字分组）', () => {
  const validate = makeValidator()
  for (const bad of ['2026-13-40', '2026-02-30', '2026-00-01', '2026-01-00']) {
    const clone = withField(sample, ['protocol_revision'], bad)
    assert.equal(validate(clone), false, `protocol_revision="${bad}" 不是真实日历日期，应当被拒绝`)
  }
})

console.log('\nattestation.schema.json：target/launch_config_digest 的 transport 条件反例')

t('transport=remote 但 launch_config_digest 非 null → 拒绝', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['launch_config_digest'], 'sha256:821d1053a632c5076dd4a55446d1e3409bece9cebe09c3d44620f138d72459f7')
  assert.equal(validate(clone), false)
})

t('transport=stdio 但 launch_config_digest 为 null → 拒绝（stdio 必填）', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['target'], {
    provider: 'example-notes-co',
    name: 'notes-mcp-stdio',
    transport: 'stdio',
    endpoint_url: null,
    package_ref: '@example-notes/mcp-server@1.2.3', // scan-secrets-allow: npm scope/name@version shape, not an email
  })
  assert.equal(validate(clone), false)
})

t('transport=remote 但 endpoint_url 为 null → 拒绝', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['target', 'endpoint_url'], null)
  assert.equal(validate(clone), false)
})

t('transport=remote 但 package_ref 非 null → 拒绝（不能两边都填，会让第三方困惑到底是哪种）', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['target', 'package_ref'], '@example-notes/mcp-server@1.2.3') // scan-secrets-allow: npm scope/name@version shape, not an email
  assert.equal(validate(clone), false)
})

t('transport=stdio 但 endpoint_url 非 null → 拒绝', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['target'], {
    provider: 'example-notes-co',
    name: 'notes-mcp-stdio',
    transport: 'stdio',
    endpoint_url: 'https://notes-mcp.example.com/mcp',
    package_ref: '@example-notes/mcp-server@1.2.3', // scan-secrets-allow: npm scope/name@version shape, not an email
  })
  assert.equal(validate(clone), false)
})

console.log('\nattestation.schema.json：probe_dns_answer_changed —— 运行条件，不是 check 判定')

t('整个键缺失（不是 null，是键本身不存在）→ 拒绝', () => {
  const clone = deepClone(sample)
  delete clone.probe_dns_answer_changed
  assert.equal(makeValidator()(clone), false)
})

t('transport=remote 且 probe_dns_answer_changed=true（观察到 DNS 答案变化）→ 依然通过——这是运行条件，不影响任何 assertion 的合法性', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['probe_dns_answer_changed'], true)
  const ok = validate(clone)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

t('transport=remote 但 probe_dns_answer_changed 为 null → 拒绝（remote 必须是明确的 boolean）', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['probe_dns_answer_changed'], null)
  assert.equal(validate(clone), false)
})

t('transport=stdio 但 probe_dns_answer_changed 非 null（例如 false）→ 拒绝——stdio 不做 DNS 解析，这个字段不适用，必须是 null', () => {
  const validate = makeValidator()
  const stdioTarget = {
    provider: 'example-notes-co',
    name: 'notes-mcp-stdio',
    transport: 'stdio',
    endpoint_url: null,
    package_ref: '@example-notes/mcp-server@1.2.3', // scan-secrets-allow: npm scope/name@version shape, not an email
  }
  const withStdioTarget = withField(sample, ['target'], stdioTarget)
  const clone = withField(withStdioTarget, ['launch_config_digest'], 'sha256:821d1053a632c5076dd4a55446d1e3409bece9cebe09c3d44620f138d72459f7')
  assert.equal(validate(clone), false, 'probe_dns_answer_changed=false 但 transport=stdio 应当被拒绝')

  const withNull = withField(clone, ['probe_dns_answer_changed'], null)
  const ok = validate(withNull)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true, 'transport=stdio 且 probe_dns_answer_changed=null 才是合法组合')
})

t('target.name 不符合 slug 格式（大写字母）→ 拒绝', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['target', 'name'], 'Notes-MCP')
  assert.equal(validate(clone), false)
})

t('target.endpoint_url / package_ref 整个键缺失（不是 null，是键本身不存在）→ 拒绝', () => {
  const validate = makeValidator()
  for (const field of ['endpoint_url', 'package_ref']) {
    const clone = withField(sample, ['target', field], '__DELETE__')
    assert.equal(validate(clone), false, `target.${field} 整个键缺失应当被拒绝`)
  }
})

console.log('\nattestation.schema.json：UNVERIFIED 缺原因反例（四态模型的硬约束）')

t('assertion_status=UNVERIFIED 且 reason 与 unverified_reason 都是 null → 拒绝', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[1].reason = null
  clone.assertions[1].unverified_reason = null
  assert.equal(validate(clone), false)
})

t('assertion_status=UNVERIFIED 且 unverified_reason 是空字符串 → 拒绝（必须非空，不只是非 null）', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[1].unverified_reason = ''
  assert.equal(validate(clone), false)
})

t('assertion_status=UNVERIFIED 且 unverified_reason 只有空白字符（三个空格）、reason 为 null → 拒绝（反例：光靠 minLength 挡不住"看起来非空、实际没内容"的字符串）', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[1].unverified_reason = '   '
  clone.assertions[1].reason = null
  assert.equal(validate(clone), false)
})

t('assertion_status=UNVERIFIED 且 reason 只有空白字符、unverified_reason 为 null → 拒绝（同上，走 reason 兜底那条分支）', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[1].reason = '\t \t'
  clone.assertions[1].unverified_reason = null
  assert.equal(validate(clone), false)
})

t('reason / unverified_reason 整个键缺失（不是 null，是键本身不存在）→ 拒绝', () => {
  const validate = makeValidator()
  for (const field of ['reason', 'unverified_reason']) {
    const clone = deepClone(sample)
    delete clone.assertions[0][field] // assertions[0] 是 VERIFIED，不受 UNVERIFIED 那条 anyOf 影响，纯测 required
    assert.equal(validate(clone), false, `assertions[0].${field} 整个键缺失应当被拒绝`)
  }
})

t('assertion_status=UNVERIFIED 但只有 reason（没有 unverified_reason）非空 → 通过（DB 用 coalesce(unverified_reason, reason)，reason 是合法兜底）', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[1].unverified_reason = null
  clone.assertions[1].reason = { key: 'fallback_reason_also_counts' }
  const ok = validate(clone)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

t('assertion_status=VERIFIED 时 reason 与 unverified_reason 都为 null 是允许的（约束只针对 UNVERIFIED）', () => {
  const validate = makeValidator()
  assert.equal(sample.assertions[0].assertion_status, 'VERIFIED')
  assert.equal(sample.assertions[0].reason, null)
  assert.equal(sample.assertions[0].unverified_reason, null)
  assert.equal(validate(sample), true)
})

console.log('\nattestation.schema.json：reason/unverified_reason 的 reasonRef 形状（v0.2）')

t('assertion.reason 接受 {key, params}，拒绝裸字符串（v0.2）', () => {
  const validate = makeValidator()

  const withKeyedReason = deepClone(sample)
  withKeyedReason.assertions[0].assertion_status = 'FAILED'
  withKeyedReason.assertions[0].reason = { key: 'fingerprint_baseline_mismatch' }
  withKeyedReason.assertions[0].unverified_reason = null
  const ok = validate(withKeyedReason)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)

  const withStringReason = deepClone(sample)
  withStringReason.assertions[0].assertion_status = 'FAILED'
  withStringReason.assertions[0].reason = 'old literal string'
  withStringReason.assertions[0].unverified_reason = null
  assert.equal(validate(withStringReason), false, 'v0.1 的裸字符串 reason 在 v0.2 schema 下应当被拒绝')
})

t('reason.key 拒绝空/不合法的 key', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[0].assertion_status = 'FAILED'
  clone.assertions[0].reason = { key: '' }
  clone.assertions[0].unverified_reason = null
  assert.equal(validate(clone), false)
})

t('reason.params 接受由字符串/数字组成的扁平对象', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[0].assertion_status = 'FAILED'
  clone.assertions[0].reason = { key: 'auth_metadata_http_error', params: { status: 404 } }
  clone.assertions[0].unverified_reason = null
  const ok = validate(clone)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

t('UNVERIFIED 仍然要求 reason 或 unverified_reason 非 null（v0.2 形状）', () => {
  const validate = makeValidator()

  const neither = deepClone(sample)
  neither.assertions[1].reason = null
  neither.assertions[1].unverified_reason = null
  assert.equal(validate(neither), false)

  const withUnverified = deepClone(sample)
  withUnverified.assertions[1].reason = null
  withUnverified.assertions[1].unverified_reason = { key: 'fingerprint_comparison_unavailable' }
  const ok = validate(withUnverified)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

console.log('\nattestation.schema.json：execution_status / assertion_status / evidence_provenance 三个独立字段')

t('execution_status 和 assertion_status 是两个独立字段（不是合并出的布尔值），非法枚举值被拒绝', () => {
  const validate = makeValidator()
  const badExec = deepClone(sample)
  badExec.assertions[0].execution_status = 'DONE'
  assert.equal(validate(badExec), false)

  const badAssertion = deepClone(sample)
  badAssertion.assertions[0].assertion_status = 'PASSED'
  assert.equal(validate(badAssertion), false)
})

t('evidence_provenance 三值：非法值被拒绝', () => {
  const validate = makeValidator()
  const clone = deepClone(sample)
  clone.assertions[0].evidence_provenance = 'TRUST_ME'
  assert.equal(validate(clone), false)
})

t('assertions 至少要有一条，空数组被拒绝', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['assertions'], [])
  assert.equal(validate(clone), false)
})

console.log('\nattestation.schema.json：指纹与时间戳格式')

t('toolset_fingerprint / schema_fingerprint 必须是 sha256:<64 hex> 格式', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['toolset_fingerprint'], 'not-a-digest')
  assert.equal(validate(clone), false)
})

t('observed_at 不是合法 date-time → 拒绝（用了 ajv-formats 真实强校验，不只是 annotation）', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['observed_at'], 'yesterday')
  assert.equal(validate(clone), false)
})

t('时间戳必须固定精度、固定 Z 后缀（反例：格式合法但写法不唯一的变体全部拒绝）', () => {
  // 同一个时刻可以用好几种 RFC 3339 合法写法表示，但那几种写法的字节不同、hash 就不同。
  // format: date-time 本身允许全部这些变体——canonicalize() 会原样保留字符串，所以
  // 光靠 format 关键字堵不住"同一时刻两种合法写法产出两个不同 digest"这个洞。
  const validate = makeValidator()
  const variants = [
    '2026-08-18T09:15:00Z', // 缺毫秒
    '2026-08-18T09:15:00+00:00', // 不是 Z 后缀
    '2026-08-18T09:15:00.000000Z', // 微秒精度，不是毫秒
    '2026-08-18T09:15:00.5Z', // 一位小数，不是三位
    '2026-08-18T17:15:00+08:00', // 非 UTC 偏移（即便代表同一时刻）
  ]
  for (const ts of variants) {
    const clone = withField(sample, ['observed_at'], ts)
    assert.equal(validate(clone), false, `观察到 observed_at="${ts}" 被放过了——它和标准毫秒+Z写法代表相近/相同时刻但字节不同`)
  }
})

t('时间戳：毫秒精度 + Z 后缀是唯一允许的写法（正例）', () => {
  const validate = makeValidator()
  const clone = withField(sample, ['observed_at'], '2026-08-18T09:15:00.000Z')
  const ok = validate(clone)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

console.log('\nattestation-payload-v0.1.json：归档 schema，仅供验证 v0.2 之前签发的 attestation')

t('v0.1 schema 自身通过 2020-12 meta-schema 校验', () => {
  const ajv = new Ajv2020({ strict: true })
  addFormats(ajv)
  assert.doesNotThrow(() => ajv.compile(schemaV01))
})

t('v0.1 形状的样例（reason/unverified_reason 为裸字符串）通过 v0.1 schema 校验', () => {
  const validate = makeV01Validator()
  // v0.2 的样例里 reason/unverified_reason 是 {key, params?} 对象；v0.1 时代它们是裸字符串。
  // 从 sampleV02 派生、不从 sample（v0.3）派生：v0.3 多了一个 v0.1 不认识的 suite_commit，
  // 若从 v0.3 派生，这条断言就变成在测 additionalProperties，而不是在测 reason 的形状。
  const v01Sample = deepClone(sampleV02)
  v01Sample.assertions[1].unverified_reason = 'auth metadata endpoint returned no WWW-Authenticate challenge'
  v01Sample.assertions[2].reason = '该 target 未被认领，不存在已批准基线'
  const ok = validate(v01Sample)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

t('v0.1 shaped 样例（裸字符串 reason）会被当前 v0.3 schema 拒绝（确认两个 schema 确实不同，不是巧合都通过）', () => {
  const validate = makeValidator()
  const v01Sample = deepClone(sample)
  v01Sample.assertions[1].unverified_reason = 'auth metadata endpoint returned no WWW-Authenticate challenge'
  assert.equal(validate(v01Sample), false)
})

t('v0.2 形状的样例（reason 为 {key} 对象）会被 v0.1 schema 拒绝（确认两者不能互相通过对方的校验）', () => {
  const validate = makeV01Validator()
  const ok = validate(sampleV02)
  assert.equal(ok, false)
})

console.log('\nattestation.schema.json：suite_commit —— v0.3 新增的必填字段（40 位小写十六进制 commit sha）')

t('suite_commit 换成另外几个合法的 40 位小写十六进制值 → 通过（证明 pattern 不是只认 fixture 里那一个值）', () => {
  const validate = makeValidator()
  for (const good of ['0'.repeat(40), 'f'.repeat(40), '9d3a2b1c0e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b']) {
    const clone = withField(sample, ['suite_commit'], good)
    const ok = validate(clone)
    if (!ok) console.error(validate.errors)
    assert.equal(ok, true, `suite_commit="${good}" 是合法的 40 位小写十六进制，不应被拒绝`)
  }
})

t('suite_commit 形状不对 → 逐个拒绝（39 位截断、41 位、大写、64 位 SHA-256 对象名、含非十六进制字符、带算法前缀、前后空白）', () => {
  const validate = makeValidator()
  const valid: string = sample.suite_commit
  const bad: Array<[string, string]> = [
    [valid.slice(0, 39), '39 位：截断一位'],
    [valid + '0', '41 位：多一位'],
    // 大写：git 自己的对象名输出一律小写。放过大写等于允许同一个 commit 有两种写法，
    // 同一份代码身份就会产出两组不同的签名字节，验证者没法逐字节比对。
    [valid.toUpperCase(), '大写十六进制'],
    // SHA-256 仓库的对象名是 64 位。本版本明确不支持——两种长度都收，
    // 等于这个字段不再声明它到底是哪种对象名。
    ['0a1b2c3d4e5f60718293a4b5c6d7e8f9'.repeat(2), '64 位：SHA-256 对象名'],
    [valid.slice(0, 39) + 'g', '含非十六进制字符 g'],
    ['sha1:' + valid, '带算法前缀'],
    [' ' + valid, '前导空格'],
    [valid + '\n', '尾随换行'],
  ]
  for (const [value, why] of bad) {
    const clone = withField(sample, ['suite_commit'], value)
    assert.equal(validate(clone), false, `suite_commit=${JSON.stringify(value)}（${why}）应当被拒绝，但校验通过了`)
  }
})

console.log('\nschema 版本身份：三份文件的 $id 互不相同（归档不是改个文件名了事）')

t('当前 schema 的 $id 是 v0.3，两份归档分别是 v0.2 / v0.1，三者互不相同', () => {
  assert.equal(schema.$id, 'https://mcpcheckup.com/schema/attestation-payload-v0.3.json')
  assert.equal(schemaV02.$id, 'https://mcpcheckup.com/schema/attestation-payload-v0.2.json')
  assert.equal(schemaV01.$id, 'https://mcpcheckup.com/schema/attestation-payload-v0.1.json')
  assert.equal(new Set([schema.$id, schemaV02.$id, schemaV01.$id]).size, 3)
})

console.log('\nattestation-payload-v0.2.json：归档 schema，仅供验证 v0.3 之前签发的 attestation')

t('v0.2 schema 自身通过 2020-12 meta-schema 校验', () => {
  const ajv = new Ajv2020({ strict: true })
  addFormats(ajv)
  assert.doesNotThrow(() => ajv.compile(schemaV02))
})

t('v0.2 样例（没有 suite_commit）通过 v0.2 schema 校验', () => {
  const validate = makeV02Validator()
  const ok = validate(sampleV02)
  if (!ok) console.error(validate.errors)
  assert.equal(ok, true)
})

t('v0.2 样例被当前 v0.3 schema 拒绝，且拒绝理由就是缺 suite_commit（确认 v0.3 真的收紧了，不是两份都放行）', () => {
  const validate = makeValidator()
  assert.equal(validate(sampleV02), false)
  assert.ok(
    (validate.errors ?? []).some((e) => e.keyword === 'required' && (e.params as { missingProperty?: string }).missingProperty === 'suite_commit'),
    `期望因为缺少 suite_commit 被拒绝，实际错误是 ${JSON.stringify(validate.errors)}`,
  )
})

t('v0.3 样例被 v0.2 schema 拒绝，且拒绝理由就是 suite_commit 是未声明字段（additionalProperties:false）', () => {
  const validate = makeV02Validator()
  assert.equal(validate(sample), false)
  assert.ok(
    (validate.errors ?? []).some((e) => e.keyword === 'additionalProperties' && (e.params as { additionalProperty?: string }).additionalProperty === 'suite_commit'),
    `期望因为 suite_commit 是未声明字段被拒绝，实际错误是 ${JSON.stringify(validate.errors)}`,
  )
})

console.log('\nattestationSchemaForPayloadType：派发出的 schema 真的能校验对应版本的样例（不只是对象引用相等）')

t('每个 payloadType 派发出的 schema，收下本版本的样例、拒绝另外两个版本的样例', () => {
  // v0.1 样例：v0.2 的形状，但 reason/unverified_reason 退回裸字符串（v0.1 时代的写法）。
  const sampleV01 = deepClone(sampleV02)
  sampleV01.assertions[1].unverified_reason = 'auth metadata endpoint returned no WWW-Authenticate challenge'
  sampleV01.assertions[2].reason = '该 target 未被认领，不存在已批准基线'

  const cases: Array<[string, unknown]> = [
    ['application/vnd.mcpcheckup.attestation+json;version=0.1', sampleV01],
    ['application/vnd.mcpcheckup.attestation+json;version=0.2', sampleV02],
    ['application/vnd.mcpcheckup.attestation+json;version=0.3', sample],
  ]

  for (const [payloadType, ownSample] of cases) {
    const ajv = new Ajv2020({ allErrors: true, strict: true })
    addFormats(ajv)
    const validate = ajv.compile(attestationSchemaForPayloadType(payloadType))
    const ok = validate(ownSample)
    if (!ok) console.error(payloadType, validate.errors)
    assert.equal(ok, true, `${payloadType} 派发出的 schema 应当收下同版本的样例`)

    for (const [otherType, otherSample] of cases) {
      if (otherType === payloadType) continue
      assert.equal(
        validate(otherSample),
        false,
        `${payloadType} 派发出的 schema 不应当收下 ${otherType} 的样例——两份 schema 若互相都能通过，“按版本校验” 就是句空话`,
      )
    }
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
