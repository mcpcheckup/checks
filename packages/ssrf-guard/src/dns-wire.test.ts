import assert from 'node:assert'
import { encodeQuery, decodeResponse, QTYPE_A, QTYPE_AAAA, QTYPE_TXT } from './dns-wire.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('encodeQuery: 逐字节手工核对（不依赖 decodeResponse，独立推导）')

t('example.com / A / id=0x1234 —— 逐字节等于按 RFC 1035 §4.1 手工推导的期望值', () => {
  // header: ID=0x1234, flags=0x0100 (RD=1，其余为 0), QDCOUNT=1, AN/NS/AR COUNT=0
  // question: QNAME = 07 "example" 03 "com" 00, QTYPE=1(A), QCLASS=1(IN)
  const expected = Uint8Array.from([
    0x12, 0x34, // ID
    0x01, 0x00, // flags
    0x00, 0x01, // QDCOUNT
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // 7 "example"
    0x03, 0x63, 0x6f, 0x6d, // 3 "com"
    0x00, // root terminator
    0x00, 0x01, // QTYPE = A
    0x00, 0x01, // QCLASS = IN
  ])
  const actual = encodeQuery('example.com', QTYPE_A, 0x1234)
  assert.deepEqual(Array.from(actual), Array.from(expected))
})

t('QTYPE_A === 1, QTYPE_AAAA === 28（IANA DNS 记录类型编号）', () => {
  assert.equal(QTYPE_A, 1)
  assert.equal(QTYPE_AAAA, 28)
})

t('单标签主机名 "localhost" 编码正确', () => {
  const actual = encodeQuery('localhost', QTYPE_A, 0)
  // 12 字节 header + (1+9) label + 1 root + 2 qtype + 2 qclass = 27
  assert.equal(actual.length, 27)
  assert.equal(actual[12], 9) // label 长度
  assert.equal(actual[12 + 1 + 9], 0) // root terminator
})

console.log('\ndecodeResponse: 手工构造的合法响应字节')

function buildHeader(id: number, rcode: number, qdcount: number, ancount: number): number[] {
  return [
    (id >> 8) & 0xff, id & 0xff,
    0x81, 0x80 | (rcode & 0x0f), // QR=1,RD=1,RA=1 + rcode in low nibble
    (qdcount >> 8) & 0xff, qdcount & 0xff,
    (ancount >> 8) & 0xff, ancount & 0xff,
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
  ]
}

const QUESTION_EXAMPLE_COM_A = [
  0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
  0x03, 0x63, 0x6f, 0x6d,
  0x00,
  0x00, 0x01, // QTYPE A
  0x00, 0x01, // QCLASS IN
]

const POINTER_TO_QNAME = [0xc0, 0x0c] // offset 12 = start of QNAME right after the 12-byte header

t('单条 A 记录：answer NAME 用压缩指针，正确解出 IP', () => {
  const bytes = Uint8Array.from([
    ...buildHeader(0x1234, 0, 1, 1),
    ...QUESTION_EXAMPLE_COM_A,
    ...POINTER_TO_QNAME,
    0x00, 0x01, // TYPE = A
    0x00, 0x01, // CLASS = IN
    0x00, 0x00, 0x01, 0x2c, // TTL = 300
    0x00, 0x04, // RDLENGTH = 4
    93, 184, 216, 34, // RDATA
  ])
  const result = decodeResponse(bytes)
  assert.equal(result.rcode, 0)
  assert.deepEqual(result.answers, [{ type: QTYPE_A, ip: '93.184.216.34' }])
})

t('两条 A 记录：都用压缩指针，顺序正确解出两个 IP', () => {
  const record = (ip: number[]) => [
    ...POINTER_TO_QNAME,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x04,
    ...ip,
  ]
  const bytes = Uint8Array.from([
    ...buildHeader(0x1234, 0, 1, 2),
    ...QUESTION_EXAMPLE_COM_A,
    ...record([93, 184, 216, 34]),
    ...record([1, 2, 3, 4]),
  ])
  const result = decodeResponse(bytes)
  assert.deepEqual(result.answers, [
    { type: QTYPE_A, ip: '93.184.216.34' },
    { type: QTYPE_A, ip: '1.2.3.4' },
  ])
})

t('单条 AAAA 记录：正确解出压缩形式的 IPv6', () => {
  const bytes = Uint8Array.from([
    ...buildHeader(0x1234, 0, 1, 1),
    ...QUESTION_EXAMPLE_COM_A,
    ...POINTER_TO_QNAME,
    0x00, 0x1c, // TYPE = AAAA (28)
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x10, // RDLENGTH = 16
    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
  ])
  const result = decodeResponse(bytes)
  assert.deepEqual(result.answers, [{ type: QTYPE_AAAA, ip: '2606:4700:4700:0:0:0:0:1111' }])
})

t('RCODE=3 (NXDOMAIN)：rcode 正确透出，answers 为空数组', () => {
  const bytes = Uint8Array.from([
    ...buildHeader(0x1234, 3, 1, 0),
    ...QUESTION_EXAMPLE_COM_A,
  ])
  const result = decodeResponse(bytes)
  assert.equal(result.rcode, 3)
  assert.deepEqual(result.answers, [])
})

t('CNAME 记录被跳过（不当成 IP），后面的 A 记录仍正确解出——证明是按 RDLENGTH 跳过而不是按类型猜长度', () => {
  const cnameRecord = [
    ...POINTER_TO_QNAME,
    0x00, 0x05, // TYPE = CNAME
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x02, // RDLENGTH = 2 (随便两个字节，反正不解析内容)
    0xc0, 0x0c,
  ]
  const aRecord = [
    ...POINTER_TO_QNAME,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x04,
    8, 8, 8, 8,
  ]
  const bytes = Uint8Array.from([
    ...buildHeader(0x1234, 0, 1, 2),
    ...QUESTION_EXAMPLE_COM_A,
    ...cnameRecord,
    ...aRecord,
  ])
  const result = decodeResponse(bytes)
  assert.deepEqual(result.answers, [{ type: QTYPE_A, ip: '8.8.8.8' }])
})

console.log('\ndecodeResponse: TXT 记录（RFC 1035 §3.3.14：rdata 是一或多个 length-prefixed character-string）')

// 与文件顶部的 QUESTION_EXAMPLE_COM_A 同理，手工构造 question 段，不依赖 encodeQuery——
// decodeResponse 的测试要独立于 encodeQuery 的实现。
function question(hostname: string, qtype: number): number[] {
  const out: number[] = []
  for (const label of hostname.split('.')) {
    out.push(label.length, ...Array.from(Buffer.from(label, 'ascii')))
  }
  out.push(0, (qtype >> 8) & 0xff, qtype & 0xff, 0x00, 0x01)
  return out
}

// segments 里的每个元素是一条 TXT answer 记录的完整内容。元素内如果含有 SPLIT_MARKER，
// 表示这条记录的 rdata 由多个 character-string 拼接而成——在该标记处切开，各自单独
// length-prefix，解码后应重新拼接回不含标记的原字符串。
const SPLIT_MARKER = '\u0000SPLIT\u0000'

function buildTxtResponse(hostname: string, segments: string[]): Uint8Array<ArrayBuffer> {
  const encoder = new TextEncoder()
  const records = segments.map((segment) => {
    const rdata: number[] = []
    for (const chunk of segment.split(SPLIT_MARKER)) {
      const chunkBytes = Array.from(encoder.encode(chunk))
      rdata.push(chunkBytes.length, ...chunkBytes)
    }
    return [
      ...POINTER_TO_QNAME,
      0x00, 0x10, // TYPE = TXT (16)
      0x00, 0x01, // CLASS = IN
      0x00, 0x00, 0x01, 0x2c, // TTL = 300
      (rdata.length >> 8) & 0xff, rdata.length & 0xff, // RDLENGTH
      ...rdata,
    ]
  })
  return Uint8Array.from([
    ...buildHeader(0, 0, 1, records.length),
    ...question(hostname, QTYPE_TXT),
    ...records.flat(),
  ])
}

function buildMalformedTxtResponse(): Uint8Array<ArrayBuffer> {
  const record = [
    ...POINTER_TO_QNAME,
    0x00, 0x10, // TYPE = TXT
    0x00, 0x01, // CLASS = IN
    0x00, 0x00, 0x01, 0x2c, // TTL
    0x00, 0x03, // RDLENGTH = 3，但下面第一个 character-string 声称长度 10
    0x0a, 0x61, 0x62, // segLen=10, 实际 rdata 里只剩 2 字节 'ab'，越过 RDLENGTH 边界
  ]
  return Uint8Array.from([
    ...buildHeader(0, 0, 1, 1),
    ...question('_x.example.com', QTYPE_TXT),
    ...record,
  ])
}

t('decodeResponse reads a single-segment TXT record', () => {
  const msg = buildTxtResponse('_x.example.com', ['hello'])
  const decoded = decodeResponse(msg)
  assert.equal(decoded.rcode, 0)
  assert.deepEqual(decoded.answers.filter((a) => a.type === QTYPE_TXT).map((a) => a.text), ['hello'])
})

t('decodeResponse concatenates a multi-segment TXT record', () => {
  const msg = buildTxtResponse('_x.example.com', ['abc' + SPLIT_MARKER + 'def'])
  const decoded = decodeResponse(msg)
  assert.deepEqual(decoded.answers.filter((a) => a.type === QTYPE_TXT).map((a) => a.text), ['abcdef'])
})

t('decodeResponse rejects a TXT rdata whose segment length overruns rdlength', () => {
  const msg = buildMalformedTxtResponse()
  assert.throws(() => decodeResponse(msg), /truncated|overrun/i)
})

console.log('\ndecodeResponse: 畸形/截断响应必须 fail closed（抛错，不能返回半截或猜测的数据）')

t('长度小于 12 字节的 header 抛错', () => {
  assert.throws(() => decodeResponse(Uint8Array.from([0, 1, 2])))
})

t('RDLENGTH 声称的长度超出实际缓冲区末尾时抛错，不能静默截断或读越界', () => {
  const bytes = Uint8Array.from([
    ...buildHeader(0x1234, 0, 1, 1),
    ...QUESTION_EXAMPLE_COM_A,
    ...POINTER_TO_QNAME,
    0x00, 0x01,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x04, // RDLENGTH = 4，但下面只给了 2 个字节
    93, 184,
  ])
  assert.throws(() => decodeResponse(bytes))
})

t('A 记录但 RDLENGTH 不是 4 时抛错，不能把错误长度的数据强行拼成一个 IP', () => {
  const bytes = Uint8Array.from([
    ...buildHeader(0x1234, 0, 1, 1),
    ...QUESTION_EXAMPLE_COM_A,
    ...POINTER_TO_QNAME,
    0x00, 0x01, // TYPE = A
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    0x00, 0x03, // RDLENGTH = 3，A 记录应该恒为 4
    93, 184, 216,
  ])
  assert.throws(() => decodeResponse(bytes))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
