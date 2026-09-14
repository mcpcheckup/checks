import assert from 'node:assert'
import { parseGuardedTarget } from './url-target.ts'
import { SsrfBlocked } from './errors.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

function blockedWith(url: string, code: string) {
  assert.throws(
    () => parseGuardedTarget(url),
    (e: unknown) => e instanceof SsrfBlocked && e.code === code,
    `expected ${JSON.stringify(url)} to throw SsrfBlocked(${code})`,
  )
}

console.log('parseGuardedTarget: scheme')
t('http:// 拒绝', () => blockedWith('http://example.com/', 'NON_HTTPS_SCHEME'))
t('file:// 拒绝', () => blockedWith('file:///etc/passwd', 'NON_HTTPS_SCHEME'))
t('ftp:// 拒绝', () => blockedWith('ftp://example.com/', 'NON_HTTPS_SCHEME'))
t('data: 拒绝', () => blockedWith('data:text/plain,hello', 'NON_HTTPS_SCHEME'))
t('blob: 拒绝', () => blockedWith('blob:https://example.com/uuid', 'NON_HTTPS_SCHEME'))
t('gopher:// 拒绝', () => blockedWith('gopher://example.com/', 'NON_HTTPS_SCHEME'))
t('https:// 允许通过 scheme 检查', () => {
  const target = parseGuardedTarget('https://example.com/mcp')
  assert.equal(target.url.protocol, 'https:')
})

console.log('\nparseGuardedTarget: 凭据')
t('URL 里带用户名密码拒绝', () => blockedWith('https://user:pass@example.com/', 'CREDENTIALS_IN_URL')) // scan-secrets-allow: placeholder credentials, not real
t('只带用户名不带密码也拒绝', () => blockedWith('https://user@example.com/', 'CREDENTIALS_IN_URL')) // scan-secrets-allow: placeholder credentials, not real

console.log('\nparseGuardedTarget: 端口策略（默认 443 之外一律拒绝——见 README「非标准端口」一节的理由）')
t('显式 :443 允许（等价于默认端口）', () => {
  const target = parseGuardedTarget('https://example.com:443/')
  assert.equal(target.hostname, 'example.com')
})
t('省略端口允许', () => {
  const target = parseGuardedTarget('https://example.com/')
  assert.equal(target.hostname, 'example.com')
})
t(':8443 拒绝', () => blockedWith('https://example.com:8443/', 'NON_STANDARD_PORT'))
t(':80 拒绝', () => blockedWith('https://example.com:80/', 'NON_STANDARD_PORT'))

console.log('\nparseGuardedTarget: 格式错误')
t('不是合法 URL 拒绝', () => blockedWith('not a url', 'MALFORMED_URL'))

console.log('\nparseGuardedTarget: IP 字面量识别（含混淆形式——WHATWG URL 解析器会先把它们归一化）')
t('普通域名不被识别为 IP 字面量', () => {
  const target = parseGuardedTarget('https://example.com/')
  assert.equal(target.isIpLiteral, false)
  assert.equal(target.ipFamily, null)
})
t('点分十进制 IPv4 字面量被识别', () => {
  const target = parseGuardedTarget('https://169.254.169.254/') // scan-secrets-allow: cloud metadata IP, testing that it's recognized as an IPv4 literal
  assert.equal(target.isIpLiteral, true)
  assert.equal(target.ipFamily, 4)
  assert.equal(target.hostname, '169.254.169.254')
})
t('十六进制混淆形式 0x7f000001 经 URL 解析器归一化后仍被识别为 IPv4 字面量', () => {
  const target = parseGuardedTarget('https://0x7f000001/') // scan-secrets-allow: obfuscated-loopback example, not a real host
  assert.equal(target.isIpLiteral, true)
  assert.equal(target.ipFamily, 4)
  assert.equal(target.hostname, '127.0.0.1')
})
t('八进制混淆形式 017700000001 经归一化后仍被识别为 IPv4 字面量', () => {
  const target = parseGuardedTarget('https://017700000001/') // scan-secrets-allow: obfuscated-loopback example, not a real host
  assert.equal(target.isIpLiteral, true)
  assert.equal(target.hostname, '127.0.0.1')
})
t('短点分形式 127.1 经归一化后仍被识别为 IPv4 字面量', () => {
  const target = parseGuardedTarget('https://127.1/') // scan-secrets-allow: obfuscated-loopback example, not a real host
  assert.equal(target.isIpLiteral, true)
  assert.equal(target.hostname, '127.0.0.1')
})
t('IPv6 字面量（带方括号）被识别，hostname 去掉方括号', () => {
  const target = parseGuardedTarget('https://[::1]/')
  assert.equal(target.isIpLiteral, true)
  assert.equal(target.ipFamily, 6)
  assert.equal(target.hostname, '::1')
})
t('IPv4-mapped IPv6 字面量 [::ffff:127.0.0.1] 经归一化后按 IPv6 字面量处理', () => {
  const target = parseGuardedTarget('https://[::ffff:127.0.0.1]/')
  assert.equal(target.isIpLiteral, true)
  assert.equal(target.ipFamily, 6)
  assert.equal(target.hostname, '::ffff:7f00:1')
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
