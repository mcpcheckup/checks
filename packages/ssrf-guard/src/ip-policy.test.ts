import assert from 'node:assert'
import { classifyIp } from './ip-policy.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

function allowed(ip: string, family: 4 | 6) {
  const v = classifyIp(ip, family)
  assert.equal(v.blocked, false, `expected ${ip} to be allowed, got blocked: ${JSON.stringify(v)}`)
}
function blocked(ip: string, family: 4 | 6, expectedCode?: string) {
  const v = classifyIp(ip, family)
  assert.equal(v.blocked, true, `expected ${ip} to be blocked, got allowed`)
  if (expectedCode) assert.equal((v as { code: string }).code, expectedCode, `${ip}: expected code ${expectedCode}, got ${(v as { code: string }).code}`)
}

console.log('classifyIp: IPv4 — 10.0.0.0/8')
t('10.0.0.1 blocked', () => blocked('10.0.0.1', 4, 'PRIVATE_USE'))
t('10.255.255.255 blocked (top of range)', () => blocked('10.255.255.255', 4, 'PRIVATE_USE'))
t('9.255.255.255 allowed (just below range)', () => allowed('9.255.255.255', 4))
t('11.0.0.0 allowed (just above range)', () => allowed('11.0.0.0', 4))

console.log('\nclassifyIp: IPv4 — 172.16.0.0/12')
t('172.16.0.0 blocked (bottom of range)', () => blocked('172.16.0.0', 4, 'PRIVATE_USE'))
t('172.31.255.255 blocked (top of range)', () => blocked('172.31.255.255', 4, 'PRIVATE_USE'))
t('172.15.255.255 allowed (just below range)', () => allowed('172.15.255.255', 4))
t('172.32.0.0 allowed (just above range)', () => allowed('172.32.0.0', 4))

console.log('\nclassifyIp: IPv4 — 192.168.0.0/16')
t('192.168.0.1 blocked', () => blocked('192.168.0.1', 4, 'PRIVATE_USE'))
t('192.167.255.255 allowed (just below range)', () => allowed('192.167.255.255', 4))
t('192.169.0.0 allowed (just above range)', () => allowed('192.169.0.0', 4))

console.log('\nclassifyIp: IPv4 — 127.0.0.0/8 (loopback)')
t('127.0.0.1 blocked', () => blocked('127.0.0.1', 4, 'LOOPBACK'))
t('127.255.255.255 blocked (top of range)', () => blocked('127.255.255.255', 4, 'LOOPBACK'))
t('126.255.255.255 allowed (just below range)', () => allowed('126.255.255.255', 4))
t('128.0.0.0 allowed (just above range)', () => allowed('128.0.0.0', 4))

console.log('\nclassifyIp: IPv4 — 169.254.0.0/16 (link-local) 与云 metadata')
t('169.254.1.1 blocked as LINK_LOCAL', () => blocked('169.254.1.1', 4, 'LINK_LOCAL'))
t('169.254.169.254 blocked with dedicated CLOUD_METADATA code（不是笼统的 LINK_LOCAL）', () =>
  blocked('169.254.169.254', 4, 'CLOUD_METADATA'))
t('169.253.255.255 allowed (just below range)', () => allowed('169.253.255.255', 4))
t('169.255.0.0 allowed (just above range)', () => allowed('169.255.0.0', 4))

console.log('\nclassifyIp: IPv4 — 0.0.0.0/8')
t('0.0.0.0 blocked', () => blocked('0.0.0.0', 4, 'THIS_NETWORK'))
t('0.255.255.255 blocked (top of range)', () => blocked('0.255.255.255', 4, 'THIS_NETWORK'))
t('1.0.0.0 allowed (just above range)', () => allowed('1.0.0.0', 4))

console.log('\nclassifyIp: IPv4 — 100.64.0.0/10 (CGNAT)')
t('100.64.0.1 blocked', () => blocked('100.64.0.1', 4, 'CGNAT'))
t('100.127.255.255 blocked (top of range)', () => blocked('100.127.255.255', 4, 'CGNAT'))
t('100.63.255.255 allowed (just below range)', () => allowed('100.63.255.255', 4))
t('100.128.0.0 allowed (just above range)', () => allowed('100.128.0.0', 4))

console.log('\nclassifyIp: IPv4 — 192.0.2.0/24 (TEST-NET-1)')
t('192.0.2.1 blocked', () => blocked('192.0.2.1', 4, 'DOCUMENTATION'))
t('192.0.1.255 allowed (just below range)', () => allowed('192.0.1.255', 4))
t('192.0.3.0 allowed (just above range)', () => allowed('192.0.3.0', 4))

console.log('\nclassifyIp: IPv4 — 198.18.0.0/15 (benchmarking)')
t('198.18.0.1 blocked', () => blocked('198.18.0.1', 4, 'BENCHMARKING'))
t('198.19.255.255 blocked (top of range)', () => blocked('198.19.255.255', 4, 'BENCHMARKING'))
t('198.17.255.255 allowed (just below range)', () => allowed('198.17.255.255', 4))
t('198.20.0.0 allowed (just above range)', () => allowed('198.20.0.0', 4))

console.log('\nclassifyIp: IPv4 — 224.0.0.0/4 (multicast) 与 240.0.0.0/4 (reserved)')
t('224.0.0.1 blocked as MULTICAST', () => blocked('224.0.0.1', 4, 'MULTICAST'))
t('239.255.255.255 blocked (top of multicast)', () => blocked('239.255.255.255', 4, 'MULTICAST'))
t('223.255.255.255 allowed (just below multicast)', () => allowed('223.255.255.255', 4))
t('240.0.0.1 blocked as RESERVED', () => blocked('240.0.0.1', 4, 'RESERVED'))
t('255.255.255.255 blocked (broadcast, top of reserved)', () => blocked('255.255.255.255', 4, 'RESERVED'))

console.log('\nclassifyIp: IPv4 — 正常公网地址（正例）')
t('8.8.8.8 allowed', () => allowed('8.8.8.8', 4))
t('93.184.216.34 allowed', () => allowed('93.184.216.34', 4))

console.log('\nclassifyIp: IPv6 — ::1 (loopback) 与 ::（unspecified）')
t('::1 blocked as LOOPBACK', () => blocked('::1', 6, 'LOOPBACK'))
t(':: blocked as UNSPECIFIED', () => blocked('::', 6, 'UNSPECIFIED'))

console.log('\nclassifyIp: IPv6 — fc00::/7 (ULA)')
t('fc00::1 blocked', () => blocked('fc00::1', 6, 'UNIQUE_LOCAL'))
t('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff blocked (top of range)', () =>
  blocked('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 6, 'UNIQUE_LOCAL'))
t('fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff allowed (just below range)', () =>
  allowed('fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 6))
t('fe00:: allowed (just above range)', () => allowed('fe00::', 6))

console.log('\nclassifyIp: IPv6 — fd00:ec2::254（AWS IMDSv2 的 IPv6 metadata 地址，专用测试）')
t('fd00:ec2::254 blocked with dedicated CLOUD_METADATA code（不是笼统的 UNIQUE_LOCAL）', () =>
  blocked('fd00:ec2::254', 6, 'CLOUD_METADATA'))

console.log('\nclassifyIp: IPv6 — fe80::/10 (link-local)')
t('fe80::1 blocked', () => blocked('fe80::1', 6, 'LINK_LOCAL'))
t('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff blocked (top of range)', () =>
  blocked('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 6, 'LINK_LOCAL'))
t('fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff allowed (just below range)', () =>
  allowed('fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 6))
t('fec0:: allowed (just above range)', () => allowed('fec0::', 6))

console.log('\nclassifyIp: IPv6 — ::ffff:0:0/96 (IPv4-mapped，必须解出内嵌 v4 再校验)')
t('::ffff:7f00:1 (内嵌 127.0.0.1) blocked as LOOPBACK（证明真的解出内嵌 v4 并复用 v4 规则，不是整段放行或整段拦截）', () =>
  blocked('::ffff:7f00:1', 6, 'LOOPBACK'))
t('::ffff:808:808 (内嵌 8.8.8.8) allowed（同一前缀下内嵌公网地址必须放行，证明不是整段拦截）', () =>
  allowed('::ffff:808:808', 6))
t('::ffff:a9fe:a9fe (内嵌 169.254.169.254) blocked as CLOUD_METADATA', () =>
  blocked('::ffff:a9fe:a9fe', 6, 'CLOUD_METADATA'))

console.log('\nclassifyIp: IPv6 — 正常公网地址（正例）')
t('2606:4700:4700::1111 allowed (Cloudflare 自己的 1.1.1.1 的 IPv6 地址)', () =>
  allowed('2606:4700:4700::1111', 6))

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
