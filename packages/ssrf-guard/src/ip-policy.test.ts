import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
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
t('fec0:: blocked as SITE_LOCAL (just above link-local: the deprecated site-local block, fec0::/10)', () => blocked('fec0::', 6, 'SITE_LOCAL'))

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

/** One test per entry of the IANA Special-Purpose Address Registries ("Last Updated
 *  2025-10-09", retrieved 2026-10-09), in registry order, then the blocks this policy adds
 *  that the registry does not list. Each address is chosen inside the entry and, where the
 *  entry has a more specific child, outside that child. `null` = the registry marks the
 *  entry Globally Reachable = True, so it must stay allowed. Written out by hand rather
 *  than read from ip-policy.ts, so the table cannot agree with the code by construction. */
const REGISTRY_V4: Array<[entry: string, address: string, expected: string | null, note?: string]> = [
  ['0.0.0.0/8', '0.1.2.3', 'THIS_NETWORK'],
  ['0.0.0.0/32', '0.0.0.0', 'THIS_NETWORK'],
  ['10.0.0.0/8', '10.1.2.3', 'PRIVATE_USE'],
  ['100.64.0.0/10', '100.100.1.1', 'CGNAT'],
  ['127.0.0.0/8', '127.5.6.7', 'LOOPBACK'],
  ['169.254.0.0/16', '169.254.10.1', 'LINK_LOCAL'],
  ['172.16.0.0/12', '172.20.0.1', 'PRIVATE_USE'],
  ['192.0.0.0/24', '192.0.0.100', 'PROTOCOL_ASSIGNMENT'],
  ['192.0.0.0/29', '192.0.0.1', 'PROTOCOL_ASSIGNMENT'],
  ['192.0.0.8/32', '192.0.0.8', 'PROTOCOL_ASSIGNMENT'],
  ['192.0.0.9/32', '192.0.0.9', null, 'Globally Reachable = True inside the blocked 192.0.0.0/24'],
  ['192.0.0.10/32', '192.0.0.10', null, 'Globally Reachable = True inside the blocked 192.0.0.0/24'],
  ['192.0.0.170/32', '192.0.0.170', 'PROTOCOL_ASSIGNMENT'],
  ['192.0.0.171/32', '192.0.0.171', 'PROTOCOL_ASSIGNMENT'],
  ['192.0.2.0/24', '192.0.2.200', 'DOCUMENTATION'],
  ['192.31.196.0/24', '192.31.196.1', null],
  ['192.52.193.0/24', '192.52.193.1', null],
  ['192.88.99.0/24', '192.88.99.1', 'DEPRECATED', 'no Globally Reachable value in the registry (deprecated); blocked whole'],
  ['192.88.99.2/32', '192.88.99.2', 'PROTOCOL_ASSIGNMENT'],
  ['192.168.0.0/16', '192.168.1.1', 'PRIVATE_USE'],
  ['192.175.48.0/24', '192.175.48.1', null],
  ['198.18.0.0/15', '198.19.1.1', 'BENCHMARKING'],
  ['198.51.100.0/24', '198.51.100.7', 'DOCUMENTATION'],
  ['203.0.113.0/24', '203.0.113.9', 'DOCUMENTATION'],
  ['240.0.0.0/4', '250.1.2.3', 'RESERVED'],
  ['255.255.255.255/32', '255.255.255.255', 'RESERVED'],
]
const REGISTRY_V6: Array<[entry: string, address: string, expected: string | null, note?: string]> = [
  ['::1/128', '::1', 'LOOPBACK'],
  ['::/128', '::', 'UNSPECIFIED'],
  ['::ffff:0:0/96', '::ffff:a00:1', 'PRIVATE_USE', 'judged by the embedded IPv4 address (10.0.0.1), see the IPv4-mapped tests above'],
  ['64:ff9b::/96', '64:ff9b::808:808', 'NAT64', 'Globally Reachable = True in the registry; blocked whole, even with a public IPv4 address embedded'],
  ['64:ff9b:1::/48', '64:ff9b:1::1', 'NAT64'],
  ['100::/64', '100::1', 'DISCARD_ONLY'],
  ['100:0:0:1::/64', '100:0:0:1::1', 'DUMMY_PREFIX'],
  ['2001::/23', '2001:100::1', 'PROTOCOL_ASSIGNMENT'],
  ['2001::/32', '2001:0:4136:e378::1', 'TEREDO', 'Globally Reachable = N/A in the registry; blocked'],
  ['2001:1::1/128', '2001:1::1', null, 'Globally Reachable = True inside the blocked 2001::/23'],
  ['2001:1::2/128', '2001:1::2', null, 'Globally Reachable = True inside the blocked 2001::/23'],
  ['2001:1::3/128', '2001:1::3', null, 'Globally Reachable = True inside the blocked 2001::/23'],
  ['2001:2::/48', '2001:2::1', 'BENCHMARKING'],
  ['2001:3::/32', '2001:3::1', null, 'Globally Reachable = True inside the blocked 2001::/23'],
  ['2001:4:112::/48', '2001:4:112::1', null, 'Globally Reachable = True inside the blocked 2001::/23'],
  ['2001:10::/28', '2001:10::1', 'DEPRECATED', 'no Globally Reachable value in the registry (deprecated); blocked'],
  ['2001:20::/28', '2001:20::1', null, 'Globally Reachable = True inside the blocked 2001::/23'],
  ['2001:30::/28', '2001:30::1', null, 'Globally Reachable = True inside the blocked 2001::/23'],
  ['2001:db8::/32', '2001:db8::1', 'DOCUMENTATION'],
  ['2002::/16', '2002:c000:204::1', 'SIX_TO_FOUR', 'Globally Reachable = N/A in the registry; blocked whole'],
  ['2620:4f:8000::/48', '2620:4f:8000::1', null],
  ['3fff::/20', '3fff:fff::1', 'DOCUMENTATION'],
  ['5f00::/16', '5f00:1::1', 'SEGMENT_ROUTING'],
  ['fc00::/7', 'fd12:3456::1', 'UNIQUE_LOCAL'],
  ['fe80::/10', 'fe80::abcd', 'LINK_LOCAL'],
]
const ADDED_V6: Array<[entry: string, address: string, expected: string, note: string]> = [
  ['::/96', '::7f00:1', 'IPV4_COMPATIBLE', 'deprecated IPv4-compatible block; ::127.0.0.1 used to get through'],
  ['::/96', '::808:808', 'IPV4_COMPATIBLE', 'blocked whole: a public IPv4 address inside does not make it allowed'],
  ['fec0::/10', 'feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'SITE_LOCAL', 'top of the deprecated site-local block'],
  ['ff00::/8', 'ff02::1', 'MULTICAST', 'link-local all-nodes multicast'],
  ['ff00::/8', 'ff00::', 'MULTICAST', 'bottom of multicast, just above fec0::/10'],
  ['ff00::/8', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'MULTICAST', 'top of the address space'],
]

const show = (expected: string | null) => (expected === null ? 'allowed' : `blocked as ${expected}`)
console.log('\nIANA IPv4 Special-Purpose Address Registry (Last Updated 2025-10-09): one test per entry')
for (const [entry, address, expected, note] of REGISTRY_V4) {
  t(`${entry}: ${address} ${show(expected)}${note ? ` (${note})` : ''}`, () => expected === null ? allowed(address, 4) : blocked(address, 4, expected))
}
console.log('\nIANA IPv6 Special-Purpose Address Registry (Last Updated 2025-10-09): one test per entry')
for (const [entry, address, expected, note] of REGISTRY_V6) {
  t(`${entry}: ${address} ${show(expected)}${note ? ` (${note})` : ''}`, () => expected === null ? allowed(address, 6) : blocked(address, 6, expected))
}
console.log('\nIPv6 blocks not in the special-purpose registry')
for (const [entry, address, expected, note] of ADDED_V6) {
  t(`${entry}: ${address} blocked as ${expected} (${note})`, () => blocked(address, 6, expected))
}

console.log('\nEdges of the newly blocked ranges, and the most specific entry deciding')
t('191.255.255.255 allowed (just below 192.0.0.0/24)', () => allowed('191.255.255.255', 4))
t('192.0.0.255 blocked (top of 192.0.0.0/24)', () => blocked('192.0.0.255', 4, 'PROTOCOL_ASSIGNMENT'))
t('192.0.1.0 allowed (just above 192.0.0.0/24)', () => allowed('192.0.1.0', 4))
t('192.0.0.11 blocked (next to the allowed 192.0.0.10: only the registry entry itself is allowed)', () => blocked('192.0.0.11', 4, 'PROTOCOL_ASSIGNMENT'))
t('192.88.98.255 allowed / 192.88.100.0 allowed (either side of 192.88.99.0/24)', () => { allowed('192.88.98.255', 4); allowed('192.88.100.0', 4) })
t('198.51.99.255 allowed / 198.51.101.0 allowed (either side of 198.51.100.0/24)', () => { allowed('198.51.99.255', 4); allowed('198.51.101.0', 4) })
t('203.0.112.255 allowed / 203.0.114.0 allowed (either side of 203.0.113.0/24)', () => { allowed('203.0.112.255', 4); allowed('203.0.114.0', 4) })
t('2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff blocked (top of 2001::/23)', () => blocked('2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff', 6, 'PROTOCOL_ASSIGNMENT'))
t('2001:200::1 allowed (just above 2001::/23: ordinary allocated space)', () => allowed('2001:200::1', 6))
t('2001:1::4 blocked (next to the allowed 2001:1::3: only the registry entry itself is allowed)', () => blocked('2001:1::4', 6, 'PROTOCOL_ASSIGNMENT'))
t('2001:3::1 allowed while 2001:2::1 is blocked (most specific entry decides inside 2001::/23)', () => { allowed('2001:3::1', 6); blocked('2001:2::1', 6, 'BENCHMARKING') })
t('2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff allowed / 2003::1 allowed (either side of 2002::/16)', () => { allowed('2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 6); allowed('2003::1', 6) })
t('2001:db7:ffff:ffff:ffff:ffff:ffff:ffff allowed / 2001:db9::1 allowed (either side of 2001:db8::/32)', () => { allowed('2001:db7:ffff:ffff:ffff:ffff:ffff:ffff', 6); allowed('2001:db9::1', 6) })
t('::1 stays LOOPBACK and :: stays UNSPECIFIED inside ::/96 (the /128 entries are more specific)', () => { blocked('::1', 6, 'LOOPBACK'); blocked('::', 6, 'UNSPECIFIED') })

/** The rows of ip-policy.ts that block nothing (`code: null`), read off its TypeScript
 *  AST: base/prefix of every object literal whose `code` property is the `null` keyword.
 *  Each must be a registry entry marked Globally Reachable = True; this list is the whole
 *  set, so a row that would let a new range through cannot be added without editing it. */
function nonBlockingRowsInSource(): string[] {
  const text = readFileSync(new URL('./ip-policy.ts', import.meta.url), 'utf8')
  const sf = ts.createSourceFile('ip-policy.ts', text, ts.ScriptTarget.Latest, true)
  const out: string[] = []
  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      const prop = (name: string) => node.properties.find((p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === name)?.initializer
      const code = prop('code')
      if (code !== undefined) {
        if (code.kind !== ts.SyntaxKind.NullKeyword && !ts.isStringLiteral(code)) throw new Error(`ip-policy.ts: a row whose code is neither a string literal nor null: ${code.getText(sf)}`)
        const base = prop('base'), prefix = prop('prefix')
        if (base === undefined || !ts.isStringLiteral(base) || prefix === undefined || !ts.isNumericLiteral(prefix)) throw new Error(`ip-policy.ts: a row without a literal base and prefix: ${node.getText(sf)}`)
        if (code.kind === ts.SyntaxKind.NullKeyword) out.push(`${base.text}/${prefix.text}`)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return out.sort()
}

t('the rows that block nothing are exactly the registry entries marked Globally Reachable = True (read off the AST)', () => {
  assert.deepEqual(nonBlockingRowsInSource(), [
    '192.0.0.10/32', '192.0.0.9/32', '192.175.48.0/24', '192.31.196.0/24', '192.52.193.0/24',
    '2001:1::1/128', '2001:1::2/128', '2001:1::3/128', '2001:20::/28', '2001:30::/28', '2001:3::/32', '2001:4:112::/48',
    '2620:4f:8000::/48',
  ])
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
