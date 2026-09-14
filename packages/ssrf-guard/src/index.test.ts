import assert from 'node:assert'
import * as pkg from './index.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('index：公开 API 面')

t('导出 guardedFetch', () => {
  assert.equal(typeof pkg.guardedFetch, 'function')
})

t('导出预算相关：DEFAULT_PROBE_BUDGET / createProbeBudget', () => {
  assert.equal(pkg.DEFAULT_PROBE_BUDGET.maxRequests, 8)
  assert.equal(typeof pkg.createProbeBudget, 'function')
})

t('导出限流相关：assertRateLimitAllowed', () => {
  assert.equal(typeof pkg.assertRateLimitAllowed, 'function')
})

t('导出 DNS 解析相关：resolveHost / resolveAndValidateHost / validateAddresses / DOH_ENDPOINT', () => {
  assert.equal(typeof pkg.resolveHost, 'function')
  assert.equal(typeof pkg.resolveAndValidateHost, 'function')
  assert.equal(typeof pkg.validateAddresses, 'function')
  assert.equal(pkg.DOH_ENDPOINT, 'https://cloudflare-dns.com/dns-query') // scan-secrets-allow: real Cloudflare DoH endpoint
})

t('导出 IP 策略相关：classifyIp / classifyIpv4 / classifyIpv6，从 index 调用也能正常工作', () => {
  assert.equal(typeof pkg.classifyIp, 'function')
  assert.equal(pkg.classifyIp('127.0.0.1', 4).blocked, true)
})

t('导出 URL 目标解析：parseGuardedTarget', () => {
  assert.equal(typeof pkg.parseGuardedTarget, 'function')
})

t('导出错误类：SsrfGuardError / SsrfBlocked / BudgetExceeded / RateLimited', () => {
  assert.equal(typeof pkg.SsrfGuardError, 'function')
  assert.equal(typeof pkg.SsrfBlocked, 'function')
  assert.equal(typeof pkg.BudgetExceeded, 'function')
  assert.equal(typeof pkg.RateLimited, 'function')
  assert.ok(new pkg.SsrfBlocked('X', 'y') instanceof pkg.SsrfGuardError)
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
