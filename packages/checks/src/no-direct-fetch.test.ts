import assert from 'node:assert'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const srcDir = fileURLToPath(new URL('.', import.meta.url))

function findSourceFiles(dir: string, base = ''): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const rel = base ? `${base}/${entry.name}` : entry.name
    const full = `${dir}/${entry.name}`
    if (entry.isDirectory()) out.push(...findSourceFiles(full, rel))
    else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts')) out.push(rel)
  }
  return out
}

// 匹配裸的 fetch( 调用（不含前缀标识符字符，所以 fetchImpl(、guardedFetch( 不会被
// 误判——这两个都不是把 "fetch(" 作为独立子串出现）。
const DIRECT_FETCH_CALL = /(?<![A-Za-z0-9_.])fetch\(/

console.log('源码扫描：packages/checks/src 的生产代码里不得出现任何直接的 fetch( 调用')
console.log('（唯一的出网途径必须是调用方注入的 fetchImpl —— 生产环境注入 guardedFetch 的适配层，本包自己绝不发起网络请求）')

const files = findSourceFiles(srcDir).sort()

t('确实扫描到了非空的源文件列表（防止这条测试因为路径写错而变成空对空的假通过）', () => {
  assert.ok(files.length > 5, `只找到 ${files.length} 个源文件`)
})

for (const file of files) {
  t(`${file}：不含裸 fetch( 调用`, () => {
    const content = readFileSync(`${srcDir}${file}`, 'utf8')
    assert.equal(DIRECT_FETCH_CALL.test(content), false, `${file} 中出现了直接的 fetch( 调用`)
  })
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
