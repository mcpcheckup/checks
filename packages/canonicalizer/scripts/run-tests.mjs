// 零依赖测试聚合器：把 src/**/*.test.ts 当独立子进程逐个跑（而不是 import 进同一进程），
// 保证每个测试文件之间完全隔离——不共享模块级状态，一个文件的问题不会连累其它文件。
import { spawnSync } from 'node:child_process'
import { readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const srcDir = fileURLToPath(new URL('../src', import.meta.url))

function findTestFiles(dir, base = '') {
  const out = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const rel = base ? `${base}/${entry.name}` : entry.name
    if (entry.isDirectory()) out.push(...findTestFiles(`${dir}/${entry.name}`, rel))
    else if (entry.name.endsWith('.test.ts')) out.push(rel)
  }
  return out
}

const files = findTestFiles(srcDir).sort()
if (files.length === 0) {
  console.error('未找到任何 *.test.ts')
  process.exitCode = 1
} else {
  let failed = false
  for (const f of files) {
    console.log(`\n=== src/${f} ===`)
    const r = spawnSync(process.execPath, [`src/${f}`], { stdio: 'inherit', cwd: root })
    if (r.status !== 0) failed = true
  }
  process.exitCode = failed ? 1 : 0
}
