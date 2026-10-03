// 零依赖测试聚合器：把 src/**/*.test.ts 当独立子进程逐个跑（而不是 import 进同一进程），
// 保证每个测试文件之间完全隔离——不共享模块级状态，一个文件的问题不会连累其它文件。
//
// TODO 441（CI speed）：三个最重的 differential 文件（下面 SHARD_PLAN 的 key）改成
// 两个分片进程并发跑，外加一个 merge 进程把分片各自算出的计数器合并、跑那些依赖
// "全集" 的断言（覆盖面/vacuousness 检查——单个分片跑会有 false negative 的风险，
// 见 src/differential-shard.ts 模块注释）。三个分片进程之间用一次性的临时目录传递
// JSON（每个分片各写一份，merge 读全部）。除了这三个文件，其它每个测试文件仍然
// 和过去一样单进程串行跑，顺序不变。
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, readdirSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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

// Pinned total input counts (packages/checks/src/*-differential.test.ts's own
// printed totals, verified against a pre-sharding run — see the PR's
// Completion Report). A shard silently processing fewer inputs than this
// (e.g. a dropped shard, or a shard/merge count mismatch) must fail the
// build even though every individual process may exit 0 — see this file's
// own assertTotal() below.
const SHARD_PLAN = {
  'probe-tool-name-differential.test.ts': { pinned: 154262, total: (s) => s.total },
  'failed-reasons-differential.test.ts': { pinned: 88347, total: (s) => s.total },
  // T96: 76 fixtures x 159 inputs each (was 74; +handshake-discover-rejected-200, +handshake-discover-202-falls-back).
  'guard-error-classification-differential.test.ts': { pinned: 12084, total: (s) => s.totalA + s.totalB },
}

/** Runs one file as a single, unsharded process — today's behavior, used for
 *  every file that isn't in SHARD_PLAN. */
function runSerial(f) {
  console.log(`\n=== src/${f} ===`)
  const r = spawnSync(process.execPath, [`src/${f}`], { stdio: 'inherit', cwd: root })
  return r.status === 0
}

/** Spawns one child with the given env additions, capturing (not streaming)
 *  its stdout/stderr so concurrent shards' output doesn't interleave —
 *  callers print each child's buffered output as one contiguous block once
 *  every child in the group has finished. */
function runChild(f, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [`src/${f}`], { cwd: root, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    child.stdout.on('data', (c) => { out += c })
    child.stderr.on('data', (c) => { out += c })
    child.on('error', (err) => resolve({ status: 1, output: `${out}failed to start: ${err.message}\n` }))
    child.on('close', (status) => resolve({ status: status ?? 1, output: out }))
  })
}

/** Runs one SHARD_PLAN file as two concurrent shards plus a merge step. See
 *  this file's own module doc and src/differential-shard.ts for the design. */
async function runSharded(f, plan) {
  const dir = mkdtempSync(join(tmpdir(), 'checks-shard-'))
  const outFiles = [join(dir, 'shard-0.json'), join(dir, 'shard-1.json')]
  let ok = true
  try {
    const shardEnv = (i) => ({ SHARD_INDEX: String(i), SHARD_COUNT: '2', SHARD_MODE: 'run', SHARD_OUT_FILE: outFiles[i] })
    const [s0, s1] = await Promise.all([0, 1].map((i) => runChild(f, shardEnv(i))))
    console.log(`\n=== src/${f} [shard 1/2] ===\n${s0.output}`)
    console.log(`\n=== src/${f} [shard 2/2] ===\n${s1.output}`)
    if (s0.status !== 0) { console.error(`run-tests: src/${f} [shard 1/2] exited ${s0.status}`); ok = false }
    if (s1.status !== 0) { console.error(`run-tests: src/${f} [shard 2/2] exited ${s1.status}`); ok = false }

    const merge = await runChild(f, { SHARD_MODE: 'merge', SHARD_IN_FILES: outFiles.join(',') })
    console.log(`\n=== src/${f} [merge] ===\n${merge.output}`)
    if (merge.status !== 0) { console.error(`run-tests: src/${f} [merge] exited ${merge.status}`); ok = false }

    // Independent of what the merge process itself asserted: sum each
    // shard's own reported total straight from its JSON output and compare
    // to the pinned count above. A shard that silently processed fewer
    // inputs than it should have (a partitioning bug, or one shard simply
    // missing) would not necessarily make `violations` nonzero — this is
    // the check that catches that case (AC "a wrong total → RED").
    let summed = 0
    for (const path of outFiles) {
      const state = JSON.parse(readFileSync(path, 'utf8'))
      summed += plan.total(state)
    }
    if (summed !== plan.pinned) {
      console.error(`run-tests: src/${f} — shards processed ${summed} inputs total, expected ${plan.pinned} (pinned). A shard is missing, mis-partitioned, or the pinned count in run-tests.mjs is stale.`)
      ok = false
    } else {
      console.log(`run-tests: src/${f} — shard totals sum to ${summed}, matches the pinned ${plan.pinned}`)
    }
  } catch (err) {
    console.error(`run-tests: src/${f} — sharded run failed: ${err instanceof Error ? err.message : String(err)}`)
    ok = false
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
  return ok
}

const files = findTestFiles(srcDir).sort()
if (files.length === 0) {
  console.error('未找到任何 *.test.ts')
  process.exitCode = 1
} else {
  let failed = false
  for (const f of files) {
    const plan = SHARD_PLAN[f]
    // eslint-disable-next-line no-await-in-loop -- deliberate: every OTHER
    // file still runs strictly serially, same order as before this task.
    const ok = plan ? await runSharded(f, plan) : runSerial(f)
    if (!ok) failed = true
  }
  process.exitCode = failed ? 1 : 0
}
