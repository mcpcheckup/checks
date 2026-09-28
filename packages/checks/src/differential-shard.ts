/**
 * Shared sharding harness for the three heaviest differential test files
 * (probe-tool-name-differential / failed-reasons-differential /
 * guard-error-classification-differential.test.ts — TODO 441, CI speed).
 * packages/checks/scripts/run-tests.mjs spawns TWO processes per file (one
 * per shard, run concurrently) plus a third "merge" process that performs
 * the whole-input-space assertions those files can't safely split — this
 * module is the contract between the runner and the three files.
 *
 * Env contract (all optional — with none of them set, a plain
 * `node src/<file>.test.ts` behaves EXACTLY as before this task: one
 * process, every input, every assertion, unchanged):
 *   SHARD_INDEX     0-based index of this shard (default 0)
 *   SHARD_COUNT     total shard count (default 1 = unsharded)
 *   SHARD_MODE      'run' (default) processes this shard's slice of the
 *                     input space; 'merge' skips the input loop entirely and
 *                     reconstructs the FULL counters from every shard's
 *                     SHARD_OUT_FILE instead.
 *   SHARD_OUT_FILE  ('run' mode, SHARD_COUNT>1 only) where this shard writes
 *                     its own counters as JSON, for 'merge' mode to read.
 *   SHARD_IN_FILES  ('merge' mode only) comma-separated SHARD_OUT_FILE paths,
 *                     one per shard, to read and merge.
 *
 * Why a merge process instead of asserting per-shard: a whole-set
 * "non-vacuous" assertion (e.g. "every oracle branch is reached") is a
 * property of the FULL input space. Splitting it across two shards would
 * make it a coin flip — a branch present in the full set could still land
 * entirely in one shard's half, failing the OTHER shard for no real
 * regression (CLAUDE.md 守卫设计原则 #6: a test that can fail for a reason
 * unrelated to what it claims to guard is worse than no test). Per-input
 * "zero violations" checks don't have this problem (a violation in either
 * half is a real violation), but this module still routes them through the
 * same merge step so every original file keeps EXACTLY its pre-sharding
 * assertion count — one file, one process before; one file, three processes
 * (2 shards + 1 merge) after, but only the merge process (or the single
 * unsharded process) runs the whole-set assertions, same count either way.
 */
import { readFileSync, writeFileSync } from 'node:fs'

// TODO 634: bare Number(...) let a typo'd/unset-in-the-wrong-place env var
// (NaN, a negative, or SHARD_COUNT=0) silently make keepThisShard() reject
// every input — the runner's pinned-total assertion caught that when run
// through run-tests.mjs, but named the wrong culprit ("totals don't match"
// instead of the env var), and standalone runs have no such backstop at all
// (fail-open — Codex P3). Validate at parse time instead, naming the
// variable and its raw value.
function parseShardEnvInt(name: string, raw: string): number {
  const n = Number(raw)
  if (!Number.isSafeInteger(n)) throw new Error(`differential-shard: ${name} must be a safe integer, got: ${JSON.stringify(raw)}`)
  return n
}
const rawShardIndex = process.env.SHARD_INDEX ?? '0'
const rawShardCount = process.env.SHARD_COUNT ?? '1'
export const SHARD_INDEX = parseShardEnvInt('SHARD_INDEX', rawShardIndex)
export const SHARD_COUNT = parseShardEnvInt('SHARD_COUNT', rawShardCount)
if (SHARD_COUNT < 1) throw new Error(`differential-shard: SHARD_COUNT must be >= 1, got: ${JSON.stringify(rawShardCount)}`)
if (SHARD_INDEX < 0 || SHARD_INDEX >= SHARD_COUNT) {
  throw new Error(`differential-shard: SHARD_INDEX must satisfy 0 <= SHARD_INDEX < SHARD_COUNT (SHARD_COUNT=${SHARD_COUNT}), got SHARD_INDEX: ${JSON.stringify(rawShardIndex)}`)
}
export const SHARD_MODE: 'run' | 'merge' = process.env.SHARD_MODE === 'merge' ? 'merge' : 'run'
export const IS_MERGE = SHARD_MODE === 'merge'
/** True on the one process responsible for assertions that must run exactly
 *  once no matter how sharding is configured — static / non-loop checks
 *  (blob-id pins, oracle self-consistency on hand-derived cases). Merge
 *  processes don't run these (a 'run'-mode shard already did). */
export const RUNS_ONCE_ONLY = !IS_MERGE && SHARD_INDEX === 0
/** True when this process holds (or has just reconstructed) the FULL input
 *  space's counters — either because it IS the whole thing (unsharded) or
 *  because it's the merge process. This is the gate for whole-set
 *  assertions (the invariant-holds check, every coverage/vacuousness
 *  check). */
export const HAS_FULL_SET = IS_MERGE || SHARD_COUNT === 1

/** Keep only every SHARD_COUNT-th item, by a continuously-incrementing
 *  index starting at 0 — the "outer-loop index modulo SHARD_COUNT"
 *  partition. Always true when unsharded or merging (merge mode never
 *  iterates real inputs — see readShardIns). `counter` is a shared
 *  `{ n: number }` box so multiple stages/loops in the same file can
 *  partition against one continuously-incrementing index. */
export function keepThisShard(counter: { n: number }): boolean {
  const idx = counter.n++
  if (IS_MERGE || SHARD_COUNT === 1) return true
  return idx % SHARD_COUNT === SHARD_INDEX
}

/** Writes this shard's counters for the merge process to read back. Must
 *  only be called in 'run' mode with SHARD_COUNT>1 (a real shard, not the
 *  unsharded whole-set case, which never needs a file at all). */
export function writeShardOut(data: unknown): void {
  const path = process.env.SHARD_OUT_FILE
  if (!path) throw new Error('differential-shard: SHARD_OUT_FILE not set — writeShardOut() is only for a real shard (SHARD_COUNT>1, SHARD_MODE=run)')
  writeFileSync(path, JSON.stringify(data))
}

/** Reads and parses every shard's SHARD_OUT_FILE, in shard order. Must only
 *  be called in 'merge' mode. */
export function readShardIns<T>(): T[] {
  const raw = process.env.SHARD_IN_FILES
  if (!raw) throw new Error('differential-shard: SHARD_IN_FILES not set — readShardIns() is only for SHARD_MODE=merge')
  return raw.split(',').map((p) => JSON.parse(readFileSync(p, 'utf8')) as T)
}

/** Sums same-keyed `Map<string, number>`s (serialized as plain objects across
 *  the shard boundary) into one merged Map. */
export function mergeCountMaps(objs: Record<string, number>[]): Map<string, number> {
  const out = new Map<string, number>()
  for (const obj of objs) for (const [k, v] of Object.entries(obj)) out.set(k, (out.get(k) ?? 0) + v)
  return out
}
