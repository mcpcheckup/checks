/**
 * Test support for suite 0.18.0, used by the differentials that hold the live
 * probe against a frozen older suite.
 *
 * Suite 0.18.0 changes one rule inside one row: tool_description_hygiene
 * (hygiene.ts) adds the unconfirmed_spending flag and lets two injection_imperative
 * patterns match again forms suite 0.16.0 matched and suite 0.17.0 did not. The
 * rule can only add flags, never remove one (suite-0180-differential.test.ts
 * proves that over every tool description the differentials serve plus
 * hygiene-0170-fixtures.ts and hygiene-0180-fixtures.ts). No tool description any
 * older differential serves is one it adds a flag to, so on their inputs the
 * suite 0.18.0 result is the suite 0.17.0 result: this remap changes no row. A
 * differential whose inputs come to include such a description goes red in its
 * own comparison; nothing here hides the difference.
 *
 * recordSuite0180 / suite0180Remap stand in for recordSuite0170 /
 * suite0170Remap: they record and apply the suite 0.17.0 rules first.
 */
import { recordSuite0170, suite0170Remap } from './suite-0170-remap.ts'
import type { Suite0170Observed, Suite0170Recorder } from './suite-0170-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

export type Suite0180Observed = Suite0170Observed
export type Suite0180Recorder = Suite0170Recorder

/** Suite 0.18.0 records nothing of its own: recordSuite0170 around `inner`. */
export function recordSuite0180(inner: FetchLike): Suite0180Recorder {
  return recordSuite0170(inner)
}

/** A copy of a suite 0.17.0 result (or an older one already remapped to it, the
 *  suite 0.17.0 rules included: they are applied here first) as suite 0.18.0
 *  computes it on the differentials' inputs. */
export function suite0180Remap(old: ProbeResult, seen: Suite0180Observed): ProbeResult {
  return hygiene0180Remap(suite0170Remap(old, seen))
}

/** The suite 0.18.0 step alone, on a copy: no row changes. Throws unless the
 *  result has exactly one tool_description_hygiene row. */
export function hygiene0180Remap(old: ProbeResult): ProbeResult {
  const out = structuredClone(old)
  const rows = out.assertions.filter((a) => a.check_id === 'tool_description_hygiene').length
  if (rows !== 1) throw new Error(`suite0180Remap: ${rows} tool_description_hygiene rows`)
  return out
}
