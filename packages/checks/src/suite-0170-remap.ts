/**
 * Test support for suite 0.17.0, used by the differentials that hold the live
 * probe against a frozen older suite.
 *
 * Suite 0.17.0 changes one rule inside one row: tool_description_hygiene
 * (hygiene.ts) no longer counts a ZWNJ/ZWJ where ordinary orthography puts it,
 * and two injection_imperative patterns only match forms addressed to the
 * assistant. The rule can only remove flags, never add one
 * (suite-0170-differential.test.ts proves that over every tool description the
 * differentials serve plus hygiene-0170-fixtures.ts). No tool description any
 * older differential serves is one it removes a flag from, so on their inputs the
 * suite 0.17.0 result is the suite 0.16.0 result: this remap changes no row. A
 * differential whose inputs come to include such a description goes red in its
 * own comparison; nothing here hides the difference.
 *
 * recordSuite0170 / suite0170Remap stand in for recordSuite0160 /
 * suite0160Remap: they record and apply the suite 0.16.0 rules first.
 */
import { recordSuite0160, suite0160Remap } from './suite-0160-remap.ts'
import type { Suite0160Observed, Suite0160Recorder } from './suite-0160-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

export type Suite0170Observed = Suite0160Observed
export type Suite0170Recorder = Suite0160Recorder

/** Suite 0.17.0 records nothing of its own: recordSuite0160 around `inner`. */
export function recordSuite0170(inner: FetchLike): Suite0170Recorder {
  return recordSuite0160(inner)
}

/** A copy of a suite 0.16.0 result (or an older one already remapped to it, the
 *  suite 0.16.0 rules included: they are applied here first) as suite 0.17.0
 *  computes it on the differentials' inputs. */
export function suite0170Remap(old: ProbeResult, seen: Suite0170Observed): ProbeResult {
  return hygiene0170Remap(suite0160Remap(old, seen))
}

/** The suite 0.17.0 step alone, on a copy: no row changes. Throws unless the
 *  result has exactly one tool_description_hygiene row. */
export function hygiene0170Remap(old: ProbeResult): ProbeResult {
  const out = structuredClone(old)
  const rows = out.assertions.filter((a) => a.check_id === 'tool_description_hygiene').length
  if (rows !== 1) throw new Error(`suite0170Remap: ${rows} tool_description_hygiene rows`)
  return out
}
