/**
 * Test support for suite 0.19.0, used by the differentials that hold the live
 * probe against a frozen older suite.
 *
 * Suite 0.19.0 changes one rule inside one row: tool_description_hygiene
 * (hygiene.ts) adds the unprompted_continuation flag, three unconfirmed_spending
 * forms and one injection_imperative form, ends some same-sentence and same-clause windows at more characters
 * (TODO 1316), and no longer counts a tool whose only flag is excessive_length
 * toward OBSERVED_RISK or hitCount. suite-0190-differential.test.ts proves which
 * tools gain or lose a flag over every tool description the differentials serve
 * plus the hygiene fixtures: only hygiene-0190-fixtures.ts's enumerated ones. No
 * tool description any older differential serves gains or loses a flag, and none
 * is flagged excessive_length alone, so on their inputs the suite 0.19.0 result is
 * the suite 0.18.0 result: this remap changes no row. A differential whose inputs
 * come to include such a description goes red in its own comparison; nothing here
 * hides the difference.
 *
 * recordSuite0190 / suite0190Remap stand in for recordSuite0180 /
 * suite0180Remap: they record and apply the suite 0.18.0 rules first.
 */
import { recordSuite0180, suite0180Remap } from './suite-0180-remap.ts'
import type { Suite0180Observed, Suite0180Recorder } from './suite-0180-remap.ts'
import type { FetchLike, ProbeResult } from './types.ts'

export type Suite0190Observed = Suite0180Observed
export type Suite0190Recorder = Suite0180Recorder

/** Suite 0.19.0 records nothing of its own: recordSuite0180 around `inner`. */
export function recordSuite0190(inner: FetchLike): Suite0190Recorder {
  return recordSuite0180(inner)
}

/** A copy of a suite 0.18.0 result (or an older one already remapped to it, the
 *  suite 0.18.0 rules included: they are applied here first) as suite 0.19.0
 *  computes it on the differentials' inputs. */
export function suite0190Remap(old: ProbeResult, seen: Suite0190Observed): ProbeResult {
  return hygiene0190Remap(suite0180Remap(old, seen))
}

/** The suite 0.19.0 step alone, on a copy: no row changes. Throws unless the
 *  result has exactly one tool_description_hygiene row. */
export function hygiene0190Remap(old: ProbeResult): ProbeResult {
  const out = structuredClone(old)
  const rows = out.assertions.filter((a) => a.check_id === 'tool_description_hygiene').length
  if (rows !== 1) throw new Error(`suite0190Remap: ${rows} tool_description_hygiene rows`)
  return out
}
