/**
 * Test support for suite 0.14.0 (auth-gated signing), used only by the
 * frozen-suite differentials.
 *
 * Suite 0.14.0 changes nothing on the wire and no assertion; it adds one key to
 * the result: ProbeResult.authObservation, on a run stopped at a credential gate
 * whose auth_metadata was judged from that gate. No older suite's result holds
 * what it is computed from (the challenge header, the metadata body), so an
 * older run cannot be remapped to carry it. The differentials of the live suite
 * against frozen suites up to 0.12.0 set it aside on the live side instead, with
 * withoutAuthObservation; suite-0140-differential.test.ts proves the key itself
 * against frozen 0.13.0, where everything else must be identical.
 */
import type { ProbeResult } from './types.ts'

/** A copy of a suite 0.14.0 result without authObservation, every other own
 *  key kept in its order. */
export function withoutAuthObservation(result: ProbeResult): ProbeResult {
  const { authObservation: _set_aside, ...rest } = structuredClone(result)
  return rest
}
