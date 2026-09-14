/**
 * The "UNVERIFIED needs a reason" rule (CLAUDE.md 三条不可违反的产品原则 #2) is deliberately
 * enforced three times, independently: the `unverified_needs_reason` CHECK constraint in
 * supabase/migrations/0001_core.sql, the `then`/`anyOf` clause on $defs.assertion in
 * schema/attestation.schema.json, and this function. None of the three trusts the others —
 * a bug in the schema or a migration that silently drops the CHECK constraint still leaves
 * this one standing, and vice versa.
 */

export type AssertionInvariantErrorCode = 'UNVERIFIED_NEEDS_REASON'

export class AssertionInvariantError extends Error {
  code: AssertionInvariantErrorCode

  constructor(code: AssertionInvariantErrorCode, message: string) {
    super(message)
    this.name = 'AssertionInvariantError'
    this.code = code
  }
}

export interface AssertionReasonFields {
  assertion_status: string
  reason: { key: string; params?: Record<string, string | number> } | null
  unverified_reason: { key: string; params?: Record<string, string | number> } | null
}

/** Mirrors the database's own constraint: assertion_status <> 'UNVERIFIED' OR coalesce(unverified_reason, reason) IS NOT NULL. */
export function assertUnverifiedHasReason(assertion: AssertionReasonFields): void {
  if (assertion.assertion_status !== 'UNVERIFIED') return
  // Non-null AND non-empty key: this is the layer that doesn't depend on schema or DB to
  // catch this rule, so it must not trust that a non-null reasonRef also has a real key —
  // an empty key ({ key: '' }) is caught by the schema's own key pattern elsewhere, but
  // this independent layer should not rely on that being true.
  const hasUnverifiedReason = assertion.unverified_reason !== null && assertion.unverified_reason.key.length > 0
  const hasReason = assertion.reason !== null && assertion.reason.key.length > 0
  if (!hasUnverifiedReason && !hasReason) {
    throw new AssertionInvariantError(
      'UNVERIFIED_NEEDS_REASON',
      'assertion_status is UNVERIFIED but both reason and unverified_reason are empty — UNVERIFIED must always carry a reason (CLAUDE.md 三条不可违反的产品原则 #2)',
    )
  }
}
