import checksRegistry from '../checks.json' with { type: 'json' }

export interface CheckDefinition {
  n: number
  check_id: string
  group: string
  docs_version: string
  predicate_zh: string
  predicate_en: string
  failure_status: string | null
  requires_baseline: boolean
  observation_only?: boolean
  no_credential_status?: string
  no_baseline_status?: string
  no_baseline_reason_zh?: string
  no_baseline_reason_en?: string
  revision_matrix?: string[]
  executor?: string
  p0_note_zh?: string
  p0_note_en?: string
  explain: { what_zh: string; what_en: string; how_zh: string; how_en: string; cannot_zh: string; cannot_en: string }
}

export interface CheckGroup {
  key: string
  name_zh: string
  name_en: string
  order: number
  description_zh: string
  description_en: string
}

export interface ChecksRegistry {
  suite_id: string
  registry_version: string
  groups: CheckGroup[]
  checks: CheckDefinition[]
  budget: {
    max_requests: number
    max_duration_ms: number
    max_body_bytes: number
    max_redirects: number
    unclaimed_max_requests: number
    on_exceeded: { execution_status: string; assertion_status: string }
  }
}

export const CHECKS_REGISTRY = checksRegistry as ChecksRegistry

export function getCheckIds(): string[] {
  return CHECKS_REGISTRY.checks.map((c) => c.check_id)
}

export function isKnownCheckId(id: string): boolean {
  return getCheckIds().includes(id)
}

export function getCheckDefinition(id: string): CheckDefinition | undefined {
  return CHECKS_REGISTRY.checks.find((c) => c.check_id === id)
}
