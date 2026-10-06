import { canonicalize } from '@mcpcheckup/canonicalizer'

/** One tool of a stored tool list. `inputSchema: undefined` is read as `null` (a stored row holds NULL for a missing schema). */
export interface ToolItem {
  name: string
  description: string | null
  inputSchema: unknown
  /** Names of fields that could not be stored for this tool. Any entry makes the side unitemizable. */
  unstorable?: readonly string[]
}

/** One side of a comparison: the tools that were stored, and how many tools the list had. */
export interface ToolsetSide {
  items: readonly ToolItem[]
  toolCount: number
}

/** In priority order: when several hold, the first one that holds on either side is the one reported. */
export const UNITEMIZABLE_REASONS = Object.freeze([
  'DUPLICATE_NAME',
  'UNSTORABLE_FIELDS',
  'ITEM_COUNT_MISMATCH',
  'NOT_CANONICALIZABLE',
] as const)
export type UnitemizableReason = (typeof UNITEMIZABLE_REASONS)[number]

export type ToolsetDiff =
  | { kind: 'unchanged' }
  | {
      kind: 'changed'
      added: string[]
      removed: string[]
      descriptionChanged: { name: string; before: string | null; after: string | null }[]
      schemaChanged: { name: string }[]
    }
  | { kind: 'unitemizable'; reason: UnitemizableReason; side: 'before' | 'after' | 'both' }

interface Row {
  item: ToolItem
  key: string // canonicalize(name): the identity used for matching and duplicate detection
  order: string // the name in NFC form: the sort key (escaping in a serialization never affects order)
  description: string // canonicalize(description)
  schema: string // canonicalize(inputSchema ?? null)
}

interface Analysis {
  holds: Record<UnitemizableReason, boolean>
  rows: Row[] // meaningful only when no reason holds
}

/** The canonical form of `value`, or null when canonicalize refuses it (for any reason at all). */
function tryCanonicalize(value: unknown): string | null {
  try {
    return canonicalize(value)
  } catch {
    return null
  }
}

/** Programmer errors (wrong shapes), as opposed to data problems. */
function assertShape(side: unknown, label: string): asserts side is ToolsetSide {
  const s = side as { items?: unknown; toolCount?: unknown } | null
  if (typeof s !== 'object' || s === null || !Array.isArray(s.items) || typeof s.toolCount !== 'number') {
    throw new TypeError(`${label}: expected { items: array, toolCount: number }`)
  }
  s.items.forEach((item: unknown, i: number) => {
    const t = item as { name?: unknown; unstorable?: unknown } | null
    if (typeof t !== 'object' || t === null || typeof t.name !== 'string') {
      throw new TypeError(`${label}.items[${i}]: expected an object with a string "name"`)
    }
    if (t.unstorable !== undefined && !Array.isArray(t.unstorable)) {
      throw new TypeError(`${label}.items[${i}].unstorable: expected an array when present`)
    }
  })
}

function analyse(side: ToolsetSide): Analysis {
  const rows: Row[] = []
  const names = new Set<string>()
  const holds = {
    DUPLICATE_NAME: false,
    UNSTORABLE_FIELDS: false,
    ITEM_COUNT_MISMATCH: side.items.length !== side.toolCount,
    NOT_CANONICALIZABLE: false,
  }
  for (const item of side.items) {
    if (item.unstorable !== undefined && item.unstorable.length > 0) holds.UNSTORABLE_FIELDS = true
    const key = tryCanonicalize(item.name)
    if (key !== null) {
      if (names.has(key)) holds.DUPLICATE_NAME = true
      names.add(key)
    }
    // Only a string or null is a description; anything else (including undefined) is not canonicalizable here.
    const description = item.description === null || typeof item.description === 'string' ? tryCanonicalize(item.description) : null
    const schema = tryCanonicalize(item.inputSchema ?? null)
    if (key === null || description === null || schema === null) holds.NOT_CANONICALIZABLE = true
    else rows.push({ item, key, order: item.name.normalize('NFC'), description, schema })
  }
  return { holds, rows }
}

// Total: two names with the same NFC form share a canonical form, so they are DUPLICATE_NAME and never reach here.
function byOrder(a: Row, b: Row): number {
  return a.order < b.order ? -1 : a.order > b.order ? 1 : 0
}

/**
 * Compares two tool lists tool by tool. Pure and deterministic; the inputs are not modified.
 *
 * Names, descriptions and schemas are compared by their nfc-jcs/v1 canonical form, so a description
 * that differs only in Unicode normalization is not a change, and `null` differs from `""`.
 * Tools are matched by canonical name; a rename is reported as one removal plus one addition.
 * Every list is sorted by the name in NFC form in UTF-16 code-unit order, so input order never shows.
 *
 * When either side cannot be itemized, the result is `unitemizable` with exactly one reason: the
 * first of UNITEMIZABLE_REASONS that holds on either side, and `side` names the side(s) it holds on.
 * Data problems never throw. A wrongly shaped argument (a non-array `items`, a non-number
 * `toolCount`, a non-string `name`) throws a TypeError.
 */
export function diffToolsets(before: ToolsetSide, after: ToolsetSide): ToolsetDiff {
  assertShape(before, 'before')
  assertShape(after, 'after')
  const b = analyse(before)
  const a = analyse(after)
  for (const reason of UNITEMIZABLE_REASONS) {
    const onBefore = b.holds[reason]
    const onAfter = a.holds[reason]
    if (onBefore || onAfter) {
      return { kind: 'unitemizable', reason, side: onBefore && onAfter ? 'both' : onBefore ? 'before' : 'after' }
    }
  }

  const beforeByKey = new Map(b.rows.map((row) => [row.key, row]))
  const afterKeys = new Set(a.rows.map((row) => row.key))
  const added: string[] = []
  const removed: string[] = []
  const descriptionChanged: { name: string; before: string | null; after: string | null }[] = []
  const schemaChanged: { name: string }[] = []

  for (const row of [...a.rows].sort(byOrder)) {
    const prev = beforeByKey.get(row.key)
    if (prev === undefined) {
      added.push(row.item.name)
      continue
    }
    if (prev.description !== row.description) {
      descriptionChanged.push({ name: row.item.name, before: prev.item.description, after: row.item.description })
    }
    if (prev.schema !== row.schema) schemaChanged.push({ name: row.item.name })
  }
  for (const row of [...b.rows].sort(byOrder)) {
    if (!afterKeys.has(row.key)) removed.push(row.item.name)
  }

  if (added.length + removed.length + descriptionChanged.length + schemaChanged.length === 0) return { kind: 'unchanged' }
  return { kind: 'changed', added, removed, descriptionChanged, schemaChanged }
}
