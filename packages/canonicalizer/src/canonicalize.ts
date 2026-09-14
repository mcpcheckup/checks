import { CanonicalizationError } from './errors.ts'

/**
 * Identifies the exact canonicalization scheme implemented here — NOT "RFC 8785",
 * because RFC 8785 §3.1 requires JCS-compliant components to preserve Unicode
 * string data "as is". Normalizing to NFC first, as this package does, is a
 * deliberate deviation from that MUST, so it gets its own name. See README.md.
 *
 *   nfc-jcs/v1 =
 *     1. NFC-normalize every object key and every string value
 *     2. reject if step 1 makes two keys of the same object collide
 *     3. apply RFC 8785 (JCS) to the result — this step alone is strictly
 *        RFC 8785 compliant
 */
export const CANONICALIZATION_PROFILE = 'nfc-jcs/v1'

/**
 * nfc-jcs/v1 (see CANONICALIZATION_PROFILE): RFC 8785 (JCS) applied after a
 * strict NFC-normalization pass over every object key and string value. See
 * README.md for the full rule set and the rationale for each deliberate
 * deviation from raw JCS.
 */
export function canonicalize(value: unknown): string {
  return serialize(value, new Set<object>())
}

export function canonicalBytes(value: unknown): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(canonicalize(value))
}

function serialize(value: unknown, stack: Set<object>): string {
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'

  switch (typeof value) {
    case 'number':
      return serializeNumber(value)
    case 'string':
      return serializeString(normalizeAndCheckSurrogates(value))
    case 'bigint':
      throw new CanonicalizationError('UNSUPPORTED_TYPE', 'bigint is not a supported JSON value')
    case 'undefined':
      throw new CanonicalizationError('UNSUPPORTED_TYPE', 'undefined is not a supported JSON value')
    case 'function':
      throw new CanonicalizationError('UNSUPPORTED_TYPE', 'function is not a supported JSON value')
    case 'symbol':
      throw new CanonicalizationError('UNSUPPORTED_TYPE', 'symbol is not a supported JSON value')
    case 'object':
      return serializeObjectOrArray(value as object, stack)
    default:
      throw new CanonicalizationError('UNSUPPORTED_TYPE', `unsupported type: ${typeof value}`)
  }
}

function serializeObjectOrArray(obj: object, stack: Set<object>): string {
  if (stack.has(obj)) {
    throw new CanonicalizationError('CIRCULAR_REFERENCE', 'value contains a circular reference')
  }
  stack.add(obj)
  try {
    if (Array.isArray(obj)) {
      return '[' + obj.map((item) => serialize(item, stack)).join(',') + ']'
    }
    return serializePlainObject(obj as Record<string, unknown>, stack)
  } finally {
    stack.delete(obj)
  }
}

function serializePlainObject(obj: Record<string, unknown>, stack: Set<object>): string {
  const rawKeys = Object.keys(obj)
  const originalByNormalized = new Map<string, string>()

  for (const rawKey of rawKeys) {
    const normalizedKey = normalizeAndCheckSurrogates(rawKey)
    const priorRawKey = originalByNormalized.get(normalizedKey)
    if (priorRawKey !== undefined) {
      throw new CanonicalizationError(
        'DUPLICATE_KEY_AFTER_NFC',
        `keys ${JSON.stringify(priorRawKey)} and ${JSON.stringify(rawKey)} both normalize (NFC) to ${JSON.stringify(normalizedKey)}`,
      )
    }
    originalByNormalized.set(normalizedKey, rawKey)
  }

  const normalizedKeys = [...originalByNormalized.keys()].sort()

  const parts = normalizedKeys.map((normalizedKey) => {
    const rawKey = originalByNormalized.get(normalizedKey)!
    return serializeString(normalizedKey) + ':' + serialize(obj[rawKey], stack)
  })
  return '{' + parts.join(',') + '}'
}

function normalizeAndCheckSurrogates(s: string): string {
  const normalized = s.normalize('NFC')
  for (const grapheme of normalized) {
    if (grapheme.length === 1) {
      const unit = grapheme.charCodeAt(0)
      if (unit >= 0xd800 && unit <= 0xdfff) {
        throw new CanonicalizationError(
          'LONE_SURROGATE',
          `string contains an unpaired UTF-16 surrogate U+${unit.toString(16).toUpperCase()}, which cannot be encoded as well-formed UTF-8`,
        )
      }
    }
  }
  return normalized
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new CanonicalizationError('NON_FINITE_NUMBER', `number must be finite, got ${String(n)}`)
  }
  if (Object.is(n, -0)) return '0'
  return String(n)
}

const SHORT_ESCAPES: Record<string, string> = {
  '"': '\\"',
  '\\': '\\\\',
  '\b': '\\b',
  '\f': '\\f',
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
}

function serializeString(s: string): string {
  let out = '"'
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!
    const shortEscape = SHORT_ESCAPES[ch]
    if (shortEscape !== undefined) {
      out += shortEscape
      continue
    }
    const unit = s.charCodeAt(i)
    if (unit < 0x20) {
      out += '\\u' + unit.toString(16).padStart(4, '0')
    } else {
      out += ch
    }
  }
  return out + '"'
}
