import assert from 'node:assert'
import { readdirSync, readFileSync } from 'node:fs'
import { canonicalize } from './canonicalize.ts'
import { digest } from './digest.ts'
import { projectToolset, projectSchemas } from './projections.ts'

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('projection-v1 test vectors (PROJECTION-v1.md ↔ real + synthetic tools/list captures)')

const VECTORS_DIR = new URL('../test/vectors/projection-v1/', import.meta.url)

interface Vector {
  description: string
  source: 'real' | 'synthetic'
  endpoint: string
  input: { tools: unknown[] }
  jcs: string
  toolset_fingerprint: string
  schema_fingerprint: string
}

// Deny-by-default (guard principle 4, applied to this directory too): the
// file list below must be EXACTLY the set of files actually on disk under
// test/vectors/projection-v1/. A vector file added without also being added
// here is a vector nothing ever recomputes or checks — worse than no vector
// at all, since it would look tested without being tested. Conversely, a
// name listed here that no longer exists on disk is caught the same way.
const EXPECTED_VECTOR_FILES = [
  'real-mcpcheckup-mcp.json',
  'synthetic-unordered-keys-and-tools.json',
  'synthetic-unicode-and-escapes.json',
  'synthetic-nested-schema-ref-anyof.json',
]

await t('deny-by-default: every file on disk under test/vectors/projection-v1/ is in EXPECTED_VECTOR_FILES, and vice versa', () => {
  const actual = readdirSync(VECTORS_DIR).filter((f) => f.endsWith('.json')).sort()
  const expected = [...EXPECTED_VECTOR_FILES].sort()
  assert.deepEqual(
    actual,
    expected,
    `directory listing and EXPECTED_VECTOR_FILES have drifted — every vector file must be registered ` +
      `here (and every registered name must exist on disk), or an added-but-unregistered vector would ` +
      `silently never be recomputed or checked.\n  on disk: ${JSON.stringify(actual)}\n  expected: ${JSON.stringify(expected)}`,
  )
})

for (const file of EXPECTED_VECTOR_FILES) {
  const vector = JSON.parse(readFileSync(new URL(file, VECTORS_DIR), 'utf8')) as Vector

  await t(`${file}: recomputed jcs matches the stored value`, () => {
    const recomputed = canonicalize(vector.input)
    assert.equal(recomputed, vector.jcs, `canonicalize(input) drifted from the stored "jcs" field for ${file}`)
  })

  await t(`${file}: recomputed toolset_fingerprint matches the stored value`, async () => {
    const recomputed = await digest(projectToolset(vector.input.tools))
    assert.equal(recomputed, vector.toolset_fingerprint, `toolset_fingerprint drifted for ${file}`)
  })

  await t(`${file}: recomputed schema_fingerprint matches the stored value`, async () => {
    const recomputed = await digest(projectSchemas(vector.input.tools))
    assert.equal(recomputed, vector.schema_fingerprint, `schema_fingerprint drifted for ${file}`)
  })
}

await t('real-mcpcheckup-mcp.json is actually marked source: "real" and carries a fetched_utc timestamp', () => {
  const vector = JSON.parse(readFileSync(new URL('real-mcpcheckup-mcp.json', VECTORS_DIR), 'utf8')) as Vector & { fetched_utc?: string }
  assert.equal(vector.source, 'real')
  assert.ok(typeof vector.fetched_utc === 'string' && vector.fetched_utc.length > 0, 'expected a recorded fetch time')
})

await t('every synthetic vector is actually marked source: "synthetic" and uses only example.com/invented endpoints', () => {
  for (const file of EXPECTED_VECTOR_FILES) {
    if (file === 'real-mcpcheckup-mcp.json') continue
    const vector = JSON.parse(readFileSync(new URL(file, VECTORS_DIR), 'utf8')) as Vector
    assert.equal(vector.source, 'synthetic', `${file} must be marked synthetic`)
    assert.ok(vector.endpoint.startsWith('https://example.com/'), `${file}'s endpoint must be example.com, got ${vector.endpoint}`)
  }
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
