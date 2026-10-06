// This package may depend on exactly one other workspace package, @mcpcheckup/canonicalizer.
// The check reads package.json and every source file in this package, so it turns red the moment
// a second workspace package is declared or imported.
import assert from 'node:assert'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const ALLOWED = '@mcpcheckup/canonicalizer'
const pkgDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const srcDir = join(pkgDir, 'src')
const SELF = 'dependency-guard.test.ts'

/** Every module specifier a source text imports, re-exports, dynamically imports or requires. */
function specifiersOf(source: string): string[] {
  const out: string[] = []
  const patterns = [
    /\b(?:import|export)\b[^'"`;]*?\bfrom\s*(['"])([^'"]+)\1/g, // import x from '..' / export * from '..'
    /\bimport\s*(['"])([^'"]+)\1/g, // import '..'
    /\b(?:import|require)\s*\(\s*(['"])([^'"]+)\1\s*\)/g, // import('..') / require('..')
  ]
  for (const re of patterns) for (const m of source.matchAll(re)) out.push(m[2] as string)
  return out
}

/** Why `specifier`, written in the file at `fromFile`, is not allowed; null when it is. */
function problemWith(specifier: string, fromFile: string): string | null {
  if (specifier.startsWith('node:')) return null
  if (specifier === ALLOWED) return null
  if (specifier.startsWith('.')) {
    const target = resolve(dirname(fromFile), specifier)
    return relative(pkgDir, target).startsWith('..') ? 'a relative path leaving this package' : null
  }
  return 'a package other than ' + ALLOWED
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sourceFiles(join(dir, e.name)) : /\.(ts|mts|cts|js|mjs|cjs)$/.test(e.name) ? [join(dir, e.name)] : [])
}

const manifest = () => JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8')) as Record<string, Record<string, string> | undefined>

console.log('dependency guard: only the canonicalizer')

t('package.json: dependencies are exactly { @mcpcheckup/canonicalizer }', () => {
  assert.deepStrictEqual(Object.keys(manifest().dependencies ?? {}), [ALLOWED])
})

t('package.json: no other dependency field lists a workspace package', () => {
  for (const field of ['devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const names = Object.keys(manifest()[field] ?? {}).filter((n) => n.startsWith('@mcpcheckup/'))
    assert.deepStrictEqual(names, [], `${field} must not list a workspace package`)
  }
})

t('src/: every import, re-export and require points at a node: built-in, the canonicalizer, or a path inside this package', () => {
  const files = sourceFiles(srcDir).filter((f) => !f.endsWith(SELF))
  assert.ok(files.length >= 2, 'expected to find the package sources')
  const offenders: string[] = []
  for (const file of files) {
    for (const spec of specifiersOf(readFileSync(file, 'utf8'))) {
      const why = problemWith(spec, file)
      if (why !== null) offenders.push(`${relative(pkgDir, file)}: '${spec}' is ${why}`)
    }
  }
  assert.deepStrictEqual(offenders, [])
})

t('the scanner itself: it reads every import form and refuses the checks and scheduling packages and paths leaving the package', () => {
  const sample = [
    "import { a } from '@mcpcheckup/checks'",
    "export * from '@mcpcheckup/scheduling'",
    'import type { B } from "@mcpcheckup/canonicalizer"',
    "import '@mcpcheckup/ssrf-guard'",
    "const x = await import('../../checks/src/index.ts')",
    "const y = require('@mcpcheckup/attestation-schema')",
    "import { z } from 'node:fs'",
    "import { w } from './diff.ts'",
  ].join('\n')
  const specs = specifiersOf(sample)
  assert.strictEqual(specs.length, 8)
  const file = join(srcDir, 'x.ts')
  const refused = specs.filter((s) => problemWith(s, file) !== null).sort()
  assert.deepStrictEqual(refused, [
    '../../checks/src/index.ts', '@mcpcheckup/attestation-schema', '@mcpcheckup/checks', '@mcpcheckup/scheduling', '@mcpcheckup/ssrf-guard',
  ])
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
