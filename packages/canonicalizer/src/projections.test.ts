import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { TOOLSET_PROJECTION_VERSION, projectToolset, projectSchemas } from './projections.ts'
import { canonicalize } from './canonicalize.ts'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

console.log('projections')

t('TOOLSET_PROJECTION_VERSION 是个具体版本号', () => {
  assert.equal(TOOLSET_PROJECTION_VERSION, 'v1')
})

t('projectToolset：只取 name，按 name 排序，与输入数组顺序无关', () => {
  const toolsA = [{ name: 'zeta' }, { name: 'alpha' }, { name: 'mid' }]
  const toolsB = [{ name: 'mid' }, { name: 'zeta' }, { name: 'alpha' }]
  const resultA = projectToolset(toolsA)
  const resultB = projectToolset(toolsB)
  assert.deepEqual(resultA, ['alpha', 'mid', 'zeta'])
  assert.deepEqual(resultA, resultB)
})

t('projectToolset：allowlist——description/annotations/_meta 等字段不得混入指纹', () => {
  const tools = [
    { name: 'a', description: 'x', annotations: { readOnlyHint: true }, _meta: { extra: 1 } },
  ]
  const result = projectToolset(tools) as unknown[]
  assert.deepEqual(result, ['a'])
  // 结果里就是纯字符串，没有任何办法让 description/annotations 混进来
  assert.equal(typeof result[0], 'string')
})

t('projectToolset：非数组输入要报错，不能静默返回空结果', () => {
  assert.throws(() => projectToolset(null as unknown as unknown[]))
  assert.throws(() => projectToolset({ tools: [] } as unknown as unknown[]))
})

t('projectToolset：工具缺少字符串 name 要报错，不能静默跳过或排到末尾', () => {
  assert.throws(() => projectToolset([{ name: 'a' }, { description: 'no name' }]))
  assert.throws(() => projectToolset([{ name: 123 }]))
})

t('projectSchemas：取 {name, inputSchema}，按 name 排序，与输入数组顺序无关', () => {
  const toolsA = [
    { name: 'b', inputSchema: { type: 'object' } },
    { name: 'a', inputSchema: { type: 'string' } },
  ]
  const toolsB = [
    { name: 'a', inputSchema: { type: 'string' } },
    { name: 'b', inputSchema: { type: 'object' } },
  ]
  const resultA = projectSchemas(toolsA)
  const resultB = projectSchemas(toolsB)
  assert.deepEqual(resultA, [
    { name: 'a', inputSchema: { type: 'string' } },
    { name: 'b', inputSchema: { type: 'object' } },
  ])
  assert.deepEqual(resultA, resultB)
})

t('projectSchemas：allowlist——description/annotations 不得混入，每个投影对象只有 name 和 inputSchema 两个键', () => {
  const tools = [
    {
      name: 'a',
      description: 'irrelevant to schema fingerprint',
      annotations: { readOnlyHint: true },
      inputSchema: { type: 'object', properties: {} },
    },
  ]
  const result = projectSchemas(tools) as Array<Record<string, unknown>>
  assert.equal(result.length, 1)
  assert.deepEqual(Object.keys(result[0]!).sort(), ['inputSchema', 'name'])
})

t('projectSchemas：缺失的 inputSchema 显式保留为 undefined，不偷偷补成 {} 或 null', () => {
  const result = projectSchemas([{ name: 'a' }]) as Array<Record<string, unknown>>
  assert.equal(result.length, 1)
  assert.ok('inputSchema' in result[0]!)
  assert.equal(result[0]!.inputSchema, undefined)
})

t('projectSchemas：非数组输入要报错', () => {
  assert.throws(() => projectSchemas(undefined as unknown as unknown[]))
})

t('projectSchemas：工具缺少字符串 name 要报错', () => {
  assert.throws(() => projectSchemas([{ inputSchema: {} }]))
})

console.log('\n真实形状的 tools/list 样例（自建，非真实维护者数据）')

const sample = JSON.parse(
  readFileSync(new URL('../test/fixtures/mcp-tools-list.sample.json', import.meta.url), 'utf8'),
)

t('projectToolset(sample.tools) 按 name 字典序排列', () => {
  assert.deepEqual(projectToolset(sample.tools), ['create_note', 'delete_note', 'search_notes'])
})

t('projectSchemas(sample.tools) 按 name 字典序排列，且不含 description/annotations', () => {
  const result = projectSchemas(sample.tools) as Array<Record<string, unknown>>
  assert.deepEqual(
    result.map((r) => r.name),
    ['create_note', 'delete_note', 'search_notes'],
  )
  for (const entry of result) {
    assert.deepEqual(Object.keys(entry).sort(), ['inputSchema', 'name'])
  }
})

t('端到端：把同一份 tools 数组打乱顺序，projectToolset + canonicalize 结果不变', () => {
  const shuffled = [sample.tools[2], sample.tools[0], sample.tools[1]]
  const a = canonicalize(projectToolset(sample.tools))
  const b = canonicalize(projectToolset(shuffled))
  assert.equal(a, b)
})

t('端到端：把同一份 tools 数组打乱顺序，projectSchemas + canonicalize 结果不变', () => {
  const shuffled = [sample.tools[1], sample.tools[2], sample.tools[0]]
  const a = canonicalize(projectSchemas(sample.tools))
  const b = canonicalize(projectSchemas(shuffled))
  assert.equal(a, b)
})

console.log('\n回归测试：projectSchemas 对同名不同 schema 的工具不再随 wire 顺序抖动（T0，M 任务报告里的精确反例）')

t('projectSchemas：两个同名工具（inputSchema 分别是 [] 和 {}），原始顺序与颠倒顺序的 canonicalize 输出逐字节相同', () => {
  const toolA = { name: 'dup', inputSchema: [] }
  const toolB = { name: 'dup', inputSchema: {} }
  const original = [toolA, toolB]
  const reversed = [toolB, toolA]
  const canonicalOriginal = canonicalize(projectSchemas(original))
  const canonicalReversed = canonicalize(projectSchemas(reversed))
  assert.equal(canonicalOriginal, canonicalReversed)
  // 不只是"恰好相等"：两种输入顺序都必须落在同一个具体顺序上
  // （按 inputSchema 的 canonicalize 输出排序，'[]' < '{}'）。
  assert.deepEqual(projectSchemas(original), [toolA, toolB])
  assert.deepEqual(projectSchemas(reversed), [toolA, toolB])
})

t('projectToolset：重名工具，原始顺序与颠倒顺序的输出逐字节相同（重复值排序本身无歧义，锁住这一点）', () => {
  const toolA = { name: 'dup' }
  const toolB = { name: 'dup' }
  const original = [toolA, toolB, { name: 'zeta' }]
  const reversed = [{ name: 'zeta' }, toolB, toolA]
  assert.deepEqual(projectToolset(original), ['dup', 'dup', 'zeta'])
  assert.deepEqual(projectToolset(original), projectToolset(reversed))
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
