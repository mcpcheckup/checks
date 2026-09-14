import { canonicalize } from './canonicalize.ts'

/**
 * 指纹不对整个 tools/list 响应算——server 会随版本增加字段（annotations、_meta 等），
 * 那样会产生大量虚假 drift。这里显式用 allowlist 挑字段，而不是"排除某些字段"，
 * 这样 server 新增字段时不会自动混进指纹。
 *
 * 保持 v1 不升：这个投影从未在任何已发布的 attestation 里生效过（下面的排序修复
 * 是这版代码第一次、也是唯一一次能"原地"改正的窗口）。若你在读这段注释时已经
 * 有 attestation 引用过 v1，这个前提就不成立了，必须把常量改成 'v2'。
 */
export const TOOLSET_PROJECTION_VERSION = 'v1'

function assertToolArray(tools: unknown): asserts tools is unknown[] {
  if (!Array.isArray(tools)) {
    throw new TypeError('expected an array of tool objects')
  }
}

function requireToolName(tool: unknown, index: number): string {
  if (
    typeof tool !== 'object' ||
    tool === null ||
    !('name' in tool) ||
    typeof (tool as { name: unknown }).name !== 'string'
  ) {
    throw new TypeError(`tool at index ${index} is missing a string "name"`)
  }
  return (tool as { name: string }).name
}

/** 用于 toolset_fingerprint：每个 tool 的 name，按 name 排序后的数组。 */
export function projectToolset(tools: unknown[]): unknown {
  assertToolArray(tools)
  const names = tools.map((tool, i) => requireToolName(tool, i))
  return names.sort()
}

/**
 * 用于 schema_fingerprint：{name, inputSchema} 对，按 name 排序。
 *
 * 同名不同 schema 的工具需要一个确定性的次级排序键，否则平局只能靠
 * `Array.prototype.sort` 的稳定排序保留输入顺序——而输入顺序就是 wire 顺序，
 * 于是同一个工具集会因为 server 返回顺序不同而算出不同的 schema_fingerprint。
 * 次级键用 `canonicalize(inputSchema)` 的字符串比较：同步、不需要 crypto、
 * 对相同内容永远给出相同结果，与 wire 顺序无关。
 *
 * `inputSchema === undefined` 时不对它调用 canonicalize（会抛
 * UNSUPPORTED_TYPE）——用固定哨兵值代替，缺失的 inputSchema 仍按现有约定原样
 * 保留在投影结果里，留到 digest 阶段才失败（见 computeSchemaFingerprint）。
 */
export function projectSchemas(tools: unknown[]): unknown {
  assertToolArray(tools)
  const pairs = tools.map((tool, i) => {
    const name = requireToolName(tool, i)
    const inputSchema = (tool as { inputSchema?: unknown }).inputSchema
    const sortKey = inputSchema === undefined ? '' : canonicalize(inputSchema)
    return { name, inputSchema, sortKey }
  })
  pairs.sort((a, b) => {
    if (a.name !== b.name) return a.name < b.name ? -1 : 1
    return a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0
  })
  return pairs.map(({ name, inputSchema }) => ({ name, inputSchema }))
}
