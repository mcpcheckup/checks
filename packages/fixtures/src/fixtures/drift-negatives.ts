import type { Fixture } from '../types.ts'
import { jsonRpcResult } from '../helpers.ts'
import { CLEAN_TOOLS, createModernHandler, modernSampleRun, cleanBaselineAssertions, withOverride } from './shared.ts'

const TOOL_MISSING_SCHEMA = { name: 'archive_note', description: 'Archive a note by id, hiding it from the default note list.' }
const TOOLS_MISSING_ONE_SCHEMA = [...CLEAN_TOOLS, TOOL_MISSING_SCHEMA]

export const crossLayerHashMismatch: Fixture = {
  id: 'cross-layer-hash-mismatch',
  description:
    '一个 modern 实现，tools/list 结构本身合法（3 个工具都有 name+description），' +
    '但其中一个工具完全没有 inputSchema 字段——不是 null，是键本身不存在。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    'PRD 点名的四类之一：cross-layer hash mismatch（本条为推断——原始 PRD 文本未在本次任务上下文中可读，' +
    '这是按字面「跨层」最贴近的理解构造的：toolset 层（只需要 name）与 schema 层（需要 inputSchema）是' +
    'checks.json 里两个独立的 check，如判断有误请指正）。' +
    '这条 fixture 证明 toolset_fingerprint 与 schema_fingerprint 真的是互相独立的判定——' +
    'toolset 层用 projectToolset（只取 name）算得出，FAILED 之外的结果，而 schema 层用 projectSchemas（取 name+inputSchema）' +
    '会在 canonicalize() 遇到 undefined 属性值时抛 UNSUPPORTED_TYPE 而算不出。fingerprint-consistency.test.ts 用真实的' +
    '@mcpcheckup/canonicalizer 投影函数验证了这一点，不是手写断言猜的。tools_list 本身仍然 VERIFIED——' +
    '它只要求"合法的工具对象数组"，不要求每个工具都有可计算指纹的 schema，这是两条 check 故意划开的边界。',
  tools: TOOLS_MISSING_ONE_SCHEMA,
  createHandler: () =>
    createModernHandler(TOOLS_MISSING_ONE_SCHEMA, {
      toolsListResponse: (id) =>
        jsonRpcResult(id, { resultType: 'complete', ttlMs: 60_000, cacheScope: 'public', tools: TOOLS_MISSING_ONE_SCHEMA }),
    }),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: withOverride(cleanBaselineAssertions(), {
    check_id: 'schema_fingerprint',
    execution_status: 'COMPLETED',
    assertion_status: 'FAILED',
  }),
}

const DRIFT_TOOLS_V1 = CLEAN_TOOLS
const DRIFT_TOOLS_V2 = [...CLEAN_TOOLS, { name: 'archive_note', description: 'Archive a note by id.', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false } }]

export const toolsetDriftRun1: Fixture = {
  id: 'toolset-drift-run-1',
  description: '与 toolset-drift-run-2 成对：同一个（未认领）target 在"批准基线之前"的监控路径下，第一次观测到的工具集。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst:
    'CLAUDE.md 判定语义硬规则：监控路径（无已批准基线）下指纹变化 → 产出 drift_event，assertion_status 仍是 VERIFIED；' +
    '只有存在已批准基线时，偏离才能是 FAILED。这条与 toolset-drift-run-2 成对存在——drift_event 是跨两次 run 的' +
    '产品概念，不是 checks.json 里的某个 check_id，所以它不出现在任何一个单独 fixture 的 expectedAssertions 里；' +
    '它由 drift-pair.test.ts 通过真实对比这两个 fixture 的 toolset_fingerprint 来验证："两次观测的指纹确实不同" + ' +
    '"两次观测各自的 toolset_unchanged_vs_approved 依然是 UNVERIFIED（无基线，与是否变化无关）"，而不是被误判为 FAILED。',
  tools: DRIFT_TOOLS_V1,
  createHandler: () => createModernHandler(DRIFT_TOOLS_V1),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}

export const toolsetDriftRun2: Fixture = {
  id: 'toolset-drift-run-2',
  description: '与 toolset-drift-run-1 成对：同一个 target 后续观测到的工具集，新增了一个工具（archive_note）。',
  protocolRevision: '2026-07-28',
  kind: 'negative',
  guardsAgainst: '见 toolset-drift-run-1——两者成对存在，共同证明"无基线时的变化"不等于"有基线时的偏离"。',
  tools: DRIFT_TOOLS_V2,
  createHandler: () => createModernHandler(DRIFT_TOOLS_V2),
  sampleRun: (handler) => modernSampleRun(handler),
  expectedAssertions: cleanBaselineAssertions(),
}
