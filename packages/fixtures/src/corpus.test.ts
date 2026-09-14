import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { FIXTURE_CORPUS } from './index.ts'
import { isKnownCheckId } from '@mcpcheckup/checks'

let pass = 0, fail = 0
function t(name: string, fn: () => void) {
  try { fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

const VALID_EXECUTION_STATUSES = new Set(['COMPLETED', 'ERROR', 'SKIPPED', 'BLOCKED'])
const VALID_ASSERTION_STATUSES = new Set(['VERIFIED', 'FAILED', 'OBSERVED_RISK', 'UNVERIFIED'])

/** PRD §5.4 的数量下限。抽成常量而不是散在两个 assert 的字面量里，是因为
 *  README 的 "N required" 现在由文件末尾那条守卫直接对着它们比——同一个数字
 *  不能在两处各写各的。 */
const MIN_POSITIVE = 3
const MIN_NEGATIVE = 9

console.log('corpus：数量与结构要求（PRD §5.4）')

t(`至少 ${MIN_POSITIVE} 条正例`, () => {
  const n = FIXTURE_CORPUS.filter((f) => f.kind === 'positive').length
  assert.ok(n >= MIN_POSITIVE, `只有 ${n} 条正例`)
})

t(`至少 ${MIN_NEGATIVE} 条反例`, () => {
  const n = FIXTURE_CORPUS.filter((f) => f.kind === 'negative').length
  assert.ok(n >= MIN_NEGATIVE, `只有 ${n} 条反例`)
})

t('id 全局唯一', () => {
  const ids = FIXTURE_CORPUS.map((f) => f.id)
  assert.equal(new Set(ids).size, ids.length, `重复 id: ${JSON.stringify(ids)}`)
})

t('每条 fixture 都有非空 description 与 guardsAgainst', () => {
  for (const f of FIXTURE_CORPUS) {
    assert.ok(f.description.trim().length > 0, `${f.id} 缺 description`)
    assert.ok(f.guardsAgainst.trim().length > 0, `${f.id} 缺 guardsAgainst`)
  }
})

t('每条 fixture 至少声明一条 expectedAssertions', () => {
  for (const f of FIXTURE_CORPUS) {
    assert.ok(f.expectedAssertions.length > 0, `${f.id} 没有任何 expectedAssertions`)
  }
})

console.log('\ncorpus：check_id 必须与 packages/checks/checks.json 对齐')

t('每条 expectedAssertion 的 check_id 都在 checks.json 里真实存在', () => {
  for (const f of FIXTURE_CORPUS) {
    for (const a of f.expectedAssertions) {
      assert.ok(isKnownCheckId(a.check_id), `${f.id}: 未知 check_id ${JSON.stringify(a.check_id)}`)
    }
  }
})

t('同一 fixture 内不会对同一个 check_id 重复声明两条 assertion', () => {
  for (const f of FIXTURE_CORPUS) {
    const ids = f.expectedAssertions.map((a) => a.check_id)
    assert.equal(new Set(ids).size, ids.length, `${f.id}: 重复 check_id`)
  }
})

console.log('\ncorpus：四态模型硬规则（CLAUDE.md）')

t('execution_status 与 assertion_status 都是合法枚举值——两个独立字段，不是合并出的布尔值', () => {
  for (const f of FIXTURE_CORPUS) {
    for (const a of f.expectedAssertions) {
      assert.ok(VALID_EXECUTION_STATUSES.has(a.execution_status), `${f.id}/${a.check_id}: 非法 execution_status ${a.execution_status}`)
      assert.ok(VALID_ASSERTION_STATUSES.has(a.assertion_status), `${f.id}/${a.check_id}: 非法 assertion_status ${a.assertion_status}`)
    }
  }
})

t('assertion_status = UNVERIFIED 的每一条都必须带非空 reason（三层冗余中的这一层）', () => {
  for (const f of FIXTURE_CORPUS) {
    for (const a of f.expectedAssertions) {
      if (a.assertion_status === 'UNVERIFIED') {
        assert.ok(a.reason, `${f.id}/${a.check_id}: UNVERIFIED 但 reason 缺失`)
        assert.ok('key' in a.reason && a.reason.key, `${f.id}/${a.check_id}: reason 缺少 key 或 key 为空`)
        assert.ok('params' in a.reason, `${f.id}/${a.check_id}: reason 缺少 params`)
      }
    }
  }
})

t('负例反例的关键判定必须覆盖全部四个 assertion_status——不能把所有负例都写成 FAILED（反例：证明这条测试本身有区分力）', () => {
  const statuses = new Set(
    FIXTURE_CORPUS.filter((f) => f.kind === 'negative').flatMap((f) => f.expectedAssertions.map((a) => a.assertion_status)),
  )
  for (const s of ['FAILED', 'OBSERVED_RISK', 'UNVERIFIED'] as const) {
    assert.ok(statuses.has(s), `负例集合里从未出现过 ${s}——四态语义没有被真正用上`)
  }
})

t('超预算的 fixture 里，没跑到的检查必须是 SKIPPED + UNVERIFIED，绝不能是 FAILED（PRD 硬规则）', () => {
  const budgetFixture = FIXTURE_CORPUS.find((f) => f.id === 'response-exceeds-budget')
  assert.ok(budgetFixture, '缺少 response-exceeds-budget fixture')
  // T6.9-F：这条断言换了对象。此前钉的是 reachability=ERROR/UNVERIFIED，而那正是
  // 被修掉的缺陷（握手已经拿到响应，可达性在那一刻就有答案了）。它守的 PRD 硬规则
  // 「超预算绝不是 FAILED」没有变，只是现在落在真正没跑到的那些 check 上。
  const toolsList = budgetFixture!.expectedAssertions.find((a) => a.check_id === 'tools_list')
  assert.ok(toolsList, 'response-exceeds-budget 缺少 tools_list 断言')
  assert.equal(toolsList!.execution_status, 'SKIPPED')
  assert.equal(toolsList!.assertion_status, 'UNVERIFIED')
  assert.equal(toolsList!.reason?.key, 'probe_budget_exhausted_body', '没跑到的检查要说出「为什么没跑」')
  for (const a of budgetFixture!.expectedAssertions) {
    assert.notEqual(a.assertion_status, 'FAILED', `${a.check_id}: 超预算的一轮里不得出现 FAILED`)
  }
  // 反向的另一半：可达性本身在这条 fixture 里必须是已判定的 VERIFIED——把断言搬回
  // try 块末尾（缺陷形态）会让这一行变红。
  const reachability = budgetFixture!.expectedAssertions.find((a) => a.check_id === 'reachability')
  assert.ok(reachability, 'response-exceeds-budget 缺少 reachability 断言')
  assert.equal(reachability!.execution_status, 'COMPLETED')
  assert.equal(reachability!.assertion_status, 'VERIFIED')
})

console.log('\nREADME 的两个数量标题必须机械可验证（本包 README 自己的规则：能机械验证的就不手工核对）')

// ---- round 18：README 的 "### Positive (N required, M provided)" 与
// "### Negative (N required, M provided)" 两行一直是手工维护的，语料早已从
// 3 / 13 长到 12 / 22，却没有任何东西会因此变红。这条守卫把那两行变成派生事实：
// required 对 MIN_POSITIVE / MIN_NEGATIVE，provided 对 FIXTURE_CORPUS 本身。
// 它守的是那两个**数字**，不是表格行数——README 明写那两张表不穷举。 ----

const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8')

/** 从 "### Positive (3 required, 12 provided)" 里取出那两个数字。刻意不用正则：
 *  这一行形状固定，切片比一条要数反斜杠的正则更难写错，而写错正则正是这一轮
 *  在修的那类缺陷。`.trim()` 顺带吃掉 CRLF 检出留下的那个 \r。
 *
 *  三处比它看上去更松的地方，round 18 一并收紧（一条比它看上去更弱的守卫，
 *  正是我们反复栽的那一类）：标题行必须**恰好一条**（`.find()` 只看第一条，
 *  后面再来一条写错数字的会混过去）、括号里必须**恰好两段**（解构只取前两个，
 *  第三段会被无声丢掉）、数字必须是**规范十进制写法**（`Number('03')` 是 3，
 *  `Number(' 3 ')` 也是 3）。 */
function headingCounts(heading: string): { required: number; provided: number } {
  const prefix = `### ${heading} (`
  const matches = README.split('\n').map((l) => l.trim()).filter((l) => l.startsWith(prefix))
  assert.equal(matches.length, 1, `README 里以 ${JSON.stringify(prefix)} 开头的标题行有 ${matches.length} 条，必须恰好一条`)
  const line = matches[0]!
  const inner = line.slice(prefix.length, line.lastIndexOf(')'))
  const parts = inner.split(', ')
  assert.equal(parts.length, 2, `README 标题括号里必须恰好两段，实际 ${parts.length} 段：${line}`)
  const req = parts[0]!
  const prov = parts[1]!
  assert.equal(req.endsWith(' required'), true, `README 标题的第一段不是 "N required"：${line}`)
  assert.equal(prov.endsWith(' provided'), true, `README 标题的第二段不是 "M provided"：${line}`)
  return { required: numeral(req.slice(0, -' required'.length), line), provided: numeral(prov.slice(0, -' provided'.length), line) }
}

/** 只接受规范十进制写法：转回字符串必须与原文逐字相同。 */
function numeral(raw: string, line: string): number {
  const v = Number(raw)
  assert.equal(String(v), raw, `README 标题里的数字 ${JSON.stringify(raw)} 不是规范写法（前导零 / 空格 / 非十进制）：${line}`)
  return v
}

for (const [kind, heading, min] of [['positive', 'Positive', MIN_POSITIVE], ['negative', 'Negative', MIN_NEGATIVE]] as const) {
  t(`README 的 "### ${heading} (N required, M provided)" 与 FIXTURE_CORPUS 一致`, () => {
    const { required, provided } = headingCounts(heading)
    assert.equal(required, min, `README 的 ${heading} required 与 corpus.test.ts 自己断言的下限对不上`)
    const actual = FIXTURE_CORPUS.filter((f) => f.kind === kind).length
    assert.equal(provided, actual, `README 的 ${heading} provided 写着 ${provided}，FIXTURE_CORPUS 实际 ${actual}`)
  })
}

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
