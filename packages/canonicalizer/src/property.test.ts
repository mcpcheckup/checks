import assert from 'node:assert'
import fc from 'fast-check'
import { canonicalize } from './canonicalize.ts'
import { digest } from './digest.ts'
import { CanonicalizationError } from './errors.ts'
import { projectToolset, projectSchemas } from './projections.ts'

// FC_SEED 使随机失败可复现：设置后，本文件里之后每个 fc.assert 都用这个种子
// 而不是一个全新的随机种子，这样这里的一次失败可以用同样的生成输入重跑。
const FC_SEED_RAW = process.env.FC_SEED
if (FC_SEED_RAW !== undefined) {
  const seed = Number(FC_SEED_RAW)
  if (!Number.isSafeInteger(seed) || !/^-?\d+$/.test(FC_SEED_RAW)) {
    throw new Error(`FC_SEED must be a safe integer, got: ${JSON.stringify(FC_SEED_RAW)}`)
  }
  fc.configureGlobal({ seed })
}

// 内部自检，仅供 property-seed.test.ts 以子进程方式调用：验证 FC_SEED 真的传给
// 了 fast-check，而不只是被读取——一个内联的、故意必败的性质，失败报告打到
// stdout 后立即退出，不进入本文件正常的 pass/fail 统计。
if (process.env.FC_SEED_SELFTEST === '1') {
  try {
    fc.assert(fc.property(fc.integer(), () => false))
    console.log('FC_SEED_SELFTEST: property unexpectedly passed')
  } catch (e) {
    console.log('FC_SEED_SELFTEST failure report:\n' + (e as Error).message)
  }
  process.exit(0)
}

let pass = 0, fail = 0
async function t(name: string, fn: () => void | Promise<void>) {
  try { await fn(); pass++; console.log('  ok   ' + name) }
  catch (e) { fail++; console.log('  FAIL ' + name + '\n       ' + (e as Error).stack) }
}

function throwsCode(fn: () => void, code: string) {
  try {
    fn()
  } catch (e) {
    assert.ok(e instanceof CanonicalizationError, `expected CanonicalizationError, got ${(e as Error).constructor.name}`)
    assert.equal((e as CanonicalizationError).code, code)
    return
  }
  assert.fail('expected to throw, did not throw')
}

// 确定性 shuffle：种子来自 fast-check 生成的整数，同一个种子永远给出同一个
// 排列，这样 fast-check 的 shrink（缩小反例）在这个种子维度上也是可复现的。
function seededShuffle<T>(items: T[], seed: number): T[] {
  let state = seed >>> 0 || 1
  function next() {
    state ^= state << 13; state >>>= 0
    state ^= state >>> 17
    state ^= state << 5; state >>>= 0
    return state / 0xffffffff
  }
  const out = items.slice()
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(next() * (i + 1))
    ;[out[i], out[j]] = [out[j]!, out[i]!]
  }
  return out
}

const jsonValueArb = fc.jsonValue({ stringUnit: 'grapheme', maxDepth: 3 })

console.log('property: canonicalize / digest 的通用性质（fast-check）')

await t('对象键顺序打乱 → canonicalize 输出完全相同（属性测试，随机内容与随机排列）', () => {
  fc.assert(
    fc.property(
      fc.dictionary(fc.string({ unit: 'grapheme-composite', minLength: 1, maxLength: 10 }), jsonValueArb, { maxKeys: 8 }),
      fc.integer(),
      (obj, seed) => {
        const shuffled = Object.fromEntries(seededShuffle(Object.entries(obj), seed))
        assert.equal(canonicalize(obj), canonicalize(shuffled))
      },
    ),
    { numRuns: 2000 },
  )
})

await t('digest(x) === digest(JSON.parse(canonicalize(x)))（属性测试）', async () => {
  await fc.assert(
    fc.asyncProperty(jsonValueArb, async (value) => {
      const roundTripped = JSON.parse(canonicalize(value))
      assert.equal(await digest(value), await digest(roundTripped))
    }),
    { numRuns: 300 },
  )
})

await t('canonicalize 的输出永远可被 JSON.parse 解析（属性测试）', () => {
  fc.assert(
    fc.property(jsonValueArb, (value) => {
      assert.doesNotThrow(() => JSON.parse(canonicalize(value)))
    }),
    { numRuns: 2000 },
  )
})

await t('NFC 幂等：canonicalize 的输出经 JSON.parse 后再次 canonicalize，结果不变——第二次序列化时字符串已经是 NFC 形式，归一化对它是空操作（属性测试）', () => {
  fc.assert(
    fc.property(jsonValueArb, (value) => {
      const once = canonicalize(value)
      const twice = canonicalize(JSON.parse(once))
      assert.equal(once, twice)
    }),
    { numRuns: 2000 },
  )
})

console.log('\nproperty: 孤立代理（LONE_SURROGATE）——任意上下文、任意位置')

await t('字符串值中任意位置出现孤立代理 → 必抛 LONE_SURROGATE，不论它被包在顶层字符串、数组还是对象里（属性测试）', () => {
  fc.assert(
    fc.property(
      fc.string({ unit: 'grapheme-composite', maxLength: 6 }),
      fc.string({ unit: 'grapheme-composite', maxLength: 6 }),
      fc.integer({ min: 0xd800, max: 0xdfff }),
      jsonValueArb,
      (before, after, surrogateCodeUnit, shell) => {
        const poisoned = before + String.fromCharCode(surrogateCodeUnit) + after
        throwsCode(() => canonicalize(poisoned), 'LONE_SURROGATE')
        throwsCode(() => canonicalize([shell, poisoned]), 'LONE_SURROGATE')
        throwsCode(() => canonicalize({ shell, poisoned }), 'LONE_SURROGATE')
      },
    ),
    { numRuns: 1000 },
  )
})

await t('对象键中任意位置出现孤立代理 → 必抛 LONE_SURROGATE（属性测试）', () => {
  fc.assert(
    fc.property(
      fc.string({ unit: 'grapheme-composite', maxLength: 6 }),
      fc.string({ unit: 'grapheme-composite', maxLength: 6 }),
      fc.integer({ min: 0xd800, max: 0xdfff }),
      (before, after, surrogateCodeUnit) => {
        const poisonedKey = before + String.fromCharCode(surrogateCodeUnit) + after
        const obj: Record<string, number> = { safe: 1 }
        obj[poisonedKey] = 2
        throwsCode(() => canonicalize(obj), 'LONE_SURROGATE')
      },
    ),
    { numRuns: 500 },
  )
})

console.log('\nproperty: 不支持的类型（UNSUPPORTED_TYPE）——任意上下文')

await t('数组或对象中任意位置出现 undefined / 函数 / Symbol → 必抛 UNSUPPORTED_TYPE（属性测试）', () => {
  fc.assert(
    fc.property(
      jsonValueArb,
      jsonValueArb,
      fc.constantFrom<unknown>(undefined, function poison() {}, Symbol('poison')),
      (before, after, bad) => {
        throwsCode(() => canonicalize([before, bad, after]), 'UNSUPPORTED_TYPE')
        throwsCode(() => canonicalize({ before, poison: bad, after }), 'UNSUPPORTED_TYPE')
      },
    ),
    { numRuns: 500 },
  )
})

console.log('\nproperty: projections 的通用性质（fast-check）')

const toolArb = fc.record({
  name: fc.string({ unit: 'grapheme-composite', minLength: 1, maxLength: 12 }),
  inputSchema: jsonValueArb,
})

await t('projectToolset / projectSchemas：工具数组顺序打乱，结果不变（属性测试）', () => {
  fc.assert(
    fc.property(
      fc.array(toolArb, { maxLength: 8 }),
      fc.integer(),
      (tools, seed) => {
        const shuffled = seededShuffle(tools, seed)
        assert.deepEqual(projectToolset(tools), projectToolset(shuffled))
        assert.deepEqual(projectSchemas(tools), projectSchemas(shuffled))
      },
    ),
    { numRuns: 1000 },
  )
})

// allowlist 之外的额外字段（如 description / annotations / _meta）不得混入
// 投影结果——这条直接测「server 新增字段不会产生虚假 drift」，虚假 drift
// 会撞 >3% 误报率的 kill criteria。
const extraFieldsArb = fc.dictionary(
  fc.string({ unit: 'grapheme-composite', minLength: 1, maxLength: 10 }).filter((k) => k !== 'name' && k !== 'inputSchema'),
  jsonValueArb,
  { maxKeys: 5 },
)

await t('projectToolset / projectSchemas：给每个 tool 加一个 allowlist 之外的字段，投影结果不变（属性测试）', () => {
  fc.assert(
    fc.property(
      fc.array(fc.tuple(toolArb, extraFieldsArb), { maxLength: 8 }),
      (pairs) => {
        const tools = pairs.map(([tool]) => tool)
        const withExtraFields = pairs.map(([tool, extra]) => ({ ...tool, ...extra }))
        assert.deepEqual(projectToolset(tools), projectToolset(withExtraFields))
        assert.deepEqual(projectSchemas(tools), projectSchemas(withExtraFields))
      },
    ),
    { numRuns: 1000 },
  )
})

console.log('\nproperty: 重名工具的确定性（显式生成器，覆盖同名场景，不依赖随机采样偶尔撞中）')

// 名字池故意很小：数组长度一旦超过池子大小就必然出现重名，
// 不再像 toolArb（名字几乎唯一）那样只能靠运气偶尔覆盖到这条路径。
const NAME_POOL = ['alpha', 'beta', 'gamma']

const duplicateNameToolArb = fc.array(
  fc.record({
    name: fc.constantFrom(...NAME_POOL),
    inputSchema: jsonValueArb,
  }),
  { minLength: 2, maxLength: 12 },
)

await t('projectSchemas：重名（不同 schema）工具集，wire 顺序打乱后 canonicalize 输出逐字节相同（显式重名生成器）', () => {
  fc.assert(
    fc.property(duplicateNameToolArb, fc.integer(), (tools, seed) => {
      const shuffled = seededShuffle(tools, seed)
      assert.equal(canonicalize(projectSchemas(tools)), canonicalize(projectSchemas(shuffled)))
    }),
    { numRuns: 500 },
  )
})

await t('projectToolset：重名工具集，wire 顺序打乱后输出不变（显式重名生成器）', () => {
  fc.assert(
    fc.property(duplicateNameToolArb, fc.integer(), (tools, seed) => {
      const shuffled = seededShuffle(tools, seed)
      assert.deepEqual(projectToolset(tools), projectToolset(shuffled))
    }),
    { numRuns: 500 },
  )
})

console.log(`\n${pass} passed, ${fail} failed`)
process.exitCode = fail ? 1 : 0
