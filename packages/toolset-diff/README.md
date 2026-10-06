# @mcpcheckup/toolset-diff

A deterministic per-tool comparison of two MCP tool lists: which tools were added, which were removed, and which kept their name but changed their description or their input schema.

It is a pure function. It does no I/O, reads no clock, uses no randomness, and does not modify its arguments. The same two inputs always give the same output, whatever order the tools were listed in.

Its only dependency is `@mcpcheckup/canonicalizer`; it uses `canonicalize` (`nfc-jcs/v1`) as its definition of "the same".

## API

```ts
import { diffToolsets } from '@mcpcheckup/toolset-diff'

interface ToolItem {
  name: string
  description: string | null
  inputSchema: unknown // undefined is read as null
  unstorable?: readonly string[] // fields that could not be stored for this tool
}
interface ToolsetSide {
  items: readonly ToolItem[]
  toolCount: number // how many tools the list had when it was observed
}

diffToolsets(before: ToolsetSide, after: ToolsetSide): ToolsetDiff
```

The result is one of three shapes.

```ts
{ kind: 'unchanged' }

{
  kind: 'changed'
  added: string[]
  removed: string[]
  descriptionChanged: { name: string; before: string | null; after: string | null }[]
  schemaChanged: { name: string }[]
}

{ kind: 'unitemizable'; reason: UnitemizableReason; side: 'before' | 'after' | 'both' }
```

`changed` is only returned when at least one of its four lists is not empty. If all four are empty, for example because the two lists differ only in order, the result is `unchanged`.

## What counts as a difference

- **Matching.** Tools are matched across the two sides by `canonicalize(name)`, so two names that differ only in Unicode normalization (NFC) are the same tool. A renamed tool is reported as one removal and one addition; no rename is ever guessed.
- **Description.** Changed when `canonicalize(before.description) !== canonicalize(after.description)`. `null` and the empty string are different. A difference in Unicode normalization alone is not a change. `before` and `after` in the result are the raw strings, exactly as passed in.
- **Input schema.** Changed when `canonicalize(before.inputSchema ?? null) !== canonicalize(after.inputSchema ?? null)`. Only the tool's name is reported, not what changed inside the schema. A tool can appear in both `descriptionChanged` and `schemaChanged`.
- **Names in the result.** `added` and the two changed lists carry the name as it is written in `after`; `removed` carries the name as it is written in `before`.
- **Order.** Every list is sorted by the tool's name in NFC form, in UTF-16 code-unit order (plain `<` on strings). The names in the result are still the raw names. The output does not depend on the order of the input.

## When the lists cannot be compared tool by tool

`unitemizable` means at least one side is not a faithful per-tool record, so a per-tool comparison would be wrong. Exactly one reason is reported. The reasons are checked in this order, and the first one that holds on either side wins. `side` says on which side or sides that reason holds.

| Reason | Holds on a side when |
| --- | --- |
| `DUPLICATE_NAME` | two of its tools have the same `canonicalize(name)` |
| `UNSTORABLE_FIELDS` | any of its tools has a non-empty `unstorable` |
| `ITEM_COUNT_MISMATCH` | `items.length !== toolCount` |
| `NOT_CANONICALIZABLE` | `canonicalize` throws on any tool's name, description or input schema (for example a number such as `1e400` that is not finite), or a description is neither a string nor `null` |

`UNITEMIZABLE_REASONS` exports the four reasons, frozen, in this order.

## Errors

Problems in the data never throw: they come back as `unitemizable`. A wrongly shaped argument is a programming error and throws a `TypeError`: a side that is not `{ items: array, toolCount: number }`, an item that is not an object with a string `name`, or an `unstorable` that is present but not an array.

## What it does not do

It does not decide whether a difference matters, and it does not order differences by importance, count them or summarize them. It does not describe how a schema changed. It does not read, store or send anything.
