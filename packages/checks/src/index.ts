export { runHygieneCheck, checkTool } from './hygiene.ts'
export type { HygieneHit, HygieneFlag, HygieneResult } from './hygiene.ts'

export { CHECKS_REGISTRY, getCheckIds, isKnownCheckId, getCheckDefinition } from './registry.ts'
export type { ChecksRegistry, CheckDefinition } from './registry.ts'

export { runProbe } from './probe.ts'
export type {
  ProbeInput,
  ProbeResult,
  ProbeTarget,
  RemoteProbeTarget,
  StdioProbeTarget,
  ApprovedBaseline,
  ToolSnapshot,
  ToolSnapshotEntry,
  DriftEvent,
  EvidenceProvenance,
  FetchLike,
  FetchCallOptions,
  ProbeBudget,
} from './types.ts'
