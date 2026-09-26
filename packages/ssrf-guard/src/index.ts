export { guardedFetch } from './guarded-fetch.ts'
export type { GuardedFetchOptions, GuardedFetchResult } from './guarded-fetch.ts'

export { DEFAULT_PROBE_BUDGET, createProbeBudget } from './budget.ts'
export type { ProbeBudget } from './budget.ts'

export { assertRateLimitAllowed } from './rate-limit.ts'
export type { RateLimitDecision, RateLimitScope } from './rate-limit.ts'

export type { ProbeAuditRecord, ProbeHopRecord, ProbeOutcome } from './audit.ts'

export type { SafeResponseHandle } from './response-view.ts'

export { resolveHost, resolveAndValidateHost, resolveTxt, validateAddresses, DOH_ENDPOINT } from './resolve.ts'
export type { ResolvedAddress, DnsDeps } from './resolve.ts'

export { classifyIp, classifyIpv4, classifyIpv6 } from './ip-policy.ts'
export type { IpVerdict, IpBlockCode } from './ip-policy.ts'

export { parseGuardedTarget } from './url-target.ts'
export type { GuardedTarget } from './url-target.ts'

export { SsrfGuardError, SsrfBlocked, BudgetExceeded, RateLimited, UpstreamFetchFailed } from './errors.ts'
export const MAX_ENDPOINT_URL_LENGTH = 2048
