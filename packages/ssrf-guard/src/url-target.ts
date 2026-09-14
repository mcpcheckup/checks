import { SsrfBlocked } from './errors.ts'

export interface GuardedTarget {
  url: URL
  /** WHATWG-normalized host. For an IPv6 literal, brackets are stripped and hex/decimal
   *  obfuscation is already collapsed by the platform's own URL parser — see README. */
  hostname: string
  isIpLiteral: boolean
  ipFamily: 4 | 6 | null
}

const IPV4_LITERAL = /^(\d{1,3}\.){3}\d{1,3}$/

/**
 * Validates scheme, credentials, and port on a target URL, and classifies whether its
 * host is an IP literal or a name needing DNS resolution. Does NOT check the IP itself
 * against the private/reserved-range policy — that is classifyIp's job (see ip-policy.ts)
 * and requires DNS resolution for non-literal hosts, which this module doesn't do.
 */
export function parseGuardedTarget(rawUrl: string): GuardedTarget {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    throw new SsrfBlocked('MALFORMED_URL', `not a valid URL: ${JSON.stringify(rawUrl)}`)
  }

  if (url.protocol !== 'https:') {
    throw new SsrfBlocked('NON_HTTPS_SCHEME', `scheme must be https, got ${JSON.stringify(url.protocol)}`)
  }
  if (url.username !== '' || url.password !== '') {
    throw new SsrfBlocked('CREDENTIALS_IN_URL', 'URL must not carry a username or password')
  }
  // .port is '' when the URL used the scheme's default port (443 for https), whether it
  // was written out or omitted. See README "Non-standard ports" for the rule this enforces.
  if (url.port !== '') {
    throw new SsrfBlocked('NON_STANDARD_PORT', `only the default https port is allowed, got ${JSON.stringify(url.port)}`)
  }

  const rawHost = url.hostname
  if (rawHost.startsWith('[') && rawHost.endsWith(']')) {
    const hostname = rawHost.slice(1, -1)
    return { url, hostname, isIpLiteral: true, ipFamily: 6 }
  }
  if (IPV4_LITERAL.test(rawHost)) {
    return { url, hostname: rawHost, isIpLiteral: true, ipFamily: 4 }
  }
  return { url, hostname: rawHost, isIpLiteral: false, ipFamily: null }
}
