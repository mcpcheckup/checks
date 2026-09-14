# @mcpcheckup/ssrf-guard

The one line of defense between an unauthenticated visitor on the MCP Checkup home page
("try it now" — no login) and this service making an HTTP request to a URL of their
choosing. That is the single largest abuse surface in the product. This document is
written for the audience most likely to read it seriously: a security researcher
deciding whether to trust it, or trying to break it. It says what is tested, what is
not, and why — the same discipline this project applies to product claims (see
`CLAUDE.md`'s `UNVERIFIED` rule). It is not a claim that this package is "secure."

## Threat model, briefly

Cloudflare Workers is not a VM: there is no instance metadata service to steal
credentials from by rebinding into a private address, the way classic cloud-SSRF
writeups go. So the prize an attacker gets from making this service fetch an arbitrary
URL is not credential theft. It is:

- **Using MCP Checkup as a proxy or amplifier** against a third party — hiding the
  attacker's own IP, or fanning a small request out into a larger one.
- **Reaching a service that allowlists Cloudflare's own IP ranges**, trusting that
  traffic from Cloudflare is traffic from *this* product specifically.

Neither of those is stopped by IP-range validation alone. That is why this package is
more than an IP blocklist — see "Beyond IP validation" below.

## What is closed

Every one of these has a dedicated test with the specific input that must be rejected,
not just a general assertion that "bad things are blocked":

- **Scheme**: only `https://`. `http://`, `file://`, `ftp://`, `data:`, `blob:`,
  `gopher://` all rejected.
- **Credentials in the URL** (`https://user:pass@host/`) rejected. <!-- scan-secrets-allow: illustrative placeholder, not a real host -->
- **Non-standard ports** rejected — see "Non-standard ports" below for why this is
  stricter than it has to be.
- **Private, reserved, and special-purpose IPv4 ranges**: `0.0.0.0/8`, `10.0.0.0/8`,
  `100.64.0.0/10` (carrier-grade NAT), `127.0.0.0/8`, `169.254.0.0/16`,
  `172.16.0.0/12`, `192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`,
  `224.0.0.0/4`, `240.0.0.0/4`.
- **Cloud instance metadata addresses** specifically: `169.254.169.254` (AWS/GCP/Azure)
  and `fd00:ec2::254` (AWS IMDSv2 over IPv6) get their own dedicated block reason and
  test, even though both already fall inside a broader blocked range — so the reason a
  request was rejected is legible, not just "link-local."
- **IPv6**: `::1`, `::`, `fc00::/7` (unique local), `fe80::/10` (link-local).
- **IPv4-mapped IPv6** (`::ffff:0:0/96`): the embedded IPv4 address is extracted and
  re-checked against the IPv4 policy — `::ffff:127.0.0.1` is rejected as loopback,
  `::ffff:8.8.8.8` is allowed, proving this is a real unwrap-and-recheck and not a
  blanket accept or reject of the whole prefix.
- **Obfuscated IP-literal forms** (`http://0x7f000001/`, `http://017700000001/`, <!-- scan-secrets-allow: obfuscated-loopback examples, not real hosts -->
  `http://127.1/`): these are never a special case in our own code. `new URL(...)` <!-- scan-secrets-allow: obfuscated-loopback example, not a real host -->
  (the WHATWG URL parser, the same one Node and Workers both implement) normalizes all
  of them into canonical form before we ever see `.hostname` — verified empirically,
  not assumed; see "Why we trust `new URL().hostname`" below.
- **A multi-homed hostname where only one resolved address is bad**: rejected
  entirely. We do not take "at least one address is public" as good enough.
- **Every redirect hop re-resolves and re-validates independently** — following
  `redirect: 'manual'` ourselves rather than letting `fetch()` auto-follow. The
  motivating attack — hop 1 a legitimate public domain, hop 2's `Location` pointing at
  a hostname that resolves to `169.254.169.254` — is a dedicated test. It asserts not
  just that the whole call is rejected, but that hop 2's `fetch()` is *never issued* —
  the block happens during hop 2's pre-flight resolution, before any request reaches
  it.
- **Relative `Location` headers** are resolved against the current hop's URL, not the
  original URL.

## What is **not** closed

After we validate a hostname's resolved addresses ourselves, the actual request still
goes through Cloudflare's `fetch()`, which re-resolves that hostname internally at
connect time — using Cloudflare's own resolution, which we cannot see or pin for a
non-zone host. If an attacker's authoritative nameserver returns one address to *our*
validation query and a different one moments later to Cloudflare's *own* resolution of
the same hostname, our check passes and the real connection can still go to the second
answer. This is a DNS-rebinding race that exists in the gap between "we checked" and
"Cloudflare connected."

We looked for a way to close this and could not find one on Workers today:

- `fetch()`'s `cf.resolveOverride` option can pin a request to a specific resolved IP —
  but per Cloudflare's own documentation, it "will only take effect if both the URL
  host and the host specified by `resolveOverride` are within your zone... if either
  specifies a host from a different zone/domain, then the option will be ignored for
  security reasons." MCP servers are arbitrary third-party domains, never our own zone,
  so this is unusable here.
- `connect()` (raw TCP sockets) does reject connections to private/reserved/
  Cloudflare-internal addresses at the point of connection — but Cloudflare's own
  troubleshooting docs say plainly: "If you need to connect to addresses on port 80 or
  443 to make HTTP requests, use `fetch`." Building our own TLS/HTTP framing on top of
  `connect()` to work around this would trade a narrow, well-understood gap for a much
  larger one — a hand-rolled TLS-adjacent stack talking to arbitrary untrusted hosts —
  and we would have no way to test whether `connect()`'s own undocumented blocklist
  covers everything we require (CGNAT, the IPv6 metadata ULA, IPv4-mapped addresses).
  We are not willing to build tested guarantees on top of untested, undocumented
  platform behavior.

If Cloudflare Workers ever exposes a way to pin `fetch()` to a pre-validated IP for an
arbitrary (non-zone) host, this package should adopt it and this section should shrink.
Until then: this package narrows the window and detects when it's been hit (see
"Detecting a DNS answer that changed mid-probe" below); it does not claim to close it.

If this gap matters for your deployment, the real fix lives one layer down, in
infrastructure, not in this package: Cloudflare Workers VPC's **Gateway egress**
binding routes a Worker's `fetch()`/`connect()` traffic through Cloudflare Gateway with
DNS/HTTP/Network policy enforcement at the network layer, independent of this or any
other JavaScript running in the Worker. That is deployment configuration — out of
scope for this package per `CLAUDE.md`'s boundary rule (`packages/` ships the policy
*implementation*; deployment thresholds and infrastructure are private) — but worth
knowing about if you're deciding how much to trust the userland check alone.

## Beyond IP validation

IP-range checking only addresses "is this address on our blocklist." It does nothing
about the two real risks described in "Threat model" above. Four things in this
package exist specifically for those, not for the rebinding gap:

### 1. Callers never get a raw response — this is deliberately blind SSRF

`guardedFetch` does not return a `Response`, and does not expose the target's raw body
or headers as a standalone value. Instead the caller supplies a `parseResponse`
function up front; it receives a [`SafeResponseHandle`](./src/response-view.ts) —
`status`, `headers` (needed for real protocol checks, e.g. reading an MCP protocol
version header — not restricted), and `.text()`/`.json()`/`.bytes()`/`.arrayBuffer()`
methods that read the body under the `maxBodyBytes` budget. The only thing that leaves
`guardedFetch` is whatever that function computes and returns as structured data.

This does not, and cannot, stop a caller from writing `parseResponse: (h) => h.text()`
and echoing the raw body anyway — real assertions need real body access, so nothing
can force that door shut. What it does is make doing so a **deliberate, visible line in
the code you write**, not the path of least resistance the way "just call `.text()` on
whatever `fetch()` handed you" would be. If MCP Checkup's report pages ever show raw
target output verbatim, that should be traceable to one specific parser function, not
an accident of API design. Error messages follow the same rule — nothing this package
throws ever includes bytes the target sent us; see the code comments on `SsrfBlocked`
and the `maxBodyBytes` rejection in `response-view.ts` for where that's enforced.

### 2. Detecting a DNS answer that changed mid-probe

After every `fetch()` we make — each redirect hop and the final one — we re-resolve
that hop's hostname via DoH again and compare the address set to what we validated
before fetching. A mismatch does not, and cannot, stop the connection that already
happened (see "What is not closed"). What it does is turn a rebind into **evidence**:
`GuardedFetchResult.dnsAnswerChangedDuringProbe` is set to `true`, and the audit record
carries the same flag. This product's entire value proposition is publishing evidence
about what was actually observed (`CLAUDE.md`) — a run whose own DNS answer changed
mid-flight is not evidence anyone should be able to trust, so **the caller must treat
`dnsAnswerChangedDuringProbe: true` as disqualifying that run from the publish
pipeline**, and should record the affected assertion as `OBSERVED_RISK` with a reason
like "DNS answer changed during probe" rather than publishing it as a normal result.
This package surfaces the signal; enforcing "don't publish" is the caller's
responsibility, since publishing is decided several layers upstream of this package.

### 3. Rate limiting, not IP validation, is the real defense against abuse

Neither "using this as a proxy against a third party" nor "hitting something that
allowlists Cloudflare's ranges" is stopped by checking the target's IP — the target can
be a perfectly legitimate public address and the abuse still happens, just repeated.
The actual defense is bounding how often this can be triggered, on at least three axes
(`RateLimitScope`): per caller IP, per target host, and global concurrency. This
package does not implement any of them — thresholds, storage (Durable Objects, KV,
whatever), and the actual limiting logic are deployment configuration, same boundary
as everywhere else in this product. What it does define is the **shape of the gate**:
`guardedFetch` requires a [`RateLimitDecision`](./src/rate-limit.ts) — already computed
by the caller — as an explicit argument, and it is checked *before anything else*,
including before any DNS lookup. Passing `undefined`, `null`, or a malformed decision
is treated the same as an explicit denial: the default is **deny**, not allow. There is
no path through this code where "the caller forgot to rate-limit" quietly becomes
"request allowed."

### 4. Every unauthenticated probe leaves an audit trail

The home page's instant-try is the one unauthenticated fan-out point in the entire
product. `guardedFetch` accepts an `onAudit` callback and calls it exactly once per
call — on success *and* on every rejection (blocked target, budget exceeded, rate
limited, network failure) — with a [`ProbeAuditRecord`](./src/audit.ts): when, who
(`callerIdentifier`, defined and supplied by the caller — an IP hash, a session id,
whatever your deployment uses), what host, every hop's resolved addresses, how many
hops, the outcome, and the DNS-rebind flag. This package only defines the shape and
guarantees delivery regardless of how the call ends; persisting it is the caller's job.

## Non-standard ports

`ProbeBudget` has no port configuration — this is a fixed rule, not a per-call option:
only the default HTTPS port (443, whether written explicitly or omitted) is allowed.
Any other explicit port is rejected outright.

This is stricter than strictly necessary and that's deliberate. Requiring HTTPS
already rules out the classic "SSRF via crafted HTTP body to a plaintext service on an
unusual port" class of attack (Redis, Memcached, SMTP command injection via a
carefully-shaped request body) structurally — a service that doesn't terminate valid
TLS for the hostname we're requesting simply fails the handshake, and `fetch()` never
sends the request payload at all. So the residual risk from allowing non-standard
*HTTPS* ports is narrower: mostly internal HTTPS services (admin panels, dev tooling)
that happen to be reachable and happen to present a certificate our HTTPS client
accepts. Real remote MCP servers overwhelmingly run on 443. There is no legitimate
target we know of that needs a non-standard port, and a hand-maintained denylist of
"dangerous" ports is inherently incomplete in a way a single-port allowlist is not — so
we picked the tightest defensible default rather than trying to enumerate the ports
worth worrying about. If a real deployment needs an exception, that belongs in a
per-target allowlist at the deployment-config layer, not as a general relaxation here.

## Why wireformat, not Cloudflare's DoH JSON API

DNS resolution uses hand-rolled [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) DoH
wireformat (`src/dns-wire.ts`), not Cloudflare's `application/dns-json` API, even
though the JSON API is simpler to parse. Cloudflare's own documentation says of it:
"The DoH JSON format has no formal RFC and its schema is not guaranteed to be stable.
If you need a stable format, use the DoH wireformat instead." This is the single most
security-critical resolution path in the product; we are not willing to build it on a
format its own vendor calls unstable, especially given that vendor is actively
mid-rollout on a breaking change to that format's schema as of this writing. Wireformat
costs us a small hand-written DNS message encoder/decoder — encoding one question,
decoding A/AAAA answers, correctly walking compression pointers to skip past record
types we don't care about (tested: a `CNAME` record followed by an `A` record decodes
the `A` correctly, proving we skip by `RDLENGTH` rather than guessing) — but it's RFC
8484, not a format that can change under us without notice.

Every decode path fails closed: malformed bytes, a truncated message, an `RDLENGTH`
that runs past the buffer, or a record whose `RDLENGTH` doesn't match its declared type
(an `A` record must be exactly 4 bytes) all throw rather than returning a best-effort
guess. A non-`NOERROR` RCODE (including `NXDOMAIN`) and a hostname with zero `A`/`AAAA`
answers are both treated as resolution failure, not as "no addresses, so nothing to
validate, so allow it."

## Why the resolver is hardcoded, not configurable

DNS resolution always goes to Cloudflare's own resolver
(`https://cloudflare-dns.com/dns-query`) and this is not a parameter — there is no way <!-- scan-secrets-allow: real Cloudflare DoH endpoint, this package's fixed resolver -->
to point `guardedFetch` at a different resolver. We already fully trust Cloudflare's
network to run this code and terminate the actual outbound TLS connection; trusting
their resolver for name lookups adds no new trust boundary beyond what already exists,
and it's the same resolver Cloudflare's own `nodejs_compat` `node:dns` shim uses
internally. Making the resolver configurable would hand a caller a way to point the
guard at an untrusted resolver, which defeats the point of having one.

## Why we trust `new URL().hostname`

Every obfuscated IPv4 literal form we reject (hex, octal, decimal-integer, short
dotted) is never handled by our own code — it's normalized before we see it. This was
verified empirically against the Node.js `URL` implementation (the same WHATWG URL
Standard implementation Cloudflare Workers uses), not assumed from the spec text:

```
new URL('http://0x7f000001/').hostname     -> '127.0.0.1'   // scan-secrets-allow: obfuscated-loopback example
new URL('http://017700000001/').hostname   -> '127.0.0.1'   // scan-secrets-allow: obfuscated-loopback example
new URL('http://127.1/').hostname          -> '127.0.0.1'   // scan-secrets-allow: obfuscated-loopback example
new URL('http://[::ffff:127.0.0.1]/').hostname -> '[::ffff:7f00:1]'
```

`src/url-target.test.ts` pins these exact input/output pairs as regression tests. An
all-numeric dotted host is never treated as a domain name by the URL Standard (that
ambiguity is resolved once, in the spec, not per-implementation), so checking
`/^(\d{1,3}\.){3}\d{1,3}$/` against the *parsed* `.hostname` reliably identifies an
IPv4 literal — this is a property of the URL Standard we depend on, not a heuristic we
invented.

## Method, headers, and body

`guardedFetch` accepts `method`, `headers`, and `body` in its options — the minimum the
MCP wire protocol actually needs (POST + JSON body + a handful of protocol headers).
This exists so `guardedFetch` can drive a real MCP request end to end, not just a bare
GET; a calling prober's own wire layer maps onto this by way of its own adapter.

- **`method`**: `'GET'` (default) or `'POST'` only — checked at runtime, not just typed,
  since a caller can hand this a plain string from an untyped `RequestInit`. Anything
  else throws `SsrfBlocked('METHOD_NOT_ALLOWED', ...)`.
- **`headers`**: checked against a fixed **allowlist**, case-insensitively, before any
  network access — `accept`, `authorization`, `content-type`, `mcp-method`, `mcp-name`,
  `mcp-protocol-version`, `mcp-session-id`. A header outside this list throws
  `SsrfBlocked('HEADER_NOT_ALLOWED', ...)` naming the rejected header. An allowlist
  rather than a blocklist because a blocklist can always miss a header nobody thought
  of; an allowlist that's missing one the prober later needs only costs adding a line.
  `mcp-method` and `mcp-name` are here because they're what the real 2026-07-28 modern
  handshake actually sends (`packages/checks/src/protocol.ts`'s `modernHeaders()`) —
  verified against that call site directly, not assumed. `authorization` has no real
  call site yet; it's here for future authenticated probing.
- **`body`**: only allowed when `method` is `'POST'` (`SsrfBlocked('BODY_REQUIRES_POST', ...)`
  otherwise); its byte length is checked against `budget.maxBodyBytes` before any network
  access — the same budget dimension response bodies are checked against
  (`response-view.ts`), not a separate one.

### Non-GET does not follow redirects

A non-GET (POST) request that receives a `3xx` response does **not** continue the
redirect chain — the redirect becomes the final result instead (a normal, successful
return; not a guard rejection), and `GuardedFetchResult.redirectCrossHostObserved` is
set to `true` if the `Location` pointed at a different host, `false` otherwise. This
applies regardless of whether the redirect is same-host or cross-host — the default is
**don't follow**, full stop, not "follow same-host but not cross-host." The reason: a
cross-host POST replaying the same body and headers is the classic credential-leak
redirect pattern (steal the token via a 302 to an attacker-controlled host), and an MCP
server responding to a POST with a redirect is itself worth recording as a signal, not
worth chasing. GET's existing multi-hop redirect-following behavior is unchanged.

### `authorization` never crosses a host

Independently of the above (a second, narrower guarantee, in case a future change ever
lets non-GET follow redirects and this gets missed): whenever any redirect chain —
GET's existing multi-hop follow included — crosses from one host to a different one,
the `authorization` header is stripped from every hop after that point, even though
the rest of the allowlisted headers travel on unchanged. This is why the guarantee is
described as jointly held by two mechanisms, and why there's a dedicated test locking
in the GET-path stripping specifically (`guarded-fetch.test.ts`), not just relying on
"non-GET never gets a second hop" to cover it implicitly.

## Public API

```ts
import {
  guardedFetch, DEFAULT_PROBE_BUDGET, createProbeBudget,
  assertRateLimitAllowed, SsrfBlocked, BudgetExceeded, RateLimited,
} from '@mcpcheckup/ssrf-guard'

const result = await guardedFetch(
  targetUrl,
  createProbeBudget({ claimed: false }), // full budget for claimed targets, halved otherwise
  rateLimitDecision,                      // caller-computed; see "Rate limiting" above
  {
    callerIdentifier: 'session:abc123',   // for the audit trail — never PII, your call
    method: 'POST',                       // defaults to 'GET'; only 'GET' | 'POST'
    headers: { 'content-type': 'application/json', 'mcp-protocol-version': '2026-07-28' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    parseResponse: async (handle) => {
      if (handle.status !== 200) return { ok: false, status: handle.status }
      return { ok: true, body: await handle.json() }
    },
    onAudit: (record) => persistProbeAudit(record), // called on success AND every rejection
  },
)

// result.result        — whatever parseResponse returned; the only body-derived data
// result.status        — final hop's HTTP status
// result.finalUrl       — where the redirect chain ended up
// result.hops           — every hop's hostname, resolved addresses, status
// result.dnsAnswerChangedDuringProbe — see "Detecting a DNS answer that changed mid-probe"
// result.redirectCrossHostObserved   — see "Non-GET does not follow redirects" above
```

`guardedFetch` throws `SsrfBlocked` (target or request rejected — scheme, credentials,
port, or a resolved IP failed policy; an unsupported method; a header outside the
allowlist; a body on a GET request — `.code` and `.detail`/`.message` describe which),
`BudgetExceeded` (redirects, wall-clock time, request count, or request body size
exhausted; `.code` says which), or `RateLimited` (no allowing rate-limit decision was
supplied) before ever calling `parseResponse`. A network failure reaching the target
(DNS-independent — e.g. connection refused, TLS failure) propagates as whatever error
`fetch()` itself throws; that is a legitimate observation for the caller's own assertion
logic to interpret (see `CLAUDE.md`'s `execution_status`), not a guard rejection.

## A note on `global_fetch_strictly_public`

If you've seen this Workers compatibility flag mentioned near SSRF discussions:
it is not SSRF protection. Per Cloudflare's own docs, it only controls whether a
request to a Worker's *own zone* loops back through Cloudflare's front door
(`global_fetch_strictly_public`) or goes straight to the zone's origin, bypassing
Cloudflare security settings for that same-zone request
(`global_fetch_private_origin`, the alternative). It has nothing to do with private
IP ranges or requests to third-party hosts, which is what this package is about.

## Zero runtime dependencies

Everything here — the DNS wireformat codec, the IP policy tables, the DoH client — is
built on nothing but platform globals (`fetch`, `URL`, `TextEncoder`/`TextDecoder`,
`DataView`). No package in `dependencies`. Nothing here should ever need one.

## Limitations summary

- Cannot close the DNS-rebinding race described in "What is not closed" — narrows and
  detects it, does not prevent it.
- Port policy is deliberately narrower than strictly required (443 only) rather than
  trying to enumerate every dangerous port.
- The response-blinding design (`SafeResponseHandle`) raises the bar for accidentally
  leaking target content; it cannot force every future `parseResponse` implementation
  to behave.
- Rate limiting, the audit trail, and the "unclaimed target gets half the budget"
  policy are all *interfaces* this package requires callers to satisfy — the actual
  thresholds and storage are deployment configuration this package deliberately does
  not contain.
- **This package's non-GET-redirect protection only holds if the caller respects it.**
  When `guardedFetch` declines to follow a non-GET redirect, it returns that redirect
  as a normal, successful `GuardedFetchResult` (status `3xx`, `redirectCrossHostObserved`
  set) — a legitimate design choice (see "Non-GET does not follow redirects" above), but
  it means the *caller* is the one responsible for not treating that result as "keep
  going." A caller with its own generic redirect-following logic sitting on top of
  `guardedFetch` (reconstructing a `Response` and re-inspecting it for `3xx` + `Location`)
  can silently undo this protection by following the redirect itself, outside this
  package's view, replaying the same method/headers/body it originally sent — this is a
  real, currently-open gap in a calling prober's own call stack; tracked internally,
  not in this package.
