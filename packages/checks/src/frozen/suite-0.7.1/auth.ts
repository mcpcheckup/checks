// FROZEN: packages/checks/src/auth.ts at suite 0.7.1 (2c99377), verbatim except that
// FROZEN: imports of files outside this directory go through ../../ instead of ./ .
// FROZEN: Test-only baseline for the T86b differentials (credential-gate-withhold-differential.test.ts
// FROZEN: and others), which check its git blob id. DO NOT edit or "update" it; it is the 0.7.1 behaviour.
import { sendRequest } from '../../wire.ts'
import type { ProbeContext } from '../../wire.ts'
import type { ProbeCallResult } from './protocol.ts'
import type { FetchLike, ProbeBudget } from '../../types.ts'

export interface AuthChallenge {
  resourceMetadataUrl: string | null
  scope: string | null
}

/** Parses the key="value" parameters of a Bearer WWW-Authenticate challenge —
 *  only the two parameters auth_metadata cares about, not a general auth-scheme
 *  parser (this check never touches credentials, only publicly observable
 *  challenge structure). */
export function parseBearerChallenge(headerValue: string): AuthChallenge {
  const params: Record<string, string> = {}
  for (const m of headerValue.matchAll(/(\w+)="([^"]*)"/g)) {
    params[m[1]!] = m[2]!
  }
  return {
    resourceMetadataUrl: params.resource_metadata ?? null,
    scope: params.scope ?? null,
  }
}

/** RFC 9110 §5.6.2's `tchar` set — the characters legal in a `token`. Used
 *  only to recognize the shape of a challenge, never to parse or act on its
 *  content. `token` is what both `auth-scheme = token` (§11.1) and
 *  `auth-param = token BWS "=" BWS ( token / quoted-string )` (§11.2) are
 *  built out of.
 *
 *  THE GRAMMAR THIS SCANNER IMPLEMENTS IS TRANSCRIBED IN THIS FILE and
 *  nowhere else in this package (app/CLAUDE.md 审查纪律 #4: the text that is
 *  easy to mis-copy lives once, next to the implementation). It is NOT all
 *  one clause, and this comment asserted for several rounds that it was:
 *  every piece was labelled §11.6.1, which is the clause that defines the
 *  HEADER (`WWW-Authenticate = #challenge`) and none of the productions
 *  under it. The map below gives, for each production this scanner leans on,
 *  the clause that defines it and the comment in THIS FILE that writes it
 *  down — so a reader checking any one of them against the RFC neither has to
 *  guess which section to open nor has to hunt for our version of it:
 *
 *    token / tchar                          §5.6.2    here
 *    auth-scheme = token                    §11.1     here
 *    auth-param                             §11.2     here, and consumeAuthParam
 *    challenge                              §11.3     here, in full, just below
 *    WWW-Authenticate = #challenge          §11.6.1   here
 *    OWS / BWS                              §5.6.3    skipWs
 *    quoted-string / qdtext / quoted-pair   §5.6.4    QUOTED_STRING_Y
 *    VCHAR                                  RFC 5234  QUOTED_STRING_Y
 *    token68, and the base64/base32 prose   §11.2     consumeToken68
 *    list #rule, the OWS around its commas  §5.6.1    classifyCredentialChallenge
 *
 *  §11.3's production, written out HERE in full and nowhere else:
 *
 *    challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
 *
 *  It used to be the other way round: this map abbreviated that line to
 *  `[ 1*SP ... ]` while a fixture's guardsAgainst spelled it out in full.
 *  That has 审查纪律 #4 backwards — the authority has to be the COMPLETE
 *  copy, or the sites that defer to it are deferring to less than they
 *  already had. Clause numbers still appear in auth.test.ts and in a few
 *  fixture guardsAgainst strings; as of round 18 those name the clause and
 *  defer to this file WITHOUT reproducing any ABNF. If a rule ever needs
 *  correcting, this file is the only place it is written down. */
const TCHAR_CLASS = `!#$%&'*+\\-.^_\`|~0-9A-Za-z`

/** Sticky (`y`) matchers, so the scanner below can advance an index without
 *  slicing the header value on every step. `token = 1*tchar`; token68's own
 *  character set is a different, smaller one (ALPHA / DIGIT / "-" / "." /
 *  "_" / "~" / "+" / "/") and is NOT tchar.
 *
 *  These are module-level and therefore SHARED: a sticky regex carries
 *  `lastIndex` between calls. Every use below sets `lastIndex` immediately
 *  before its own `exec`, which makes that state irrelevant — but only
 *  because the whole scan is synchronous, so no second call can interleave
 *  between the assignment and the `exec`. Introducing an `await` anywhere
 *  inside classifyCredentialChallenge or its helpers would break that
 *  silently; move these to locals first if that ever becomes necessary.
 *  (judgeAuthMetadata further down IS async, but it uses none of these.) */
const TOKEN_Y = new RegExp(`[${TCHAR_CLASS}]+`, 'y')
const TOKEN68_BASE_Y = /[A-Za-z0-9\-._~+/]+/y
const EQUALS_RUN_Y = /=*/y
/** `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE`. The alternation
 *  is what makes this a structure test rather than a "contains quotes" test:
 *  an unterminated `"..."` cannot match, and a `\"` inside is consumed as one
 *  escaped character rather than as the closing quote.
 *
 *  §11.2's `auth-param` reaches this rule by reference — its value
 *  alternative is `token / quoted-string` — but `quoted-string` and both of
 *  its alternatives are defined in RFC 9110 §5.6.4, NOT in §11.2. That
 *  clause is TRANSCRIBED here and nowhere else in this package — it is the
 *  §5.6.4 row of the clause map on TCHAR_CLASS above (app/CLAUDE.md
 *  审查纪律 #4):
 *
 *    qdtext      = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 *    quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
 *
 *  with `VCHAR = %x21-7E` (RFC 5234 core rule). So neither alternative admits
 *  a C0 control other than HTAB, and neither admits DEL (%x7F).
 *
 *  Both arms used to be written as "anything at all" — `[^"\\]` and
 *  `\\[\s\S]` — which accepted every one of those characters. A first
 *  challenge carrying one, e.g. `Bearer realm="x<0x01>"`, was therefore
 *  classified as a credential gate, and the round's genuine FAILED became
 *  UNVERIFIED / credential_required. The shape really is reachable: within
 *  the octet range a field value can hold, Node's `Headers` refuses NUL, LF
 *  and CR and nothing else, so a C0 control or a DEL round-trips through it
 *  byte-identical and arrives here intact.
 *  (Codex PR#19 P2, round 18 — the same over-wide direction as round 11's
 *  `1*SP` fix, and the same consequence.)
 *
 *  obs-text is `%x80-FF`, i.e. OCTETS, and what this scanner holds is a
 *  string the runtime has already decoded out of those octets. Both classes
 *  therefore spell obs-text as the CODE-UNIT range `\u0080-\uFFFF` rather
 *  than as `\x80-\xFF`, so the class does not additionally assert one
 *  particular decoding: under a runtime that decodes rather than byte-maps,
 *  one non-ASCII code unit stands for a SEQUENCE of obs-text octets, and
 *  `\x80-\xFF` would reject it.
 *
 *  THAT SENTENCE IS ABOUT A RUNTIME WE DO NOT HAVE, and it has to say so.
 *  Through the only caller that exists — the next paragraph — swapping the
 *  two spellings rejects NOTHING and accepts nothing new: no code unit above
 *  0xFF can reach here, so the two classes are indistinguishable from
 *  outside this module. Measured in round 18: substituting `\x80-\xFF` for
 *  `\u0080-\uFFFF` in BOTH arms turns zero assertions red anywhere in
 *  packages/checks or packages/fixtures. The wider bound is insurance
 *  against a future caller, not a guard, and auth.test.ts says so at the
 *  one place where it would otherwise be tempting to claim a test covers it.
 *
 *  The point of tightening these classes is to exclude control characters,
 *  not to police non-ASCII — hence also no `u` flag, so lone surrogates stay
 *  accepted here exactly as they were before.
 *
 *  BE PRECISE ABOUT WHAT THAT UPPER BOUND BUYS TODAY, measured rather than
 *  assumed: a `Headers` field value is a WHATWG ByteString, and Node's
 *  implementation throws on any code unit above 0xFF, so through the real
 *  `Headers` this function is handed, the REACHABLE obs-text range is exactly
 *  the code units 0x80-0xFF — one code unit per octet, no decoding involved.
 *  Everything above 0xFF in the class is therefore unreachable through that
 *  caller rather than merely unused, and is deliberately kept anyway: it costs
 *  nothing (obs-text is where the grammar is permissive already) and it means
 *  this class need not be revisited if the value ever arrives from a runtime
 *  that decodes instead of byte-mapping. Both halves of that claim — 0xE9
 *  accepted, U+4E2D refused by Headers itself — are pinned in auth.test.ts. */
const QUOTED_STRING_Y = /"(?:[\t \x21\x23-\x5B\x5D-\x7E\u0080-\uFFFF]|\\[\t \x21-\x7E\u0080-\uFFFF])*"/y

/** Every real IANA-registered auth-scheme name (Bearer, Basic, Digest,
 *  Negotiate, HOBA, Mutual, ...) is well under this. `scheme` becomes a
 *  Reason.params value the target server controls, propagated into the
 *  stored assertion (and, when signed, the attestation payload) verbatim —
 *  up to eight times per run, once per cascaded check. A `tchar`-only header
 *  value with no whitespace/comma anywhere in it makes the scheme token's
 *  `+` otherwise unbounded, so this predicate needs an explicit bound.
 *
 *  A token this long is not a real scheme name with a few extra characters
 *  to trim — it's malformed, full stop. Per app/CLAUDE.md's input-bounds
 *  rule (每个公开字符串输入有 .max()，超限显式报错不截断 — an over-limit
 *  public string input must be explicitly rejected, not silently
 *  truncated), and because `scheme` sits on a path that reaches a signed
 *  attestation field, classifyCredentialChallenge below rejects an
 *  over-length token outright (returns null, so the round falls through to
 *  its ordinary FAILED path) rather than truncating it and passing a
 *  mangled value through as if it were the real scheme. */
const MAX_SCHEME_LEN = 64

/** Advances past `OWS` / `BWS`. §5.6.3 spells both the same way and this is
 *  that clause's transcription (TCHAR_CLASS's map above points here):
 *
 *    OWS = *( SP / HTAB )
 *    BWS = OWS
 *
 *  SP and HTAB only — a header value can carry no bare CR/LF by the time it
 *  reaches us. */
function skipWs(v: string, i: number): number {
  let j = i
  while (j < v.length && (v[j] === ' ' || v[j] === '\t')) j++
  return j
}

/** Matches a sticky regex at exactly `i`. Returns the matched text, or null. */
function matchAt(re: RegExp, v: string, i: number): string | null {
  re.lastIndex = i
  const m = re.exec(v)
  return m !== null && m.index === i && m[0].length > 0 ? m[0] : null
}

/** Consumes one complete `auth-param = token BWS "=" BWS ( token /
 *  quoted-string )` starting at `i`. Returns the index just past it, or -1
 *  when what starts at `i` is not a well-formed auth-param — including the
 *  truncated `realm=` shape (name and "=" present, no value) and the
 *  unterminated `realm="mcp` shape. */
function consumeAuthParam(v: string, i: number): number {
  const name = matchAt(TOKEN_Y, v, i)
  if (name === null) return -1
  let j = skipWs(v, i + name.length)
  if (v[j] !== '=') return -1
  j = skipWs(v, j + 1)
  const quoted = matchAt(QUOTED_STRING_Y, v, j)
  if (quoted !== null) return j + quoted.length
  const bare = matchAt(TOKEN_Y, v, j)
  if (bare !== null) return j + bare.length
  return -1
}

/** Consumes one complete `token68` starting at `i`. Returns the index just
 *  past it, or -1.
 *
 *  `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`,
 *  taken exactly as written: any number of trailing "=" characters, with no
 *  arithmetic on the base length. §11.2 names base64, base64url, base32 and
 *  base16 as the encodings this is meant to carry, and their padding runs to
 *  different lengths (base32 pads with up to six "="), so there is no single
 *  padding length to check against and no reason to invent one.
 *
 *  AMBIGUITY, resolved here deliberately: `realm=` is simultaneously a valid
 *  token68 (base `realm`, one padding "=") and a truncated auth-param (name
 *  and "=" present, value missing). They are the same string — `token` "="
 *  end-of-string — so no branch ordering can separate them. The tie is broken
 *  in favour of the RFC's own grammar: `Bearer realm=` IS a structurally
 *  valid challenge, so it is classified as a credential gate. The alternative
 *  (guessing that the server meant a truncated auth-param and rejecting it)
 *  would make this predicate stricter than the RFC, and the published copy
 *  promises exactly RFC structural validity — anything the RFC calls valid
 *  but we reject is a case where the copy is wider than the code. Round 7,
 *  overruling round 6.
 *
 *  This costs nothing: consumeAuthParam is still what rejects a MALFORMED
 *  remainder (`Bearer ???`, `Bearer real m="x"`, `Bearer "unquoted-open`),
 *  which is what this package's own rule — "401 + 畸形/空 WWW-Authenticate
 *  不豁免" — and Codex PR#19's P2 are actually about. `realm=` is not malformed. */
function consumeToken68(v: string, i: number): number {
  const base = matchAt(TOKEN68_BASE_Y, v, i)
  if (base === null) return -1
  EQUALS_RUN_Y.lastIndex = i + base.length
  const pad = EQUALS_RUN_Y.exec(v)
  return i + base.length + (pad !== null ? pad[0].length : 0)
}

/** Classifies whether an HTTP response is "credential-gated" in the narrow,
 *  structural sense this function defines: HTTP 401
 *  AND a `WWW-Authenticate` header whose value opens with a COMPLETE, fully
 *  validated challenge whose auth-scheme token is no longer than
 *  MAX_SCHEME_LEN. Returns that scheme, lowercased, or null when any
 *  condition fails — including an over-length token, which is rejected
 *  outright rather than truncated (see MAX_SCHEME_LEN's comment above).
 *
 *  Exactly three shapes are accepted for the first challenge, and nothing
 *  else (Codex PR#19 P2, round 6 — the previous implementation validated the
 *  leading auth-scheme token and then accepted whatever followed it, so
 *  `Bearer ???` classified as a credential gate and converted a genuine
 *  FAILED into an UNVERIFIED):
 *
 *    1. `auth-scheme` alone (`Bearer`; `Basic, Bearer realm="x"`).
 *    2. `auth-scheme` 1*SP `token68` (`Bearer abc123==`; `Bearer realm=` —
 *       see consumeToken68 for why that ambiguous one is accepted).
 *    3. `auth-scheme` 1*SP one or more comma-separated, individually
 *       well-formed `auth-param`s (`Bearer realm="mcp"`;
 *       `Bearer realm="mcp", resource_metadata="<url>"`).
 *
 *  The `1*SP` in shapes 2 and 3 is SP only — the grammar never admits HTAB
 *  there. But whitespace sitting after the scheme token is AMBIGUOUS on its
 *  face: it may be that `1*SP` separator, or it may be list OWS (which DOES
 *  admit HTAB, §5.6.1) in front of a "," that ends this challenge. A comma or
 *  end-of-value immediately after the run resolves it in favour of OWS, and
 *  the scheme alone was then already a complete shape-1 challenge; anything
 *  else means it was the separator and must be all SP. See the scanner below.
 *
 *  TERMINATION, stated once here rather than per-shape (审查纪律 #4 — the
 *  earlier per-shape phrasing drifted out of date and had to be removed):
 *  every one of the three shapes ends at end-of-value or at a ",", and OWS
 *  may sit in between. The MECHANISM, stated exactly, because the obvious
 *  summary ("skipWs runs before every end-or-comma test") is false at the
 *  first site a reader looks at: shape 1 is decided at TWO sites. The
 *  immediate `i === value.length || value[i] === ','` test right after the
 *  scheme token settles the zero-OWS case (`Basic`, `Basic,`) before the
 *  OWS ambiguity can arise at all, and it has no skipWs in front of it
 *  because it does not need one. The LIST OWS branch below then decides the
 *  rest of shape 1 (`Basic ,`, `Basic<HTAB>,`) after a skipWs. Shapes 2 and
 *  3 have only the second kind: their end-or-comma tests each sit directly
 *  behind a skipWs — after `consumeToken68` returns, and after each
 *  auth-param inside the loop. So skipWs precedes every end-or-comma test
 *  except shape 1's immediate one. Measured against this code:
 *  `Bearer abc , Basic realm="y"` and
 *  `Bearer abc<HTAB>, Basic realm="y"` both yield bearer, as do the
 *  shape-3 equivalents `Bearer realm="x" , Basic realm="y"` and
 *  `Bearer realm="x"<HTAB>, Basic realm="y"`. (OWS admits HTAB here; only
 *  the `1*SP` separator above is SP-only.) What may NOT sit in between is
 *  anything else: `Bearer abc def` is null, because `def` is neither part of
 *  the `token68` nor the start of a new challenge — a complete token68
 *  PREFIX does not rescue a value carrying trailing junk after it.
 *
 *  Every character consumed as part of that first challenge is validated;
 *  there is no unvalidated remainder inside it. `Bearer ???`,
 *  `Bearer real m="x"`, `Bearer "unquoted-open`, `Bearer realm="mcp` and
 *  `Bearer realm="mcp" garbage` are all rejected.
 *
 *  WHERE VALIDATION DELIBERATELY STOPS, and why that keeps the claim honest:
 *  `WWW-Authenticate` carries a comma-separated list of challenges (§11.6.1;
 *  the production itself is on TCHAR_CLASS's map above, not repeated here),
 *  and one comma separates BOTH the auth-params inside a single challenge AND one
 *  challenge from the next — a fully general "how many challenges, and where
 *  does each one end" parse is ambiguous without scheme-specific knowledge,
 *  and is more than this predicate needs. So in shape 3, scanning stops at
 *  the first post-comma element that is not itself a well-formed auth-param:
 *  that is where a SECOND challenge begins, and everything from there on is
 *  deliberately not validated. When multiple challenges are present it
 *  reports whichever scheme leads.
 *
 *  BE PRECISE ABOUT WHAT THAT LEAVES ASSERTED — it is narrower than "this
 *  header carries at least one structurally valid challenge, and the scheme
 *  of the first one is X", which is what this comment used to claim and what
 *  the loop does not deliver. Once the first challenge opens an auth-param
 *  list, the loop keeps consuming comma-separated auth-params GREEDILY, and a
 *  malformed element after a comma rejects the WHOLE header rather than
 *  falling back to the last complete challenge. Measured: with this exact
 *  code, `Bearer realm="x", a=b junk` returns null, even though
 *  `Bearer realm="x"` on its own is a complete challenge terminated by a
 *  comma — `a=b` is consumed as a continuation of challenge #1, and the
 *  trailing `junk` then sinks the header. So what this function actually
 *  asserts is: THE FIRST CHALLENGE PARSES CLEANLY, AND SO DOES ANY AUTH-PARAM
 *  CONTINUATION AFTER IT.
 *
 *  Read "the first challenge" strictly as "the first challenge AS THIS
 *  SCANNER DELIMITS IT", never as "some complete challenge prefix" — the
 *  loose reading is wider than the code, and it is precisely the reading
 *  round 11 disproved. The shape-2 case makes the difference concrete:
 *  `Bearer abc def` returns null even though `Bearer abc` on its own is a
 *  complete token68 challenge, because a `token68` must reach end-of-value
 *  or a "," with only OWS in between (see TERMINATION above), and `def` is
 *  neither. Same direction as the auth-param case: toward FAILED, never
 *  toward a false exemption.
 *
 *  Read that closing claim — "the first challenge parses cleanly, and so
 *  does any auth-param continuation after it" — as SUBJECT TO THE
 *  PRECONDITIONS ABOVE. It is about challenge SHAPE and does not carry all
 *  of them on its own. The one that bites: the auth-scheme token is
 *  additionally bounded by MAX_SCHEME_LEN (opening paragraph; the bound and
 *  its rationale are written once on the constant itself, not repeated
 *  here). The RFC imposes no such limit, so an over-length `tchar`-only
 *  value IS a challenge this scanner would delimit and it does parse
 *  cleanly as an auth-scheme — and it is still rejected. Measured: a scheme
 *  exactly at MAX_SCHEME_LEN is accepted, one character longer returns null,
 *  and so does an over-length scheme followed by an otherwise well-formed
 *  `realm="mcp"`. That bound is ours, not the grammar's.
 *
 *  That is still sound against the published copy ("a 401 carrying a
 *  structurally valid WWW-Authenticate challenge"): the gap runs toward
 *  FAILED — a header we reject here keeps its ordinary failing verdict — and
 *  never toward a false exemption, which is the direction that would matter.
 *  Pre-existing since round 6, found by the reviewer's round-11 differential
 *  fuzz campaign; the fix is a WIDENING and is deferred to its own campaign
 *  rather than ridden along on an unrelated change (tracked internally, not
 *  in this package).
 *
 *  Deliberately narrow on purpose: 403
 *  is never exempted (RFC defines no challenge header for 403, so it can't
 *  be structurally distinguished from a WAF/geo-block); a bare 401 with no
 *  challenge header, or one that is empty or malformed, is never exempted
 *  either — that shape is the droproom cause-5 legacy-fallback signal
 *  (protocol.ts's `performHandshake`) and must keep triggering it.
 *
 *  Zero IO — this function itself never calls fetch/sendRequest and never
 *  reaches into ./protocol.ts or ./probe.ts (the module as a whole does
 *  import sendRequest from ./wire.ts and a type from ./protocol.ts, for
 *  judgeAuthMetadata below; classifyCredentialChallenge just never touches
 *  either). */
export function classifyCredentialChallenge(status: number, headers: Headers): { scheme: string } | null {
  if (status !== 401) return null
  const value = headers.get('www-authenticate')
  if (!value) return null

  const scheme = matchAt(TOKEN_Y, value, 0)
  if (scheme === null) return null
  if (scheme.length > MAX_SCHEME_LEN) return null // reject, don't truncate — see MAX_SCHEME_LEN's comment
  const accepted = { scheme: scheme.toLowerCase() }

  let i = scheme.length
  // Shape 1: the scheme token is the whole first challenge.
  if (i === value.length || value[i] === ',') return accepted
  // The scheme token must end at a token boundary. Whitespace is the only
  // thing that can legally follow it here (either the challenge's own
  // separator or list OWS before a comma — disambiguated just below), so
  // anything else means it was glued to something else (`Bearer=x`), which
  // is not a syntactically valid challenge at all.
  if (value[i] !== ' ' && value[i] !== '\t') return null
  // Codex PR#19 (round 11), two comments, one defect seen from two sides:
  // this run was previously assumed to BE the challenge's own separator, so
  // the scanner was simultaneously too wide (it accepted HTAB, which `1*SP`
  // does not admit) and too narrow (it rejected `Basic , Bearer realm="x"`,
  // a perfectly valid two-challenge list, because it read the OWS before the
  // comma as an empty parameter section). Look past the run to disambiguate.
  const afterWs = skipWs(value, i)
  if (afterWs === value.length || value[afterWs] === ',') {
    // LIST OWS. The bare scheme was already a complete first challenge, and
    // `#challenge`'s OWS legitimately contains HTAB (§5.6.1), so no 1*SP
    // check applies on this path: `Basic , Bearer realm="x"` and
    // `Basic<HTAB>, Bearer realm="x"` both yield basic, and `Basic ,` does
    // too (a #rule tolerates an empty trailing element). Headers.get() strips
    // trailing OWS, so a value that is scheme-plus-whitespace and nothing
    // else is not reachable through a real Headers object anyway.
    //
    // Only the TRAILING half of that §5.6.1 tolerance is implemented. The
    // same clause's leading `*( "," OWS )` is not: `, Bearer realm="x"` and
    // `,Bearer realm="x"` both return null, because the scheme token is
    // anchored at index 0 (matchAt(TOKEN_Y, value, 0) above) and a leading
    // comma is not a token character. That asymmetry is deliberate and stays
    // — §5.6.1 tells senders not to generate empty leading elements in the
    // first place, so rejecting them costs nothing real, and the rejection
    // direction is FAILED rather than a false exemption. Stated here so a
    // reader comparing this comment against the code finds no gap.
    return accepted
  }
  // Not a comma, so this run IS the challenge's own separator, and the
  // grammar spells that `1*SP`: one or more SP, never HTAB. Rejecting
  // `Bearer<HTAB>realm="mcp"` is the direction that matters most here —
  // exempting a malformed header turns a genuine FAILED into an UNVERIFIED,
  // which is exactly the 判据写宽 escape this task is primarily guarding
  // against. (More than one SP is fine: `1*SP`, not a single SP.)
  for (let k = i; k < afterWs; k++) {
    if (value[k] !== ' ') return null
  }
  i = afterWs

  // Shape 3 is tried before shape 2 because an element like `realm="mcp"`
  // also opens with characters token68 would accept; an element that is a
  // well-formed auth-param is unambiguously an auth-param.
  const first = consumeAuthParam(value, i)
  if (first >= 0) {
    let j = first
    for (;;) {
      const k = skipWs(value, j)
      if (k === value.length) return accepted // the auth-param list ended cleanly
      if (value[k] !== ',') return null // junk glued after an otherwise complete auth-param
      const next = skipWs(value, k + 1)
      const consumed = consumeAuthParam(value, next)
      if (consumed < 0) return accepted // a second challenge starts here — not validated, see above
      j = consumed
    }
  }

  // Shape 2.
  const end = consumeToken68(value, i)
  if (end < 0) return null
  const after = skipWs(value, end)
  if (after === value.length || value[after] === ',') return accepted
  return null
}

type Reason = { key: string; params?: Record<string, string | number> } | null

export type AuthMetadataVerdict =
  | { status: 'VERIFIED' }
  | { status: 'UNVERIFIED'; reason: Reason }
  | { status: 'OBSERVED_RISK'; reason: Reason }

/** Judges auth_metadata from the same tools/call(unknown tool) response
 *  error_taxonomy already triggered — no separate probe request needed for the
 *  challenge itself. If it's a real challenge with a resource_metadata pointer,
 *  this fetches that document (one more request, charged to the same budget) to
 *  cross-check its declared scopes_supported against what the challenge itself
 *  claimed. Deliberately does NOT follow jwks_uri even when the metadata
 *  declares one: no predicate here currently depends on JWKS contents (a
 *  multi-key JWKS is a normal key-rotation window, not evidence of anything —
 *  see jwks-multiple-keys-not-flagged in @mcpcheckup/fixtures), so fetching it
 *  would only spend probe budget without changing the verdict. */
export async function judgeAuthMetadata(opts: {
  fetchImpl: FetchLike
  budget: ProbeBudget
  ctx: ProbeContext
  callResult: ProbeCallResult
}): Promise<AuthMetadataVerdict> {
  const { fetchImpl, budget, ctx, callResult } = opts

  if (callResult.status !== 401) {
    return { status: 'VERIFIED' }
  }

  const wwwAuth = callResult.headers.get('www-authenticate')
  if (!wwwAuth) {
    return { status: 'UNVERIFIED', reason: { key: 'auth_401_no_challenge' } }
  }

  const challenge = parseBearerChallenge(wwwAuth)
  if (!challenge.resourceMetadataUrl) {
    return { status: 'UNVERIFIED', reason: { key: 'auth_challenge_no_metadata_url' } }
  }

  const metaRes = await sendRequest(fetchImpl, challenge.resourceMetadataUrl, { method: 'GET' }, budget, ctx)
  if (metaRes.status !== 200) {
    return { status: 'OBSERVED_RISK', reason: { key: 'auth_metadata_http_error', params: { status: metaRes.status } } }
  }

  let metadata: unknown
  try {
    metadata = JSON.parse(metaRes.bodyText)
  } catch {
    return { status: 'OBSERVED_RISK', reason: { key: 'auth_metadata_invalid_json' } }
  }
  if (typeof metadata !== 'object' || metadata === null) {
    return { status: 'OBSERVED_RISK', reason: { key: 'auth_metadata_not_json_object' } }
  }

  const scopesSupported = (metadata as Record<string, unknown>).scopes_supported
  if (challenge.scope && Array.isArray(scopesSupported)) {
    const declared = challenge.scope.split(/\s+/).filter(Boolean)
    const supported = new Set(scopesSupported.filter((s): s is string => typeof s === 'string'))
    const contradicted = declared.some((s) => !supported.has(s))
    if (contradicted) {
      return { status: 'OBSERVED_RISK', reason: { key: 'auth_scope_contradiction' } }
    }
  }

  return { status: 'VERIFIED' }
}
