# @mcpcheckup/attestation-schema

The shape of one signed MCP Checkup attestation, and everything needed to
verify one independently — without trusting our code, our servers, or our
uptime.

If you're writing your own verifier, this package (plus a DSSE library and a
JSON Schema draft 2020-12 validator, both of which you can pick yourself) is
the whole contract. There's nothing else to reverse-engineer.

## Shape, top to bottom

```
DSSE envelope (secure-systems-lab/dsse, unmodified)
├─ payloadType: "application/vnd.mcpcheckup.attestation+json;version=0.3"
│    (or ";version=0.2" / ";version=0.1" for envelopes signed before the
│    respective payload bumps — see "Verifying an archived-version envelope"
│    below; new attestations are always v0.3)
├─ payload: base64(SERIALIZED_BODY)
│    SERIALIZED_BODY = canonicalize(attestation payload)  — nfc-jcs/v1, see below
└─ signatures[]: [{ keyid?, sig: base64(Ed25519(PAE(payloadType, SERIALIZED_BODY))) }]

attestation payload (schema/attestation.schema.json, draft 2020-12; schema/attestation-payload-v0.2.json and schema/attestation-payload-v0.1.json for the archived shapes)
├─ canonicalization, suite_id, suite_version, suite_digest, suite_commit,
│  registry_version, toolset_projection_version, protocol_revision,
│  launch_config_digest              — every rule that produced this attestation, versioned
├─ target                            — what was tested
├─ observed_at, run, probe_region,
│  probe_dns_answer_changed          — when, from where, and under what run conditions
├─ assertions[]                      — one four-state result per check
└─ toolset_fingerprint, schema_fingerprint
```

## The outer layer: DSSE, not invented here

We use [DSSE](https://github.com/secure-systems-lab/dsse) (Dead Simple
Signing Envelope) exactly as specified — the same envelope in-toto and the
Sigstore/SLSA ecosystem use. We didn't design a signing format; we picked
one that already has independent implementations, so a generic DSSE library
in your language already understands our envelope's outer layer. The only
thing specific to us is what's inside `payload`.

The one detail worth being explicit about: what gets signed is not
`payload` itself, but its **PAE** (Pre-Authentication Encoding) —

```
PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
LEN(s) = ASCII decimal byte length of s, no leading zeros
SP     = a single ASCII space (0x20)
```

— which folds `payloadType` into the signed bytes alongside the body. This
is what stops a **type confusion attack**: without it, a signature valid for
one payload type could be replayed against different content that happens
to parse under a different type. `src/dsse.ts` implements `pae()` and is
tested against the DSSE spec's own published test vector (`"hello world"` /
`"http://example.com/HelloWorld"`) byte-for-byte, not just against its own
output.

`src/dsse.ts`'s `signDsseEnvelope`/`verifyDsseEnvelope` use Ed25519 via
`crypto.subtle` — no signing-specific dependency, just the WebCrypto API
available in Node, browsers, and Cloudflare Workers.

**Public key format.** This package never exports or imports keys itself —
`signDsseEnvelope`/`verifyDsseEnvelope` take a `CryptoKey` you already have.
But whatever eventually publishes signing keys (a future `/keys` page) has to
pick *some* byte format, and a verifier needs to know which one to expect.
The recommendation is **raw** (`crypto.subtle.exportKey('raw', publicKey)`):
for Ed25519 this is exactly the 32-byte public key with no wrapping, the
smallest and simplest of WebCrypto's export formats, and trivial to import
back:

```ts
const rawBytes = await crypto.subtle.exportKey('raw', publicKey) // 32 bytes — publish base64Encode(new Uint8Array(rawBytes))
const trustedPublicKey = await crypto.subtle.importKey('raw', base64Decode(publishedBase64), { name: 'Ed25519' }, true, ['verify'])
```

If a future `/keys` page ends up publishing a different format (`spki`, or a
JWK), that page is the one source of truth for it — this note only fixes the
recommendation *this package's own docs/examples* use, so there's at least
one concrete, tested answer instead of an open question.

**On the envelope's own strictness:** the DSSE spec explicitly says
"Producers … MAY add additional fields. Consumers MUST ignore unrecognized
fields" for the envelope's own three keys. We don't add `additionalProperties:
false` anywhere near the DSSE envelope itself — doing so would violate DSSE's
own forward-compatibility contract. Strictness lives one layer in, on the
payload, which is entirely ours to define.

## The payload: what's inside `payload`, and why every field is there

`schema/attestation.schema.json` is JSON Schema draft 2020-12. Every object
in it sets `"additionalProperties": false` and lists every one of its own
keys in `"required"` — including nullable ones (they're always present as a
key; `null` is how "not applicable" is spelled, never an absent key). An
attestation with an unrecognized field is invalid, full stop. The reasoning:
this is the one artifact meant to be picked apart by strangers forever; if
we ever start silently accepting fields nobody validates, nobody — including
us, eighteen months later — can tell whether that field was ever meaningful.

### The version fields

Every one of these is required and independently tested (each has its own
"missing → rejected" test case in `src/schema.test.ts`), because losing any
single one means a future reader can no longer reconstruct *what rules
produced this specific historical conclusion*:

| Field | Answers |
|---|---|
| `canonicalization` | Which byte-canonicalization scheme (always `"nfc-jcs/v1"` today — see below) |
| `suite_id` | Which check suite (matches `packages/checks/checks.json`'s own `suite_id`) |
| `suite_version` | Which **published version** of the executable suite package ran |
| `suite_digest` | Which check-suite source tree ran — defined so that it is recomputable from the repository at `suite_commit`, with no build step (see the caveats in the field's own schema description) |
| `suite_commit` | Which commit `suite_digest` was computed at — the starting point a verifier needs |
| `registry_version` | Which version of the check **definitions** (`checks.json`) was in effect |
| `toolset_projection_version` | Which fields of `tools/list` were allowlisted into the fingerprint |
| `protocol_revision` | Which MCP protocol revision the target was observed speaking |
| `launch_config_digest` | The stdio launch config's digest — `null` for `remote`, required for `stdio` |

`suite_version`/`suite_digest` version the *code*; `registry_version`
versions the *check definitions* that code reads. They can change
independently — a bug fix bumps `suite_version` without touching what a
check claims to test; a rewritten explanation bumps `registry_version`
without a code change — so collapsing them into one field would lose which
one actually changed.

### `target`

```ts
type Target = RemoteTarget | StdioTarget   // discriminated on `transport`
```

Mirrors `providers`/`targets` in `supabase/migrations/0001_core.sql` — same
slug pattern for `provider`/`name` — but as a portable identifier, never a
database UUID. `endpoint_url`/`package_ref` are mutually exclusive and both
always present as keys (the unused one is `null`), so which transport was
used is never ambiguous from partial data.

### `probe_region` / `probe_dns_answer_changed`: run conditions, not check verdicts

`execution_status` (did the probe run to completion) and `assertion_status`
(what it concluded) are orthogonal by design — but there's a *third* kind of
fact that isn't about either axis: conditions of *this particular run itself*,
independent of any one check. `probe_region` is the existing example (which
vantage point observed this run); `probe_dns_answer_changed` is the same idea
applied to network conditions — whether this run's outbound requests observed
the target hostname's DNS answer change mid-probe (re-resolved and compared
after every request by `@mcpcheckup/ssrf-guard`'s `guardedFetch` — its
`dnsAnswerChangedDuringProbe` signal).

**This is deliberately not a `check_id` in `packages/checks/checks.json`, and
never contributes to any assertion's `assertion_status`.** Many healthy
production endpoints legitimately return different DNS answers across
requests — round-robin load balancing, CDN edge selection, active failover
are all normal, unremarkable operation, not evidence of anything wrong with
the target. Judging this as a per-check verdict would misjudge routine DNS
behavior as a target defect on an unknown but plainly nonzero fraction of
otherwise-healthy targets — precisely the false-positive failure mode this
project's kill criteria (a >3% false-positive rate on deterministic checks)
exists to catch. An earlier design folded a DNS-answer change into the
`redirect_policy` check instead; that was wrong for a second, independent
reason too (a changed DNS answer is not a redirect — it would have shown
report readers the wrong `check_id` for what was actually observed).

It's real evidence worth signing into the envelope anyway — it's the source
fact behind `packages/checks`' `ProbeResult.disqualifiedFromPublication` (see
that package's README for the full DNS-rebinding threat model this protects
against), kept here as a field of its own precisely so a consumer never has
to infer this specific network condition from a differently-scoped field
(`disqualifiedFromPublication` may gain other, unrelated reasons later).
`null` for `target.transport: "stdio"` (a local process launch does no DNS
resolution to observe at all), a real `boolean` for `"remote"`.

If you're tempted to promote this to a real check later: don't, unless you
first have a reliable way to distinguish routine multi-answer DNS behavior
from an actual attack — the false-positive risk above is the reason it isn't
one today, not an oversight.

### `assertions[]`: the four-state model

```ts
interface AssertionBase {
  check_id: string          // references packages/checks/checks.json
  docs_version: string      // that check's own docs_version at run time
  execution_status: 'COMPLETED' | 'ERROR' | 'SKIPPED' | 'BLOCKED'
  assertion_status: 'VERIFIED' | 'FAILED' | 'OBSERVED_RISK' | 'UNVERIFIED'
  evidence_provenance: 'INDEPENDENTLY_OBSERVED' | 'SELF_ATTESTED' | 'STATICALLY_ANALYZED'
  reason: string | null
  unverified_reason: string | null
}
```

`execution_status` and `assertion_status` are separate fields on purpose
(CLAUDE.md's third product principle): *did the probe run to completion* and
*what did it conclude* are orthogonal. Collapsing them into one pass/fail
boolean is exactly the mistake this schema exists to make structurally
impossible — there's no boolean field to collapse them into.

**UNVERIFIED always carries a reason.** When `assertion_status` is
`UNVERIFIED`, at least one of `unverified_reason` (specific) or `reason`
(general fallback) must be a non-empty string — mirroring the database's own
`unverified_needs_reason` CHECK constraint
(`assertion_status <> 'UNVERIFIED' OR coalesce(unverified_reason, reason) IS NOT NULL`).
This rule is enforced **three times, independently, on purpose**: the
database CHECK constraint, the `if`/`then` clause in this schema, and
`assertUnverifiedHasReason()` in `src/invariants.ts` (a plain function that
doesn't depend on a JSON Schema validator or a database being reachable at
all). None of the three trusts the others.

### Fingerprints

`toolset_fingerprint`/`schema_fingerprint` are `digest()` output from
`@mcpcheckup/canonicalizer` — `sha256:<64 lowercase hex chars>` — over
`projectToolset(tools)`/`projectSchemas(tools)` respectively, not over a raw
`tools/list` response. See that package's README for why (fingerprinting the
raw response would produce drift on every protocol revision, and this
project's kill criteria is a false-positive rate above 3%).

## `canonicalization: "nfc-jcs/v1"`

The bytes that get signed are `canonicalize(payload)` from
`@mcpcheckup/canonicalizer` — RFC 8785 (JCS) plus a strict NFC-normalization
pass, which is *not* something a scheme calling itself "RFC 8785" is allowed
to do (RFC 8785 §3.1: implementations "MUST preserve Unicode string data
'as is'"). That's why the field says `nfc-jcs/v1`, not `"RFC 8785"` — see
`@mcpcheckup/canonicalizer`'s README for the exact three-step definition and
the full rationale.

The payload records this so you never have to trust *us* about which scheme
was used — you can recompute it yourself with any conformant JCS library
plus one extra step. Note this compares raw bytes, not digests: the DSSE
`payload` field *is* `canonicalize(payload)` directly (see the diagram at the
top of this README) — it's never hashed before signing, so recomputing it
is a direct byte comparison, not a hash comparison:

```js
const nfcNormalized = deepNormalizeToNFC(parsedPayload) // walk it, .normalize('NFC') every key/string
const recomputedBytes = anyRfc8785Library.canonicalize(nfcNormalized) // any conformant JCS implementation
recomputedBytes === SERIALIZED_BODY // the exact bytes you already verified the signature over in step 2
```

(`toolset_fingerprint`/`schema_fingerprint`, mentioned in step 5 below, *are*
digests — of `projectToolset(tools)`/`projectSchemas(tools)` specifically,
not of the payload as a whole. Recomputing those means canonicalizing that
projection and taking its SHA-256, then comparing the `sha256:<hex>` strings
directly — see `digest()` in `@mcpcheckup/canonicalizer`.)

## Verifying an attestation, end to end

1. **Decode the envelope.** `SERIALIZED_BODY = base64Decode(envelope.payload)`.
2. **Verify the signature**, against a public key you already trust (out of
   band — this package doesn't do key discovery or trust decisions, only the
   cryptographic check):
   `Ed25519.verify(pubkey, envelope.signatures[i].sig, PAE(envelope.payloadType, SERIALIZED_BODY))`.
   Reject if `envelope.payloadType` isn't one of the payload types this
   package has ever signed —
   `"application/vnd.mcpcheckup.attestation+json;version=0.3"` (current),
   `";version=0.2"` or `";version=0.1"` (archived — see "Verifying an
   archived-version envelope" below) — and if no signature verifies.
3. **Parse** `SERIALIZED_BODY` as UTF-8 JSON. Per DSSE's own security
   guidance, use *these exact verified bytes* — don't re-serialize the
   parsed object and re-verify against that; that reopens exactly the
   confusion PAE closes.
4. **Validate the parsed object** against the schema matching
   `envelope.payloadType` — `schema/attestation.schema.json` for
   `;version=0.3`, `schema/attestation-payload-v0.2.json` for `;version=0.2`,
   `schema/attestation-payload-v0.1.json` for `;version=0.1` — with any draft
   2020-12 validator. `attestationSchemaForPayloadType(envelope.payloadType)`
   does exactly this mapping and throws on any other value; it never falls
   back to the current schema. Reject on failure — a signature only proves
   who sent it, not that it's shaped like an attestation. **Always branch on
   `payloadType` before picking a schema**: the three payload shapes differ
   (v0.1's `reason`/`unverified_reason` are bare strings, v0.2's and v0.3's
   are `{key, params?}` objects; v0.3 adds a required `suite_commit`), so
   validating a payload against another version's schema fails even though
   the envelope and signature are both completely valid.
5. Optionally, **recompute** `canonicalize(payload)` and compare it byte for
   byte against `SERIALIZED_BODY` (the recipe above), and/or recompute
   `toolset_fingerprint`/`schema_fingerprint` from your own
   independently-observed `tools/list` response and compare those digest
   strings — neither step requires this package's code, only its published
   rules.

```ts
import { verifyDsseEnvelope, base64Decode, attestationSchemaForPayloadType } from '@mcpcheckup/attestation-schema'
import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'

// step 2: both halves matter. verifyDsseEnvelope only proves the signature covers
// *whatever payloadType this envelope itself claims* — checking payloadType too is
// what stops a validly-signed envelope for a DIFFERENT application (e.g. from key
// reuse) from being accepted just because it also happens to pass one of these
// schemas. attestationSchemaForPayloadType() is that check: it accepts exactly the
// payload types this package has ever produced and throws on anything else. An
// archived-version envelope is not less genuine than a current one — it just
// predates a shape change.
const schema = attestationSchemaForPayloadType(envelope.payloadType)

const sigOk = await verifyDsseEnvelope(envelope, trustedPublicKey)
if (!sigOk) throw new Error('signature does not verify')

const payload = JSON.parse(new TextDecoder().decode(base64Decode(envelope.payload))) // step 3

// step 4: validate against the schema that payloadType selected — never against
// ATTESTATION_SCHEMA unconditionally, which only matches ;version=0.3 envelopes.
const ajv = new Ajv2020({ allErrors: true, strict: true })
addFormats(ajv)
const validate = ajv.compile(schema)
if (!validate(payload)) throw new Error('payload does not match schema: ' + JSON.stringify(validate.errors))
```

### Verifying an archived-version envelope

Two payload shapes predate the current one, and envelopes carrying them are
exactly as genuine and exactly as independently verifiable as a current one —
in each case the payload *shape* changed, not the trust model, the signing
key, or the meaning of any assertion:

- `;version=0.1` — `reason`/`unverified_reason` were bare strings, before the
  v0.2 bump changed them to `{key, params?}` objects. Schema:
  `schema/attestation-payload-v0.1.json`, exported as `ATTESTATION_SCHEMA_V0_1`.
- `;version=0.2` — same reason shape as today, but no `suite_commit`, and
  `suite_digest` carried the old npm-`dist.integrity` definition (see that
  field's description in `schema/attestation.schema.json` for why no value
  produced under that definition is reproducible). Schema:
  `schema/attestation-payload-v0.2.json`, exported as `ATTESTATION_SCHEMA_V0_2`.

Each archived file is the exact schema those envelopes were validated against
at signing time. Follow the same five steps above; the only difference is which
`payloadType` you expect and which schema step 4 validates against —
`attestationSchemaForPayloadType()` picks it for you. This package never
produces new envelopes under an archived shape; these schemas exist only so the
ones that already exist stay verifiable forever.

## API

```ts
import {
  // DSSE (generic — see dsse.ts)
  pae,
  base64Encode,
  base64Decode,
  signDsseEnvelope,
  verifyDsseEnvelope,
  verifyDsseSignature,
  type DsseSignature,
  type DsseEnvelope,

  // attestation-specific
  ATTESTATION_PAYLOAD_TYPE,
  signAttestationPayload,     // canonicalize(payload) via nfc-jcs/v1, then DSSE-sign it
  ATTESTATION_SCHEMA,          // the parsed schema/attestation.schema.json object (current, v0.3)
  ATTESTATION_SCHEMA_V0_2,     // the parsed schema/attestation-payload-v0.2.json object (archived)
  ATTESTATION_SCHEMA_V0_1,     // the parsed schema/attestation-payload-v0.1.json object (archived)
  attestationSchemaForPayloadType, // envelope.payloadType -> the schema that validates it; throws on anything unknown

  // the third enforcement layer for "UNVERIFIED needs a reason"
  assertUnverifiedHasReason,
  AssertionInvariantError,

  // generated from schema/attestation.schema.json — see below
  type AttestationPayload,
  type RemoteTarget,
  type StdioTarget,
  type Assertion,
  type AssertionBase,
} from '@mcpcheckup/attestation-schema'
```

## Schema ↔ TypeScript types

`src/generated-types.ts` is generated from `schema/attestation.schema.json`
by `pnpm generate-types` (`json-schema-to-typescript`, a devDependency — not
part of this package's runtime). `src/generated-types-freshness.test.ts`
regenerates from the schema on every test run and diffs the result against
the committed file byte-for-byte, so the schema and the types can never
silently drift apart; if you edit the schema, `pnpm generate-types` and
commit the result, or CI fails.

**One known, deliberate imprecision:** two generated types
(`AttestationPayload` and `Assertion`) carry an extra
`& { [k: string]: unknown }` in their generated form. Both come from a
cross-field rule expressed as `allOf`/`if`/`then` (`launch_config_digest`'s
dependency on `target.transport`; `reason`/`unverified_reason`'s dependency
on `assertion_status`) — `json-schema-to-typescript` doesn't fully close
`additionalProperties` across that pattern. The **runtime** schema is fully
strict regardless (ajv enforces `additionalProperties: false` correctly in
every case — see the additionalProperties-rejection tests in
`src/schema.test.ts`); only the generated TypeScript type is very slightly
looser than the schema it comes from, in the one specific sense that a
malformed object literal with an unexpected extra key won't be flagged by
`tsc` for those two types. Every *named* field is fully and correctly typed
either way. Where a cross-field rule instead determines a value's *type*
(`target`'s `endpoint_url`/`package_ref`), it's expressed as `oneOf` two
complete shapes instead, which generates a real discriminated union with no
such gap — see `RemoteTarget | StdioTarget`.

## Testing

- `src/dsse.test.ts` — PAE against the DSSE spec's own published test
  vector; sign/verify round trips; tamper tests (payload byte flip,
  payloadType swap, wrong key) that must fail; multi-signature envelopes.
- `src/schema.test.ts` — a complete valid sample validates; every required
  version field has its own "missing → rejected" case;
  `additionalProperties` rejection at every nesting level; every
  `target`/`launch_config_digest`/`probe_dns_answer_changed`
  transport-conditional case; the UNVERIFIED-needs-reason rule including its
  "reason as fallback" case.
- `src/invariants.test.ts` — the same UNVERIFIED-needs-reason rule, enforced
  by plain code with no schema validator involved.
- `src/attestation.test.ts` — end to end: sign a real sample payload,
  verify it, confirm the signed bytes are genuinely `canonicalize(payload)`
  and that decoding them back still validates against the schema, and that
  a tampered payload fails verification.
- `src/generated-types-freshness.test.ts` — schema and generated types stay
  in sync.

Run with `pnpm test` (or `pnpm -r test` from the repo root). Zero runtime
dependencies of our own beyond `@mcpcheckup/canonicalizer` (our own
zero-dependency sibling package); `ajv`/`ajv-formats`/
`json-schema-to-typescript` are devDependencies used only in tests and the
type generator, never imported by anything this package ships.
