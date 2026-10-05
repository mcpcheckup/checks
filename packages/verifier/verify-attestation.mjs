#!/usr/bin/env node
/**
 * packages/verifier/verify-attestation.mjs — an independent DSSE-envelope
 * verifier for MCP Checkup attestations.
 *
 * DEPENDENCY RESTRICTION (binding, not a style preference): this file may
 * depend on Node's built-in WebCrypto and @mcpcheckup/canonicalizer ONLY. It
 * must never import from @mcpcheckup/attestation-schema or any other
 * workspace package. @mcpcheckup/attestation-schema already exports a
 * working pae()/verifyDsseEnvelope() — using them here would make this
 * "independent verifier" just re-run our own signing code and call that
 * independent proof, which proves nothing about whether that code is
 * correct in the first place. This is exactly the reasoning
 * packages/canonicalizer/src/differential.test.ts already applies to
 * itself ("judgment logic must not share code with the thing being
 * judged") — this script is that same principle applied to the whole
 * pipeline's final output, not just one package's internals. So DSSE's PAE
 * (Pre-Authentication Encoding) is reimplemented from scratch below,
 * independently of packages/attestation-schema/src/dsse.ts's own pae().
 * Both copies should compute identical bytes for identical input — that's
 * required by the public DSSE spec itself (secure-systems-lab/dsse), not
 * because one was copied from the other — and this file must never
 * `import` that one to find out.
 *
 * Usage:
 *   node packages/verifier/verify-attestation.mjs --envelope <path-to-envelope.json> --keys <path-to-keys.json>
 *   node packages/verifier/verify-attestation.mjs --envelope <path-to-envelope.json> --pubkey <spki-base64-string-or-path>
 *
 * --keys reads the published key document (its format is described in
 * packages/attestation-schema/README.md): every key in it is validated, each
 * signature's keyid is looked up in it, and the key's revoked_at, valid_from
 * and valid_until are applied against the payload's signed observed_at.
 * Download the document yourself; this script never touches the network.
 *
 * --pubkey accepts either a raw base64 SPKI string, or a path to a file
 * whose entire contents (trimmed) is that string — whichever is more
 * convenient for whoever is running this by hand. Every signature's keyid
 * must equal the first 16 hex characters of sha256(that key's SPKI bytes).
 *
 * Checks performed, in order (exit code 0 only if all pass):
 *   0. envelope.payloadType is one of the types listed in
 *      ALLOWED_PAYLOAD_TYPES below. Anything else fails before any signature
 *      work.
 *   1. Every signature names a key (--keys: one in the published set;
 *      --pubkey: the one given). With --keys, that key must not be revoked and
 *      the payload's observed_at must lie within its valid_from .. valid_until.
 *      And at least one signature verifies, under its key, over
 *      PAE(envelope.payloadType, base64-decoded payload) — DSSE's own "at least
 *      one signature" semantics.
 *   2. The payload bytes are themselves exactly nfc-jcs/v1's canonical
 *      encoding (via @mcpcheckup/canonicalizer's canonicalBytes) of the
 *      JSON they parse to. A payload that is valid JSON, correctly signed,
 *      but not byte-identical to its own canonical form is still a
 *      reportable finding: either `payload.canonicalization` was never
 *      actually true, or the payload was altered in a way that happens to
 *      still parse as the same JSON.
 *
 * This script never writes any file — it only reads the envelope (and,
 * optionally, the keys / pubkey file) and prints a summary to stdout/stderr.
 */
import { readFileSync, existsSync, statSync } from 'node:fs'

// Relative path, not the bare `@mcpcheckup/canonicalizer` specifier —
// deliberately, even though this package has its own package.json. A third
// party who has cloned this repository must be able to run
// `node packages/verifier/verify-attestation.mjs` directly, with no `pnpm
// install` and no node_modules of any kind: a bare specifier only resolves
// once a package manager has set up a symlink for it, but a relative path
// resolves from the filesystem alone. This is still exactly
// @mcpcheckup/canonicalizer's own source, unmodified — nothing is duplicated
// or reimplemented here, unlike the deliberate pae() duplication below.
import { canonicalBytes } from '../canonicalizer/src/index.ts'

// The payloadTypes this verifier accepts. A local copy, not an import: this
// file must not depend on @mcpcheckup/attestation-schema (see the header).
// verify-attestation.test.mjs pins this list against that package's list, so
// the two cannot drift apart unnoticed. An envelope with any other payloadType is refused
// before any signature work.
const ALLOWED_PAYLOAD_TYPES = Object.freeze([
  'application/vnd.mcpcheckup.attestation+json;version=0.1',
  'application/vnd.mcpcheckup.attestation+json;version=0.2',
  'application/vnd.mcpcheckup.attestation+json;version=0.3',
])

// DER prefix of an Ed25519 SubjectPublicKeyInfo; the 32 key bytes follow it.
const ED25519_SPKI_HEADER = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])
const ED25519_SPKI_LENGTH = 44

// Bounds on the key document: a real one holds a handful of keys.
const MAX_KEYS_FILE_BYTES = 1024 * 1024
const MAX_KEYS = 1000

function printUsageAndExit(code) {
  const usage = `Usage: node packages/verifier/verify-attestation.mjs --envelope <path.json> --keys <keys.json>
       node packages/verifier/verify-attestation.mjs --envelope <path.json> --pubkey <spki-base64-string-or-path>

  --envelope   path to a DSSE envelope JSON file: { payloadType, payload, signatures }
  --keys       path to the published key document, downloaded beforehand:
                 curl -fsS https://mcpcheckup.com/.well-known/mcpcheckup-keys.json -o keys.json
               Every signature's keyid must be in it, its key must not be
               revoked, and the payload's observed_at must lie within the
               key's valid_from .. valid_until (both ends inclusive).
  --pubkey     an Ed25519 public key, SPKI-encoded, base64 — either given
               directly as a string, or a path to a file containing it. Every
               signature's keyid must equal the first 16 hex characters of
               sha256 over the key's SPKI bytes.
  Give exactly one of --keys and --pubkey.

Requires Node.js 22.18 or later on the 22 line, or Node.js 24 or later.
This script imports @mcpcheckup/canonicalizer's .ts source directly and
relies on Node's unflagged native TypeScript type-stripping support to run
it, with no build step of its own.

Exit code 0 only if every signature's key passes the rules above, at least
one signature verifies, AND the payload bytes are exactly
@mcpcheckup/canonicalizer's canonical (nfc-jcs/v1) encoding of their
own JSON content.`
  if (code === 0) console.log(usage)
  else console.error(usage)
  process.exit(code)
}

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--envelope') out.envelope = argv[++i]
    else if (arg === '--pubkey') out.pubkey = argv[++i]
    else if (arg === '--keys') out.keys = argv[++i]
    else if (arg === '--help' || arg === '-h') out.help = true
    else {
      console.error(`unrecognized argument: ${arg}`)
      printUsageAndExit(1)
    }
  }
  return out
}

/**
 * PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
 * LEN(s) = ASCII decimal encoding of the byte length of s, no leading zeros.
 *
 * Written independently from packages/attestation-schema/src/dsse.ts's own
 * pae() — see this file's header comment for why. Both implement the same
 * public spec (secure-systems-lab/dsse's PAE), so they must compute
 * identical bytes for identical input by construction; that fact is exactly
 * what makes this a meaningful independent check instead of a formality.
 */
function pae(payloadType, bodyBytes) {
  const enc = new TextEncoder()
  const typeBytes = enc.encode(payloadType)
  const parts = [
    enc.encode('DSSEv1'), enc.encode(' '), enc.encode(String(typeBytes.length)), enc.encode(' '),
    typeBytes, enc.encode(' '), enc.encode(String(bodyBytes.length)), enc.encode(' '), bodyBytes,
  ]
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) { out.set(p, offset); offset += p.length }
  return out
}

function resolvePubkeyBase64(pubkeyArg) {
  if (existsSync(pubkeyArg)) {
    return readFileSync(pubkeyArg, 'utf8').trim()
  }
  return pubkeyArg.trim()
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')
}

/** The keyid every signature must carry: the first 16 hex characters of sha256 over the SPKI bytes. */
async function keyIdOfSpki(spkiBytes) {
  return (await sha256Hex(spkiBytes)).slice(0, 16)
}

const RFC3339_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/

/**
 * An RFC 3339 UTC time ("...Z" only) as epoch milliseconds, or null when the
 * text is not one or names a day that does not exist (month 13, 31 February,
 * second 60). Every time comparison in this file is on these integers, at
 * millisecond precision; digits beyond the third fractional digit are dropped.
 */
function parseInstantUtc(text) {
  if (typeof text !== 'string') return null
  const m = RFC3339_UTC.exec(text)
  if (m === null) return null
  const [, y, mo, d, h, mi, s, frac] = m
  const ms = frac === undefined ? 0 : Number(frac.slice(0, 3).padEnd(3, '0'))
  const t = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms)
  const back = new Date(t)
  if (
    back.getUTCFullYear() !== Number(y) || back.getUTCMonth() !== Number(mo) - 1 || back.getUTCDate() !== Number(d) ||
    back.getUTCHours() !== Number(h) || back.getUTCMinutes() !== Number(mi) || back.getUTCSeconds() !== Number(s)
  ) return null
  return t
}

/**
 * Validates the published key document and returns its keys by key_id.
 * Throws an Error whose message is the reason; there is no lenient mode and no
 * key is ever skipped: one bad entry makes the whole document unusable.
 *
 * Shape: { format_version: 1, keys: [ { key_id, algorithm: "Ed25519", spki
 * (standard base64 of the 44-byte DER SPKI), spki_sha256 (lowercase hex),
 * valid_from, valid_until, revoked_at } ] }. Times are RFC 3339 UTC ("Z");
 * valid_until and revoked_at are always present, null when empty.
 */
async function loadKeyDocument(path) {
  let size
  try { size = statSync(path).size } catch (e) {
    throw new Error(`cannot read keys file ${path}: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (size > MAX_KEYS_FILE_BYTES) throw new Error(`keys file ${path} is ${size} bytes; the limit is ${MAX_KEYS_FILE_BYTES}`)
  let doc
  try { doc = JSON.parse(readFileSync(path, 'utf8')) } catch (e) {
    throw new Error(`keys file ${path} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`)
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) throw new Error('keys file must be a JSON object')
  if (doc.format_version !== 1) throw new Error(`keys file format_version must be 1, got ${JSON.stringify(doc.format_version)}`)
  if (!Array.isArray(doc.keys)) throw new Error('keys file must have a "keys" array')
  if (doc.keys.length > MAX_KEYS) throw new Error(`keys file lists ${doc.keys.length} keys; the limit is ${MAX_KEYS}`)

  const byId = new Map()
  for (let i = 0; i < doc.keys.length; i++) {
    const k = doc.keys[i]
    const where = `keys[${i}]`
    const fail = (why) => { throw new Error(`${where}${typeof k?.key_id === 'string' ? ` (${k.key_id})` : ''}: ${why}`) }
    if (typeof k !== 'object' || k === null || Array.isArray(k)) fail('is not an object')
    if (k.algorithm !== 'Ed25519') fail(`algorithm must be "Ed25519", got ${JSON.stringify(k.algorithm)}`)
    for (const f of ['valid_until', 'revoked_at']) {
      if (!Object.hasOwn(k, f)) fail(`field ${f} is missing (it must be present, null when empty)`)
    }
    if (typeof k.spki !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(k.spki)) fail('spki must be standard base64')
    const spkiBytes = new Uint8Array(Buffer.from(k.spki, 'base64'))
    if (Buffer.from(spkiBytes).toString('base64') !== k.spki) fail('spki is not canonical standard base64')
    if (spkiBytes.length !== ED25519_SPKI_LENGTH) fail(`spki must decode to ${ED25519_SPKI_LENGTH} bytes, got ${spkiBytes.length}`)
    if (!bytesEqual(spkiBytes.subarray(0, ED25519_SPKI_HEADER.length), ED25519_SPKI_HEADER)) fail('spki does not start with the Ed25519 SubjectPublicKeyInfo header')
    if (typeof k.spki_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(k.spki_sha256)) fail('spki_sha256 must be 64 lowercase hex characters')
    const actualSha = await sha256Hex(spkiBytes)
    if (k.spki_sha256 !== actualSha) fail('spki_sha256 is not the sha256 of the spki bytes')
    if (typeof k.key_id !== 'string' || k.key_id !== actualSha.slice(0, 16)) fail('key_id must equal the first 16 characters of spki_sha256')
    if (byId.has(k.key_id)) fail('key_id appears more than once')
    const validFrom = parseInstantUtc(k.valid_from)
    if (validFrom === null) fail('valid_from must be an RFC 3339 UTC time ending in Z')
    const validUntil = k.valid_until === null ? null : parseInstantUtc(k.valid_until)
    if (k.valid_until !== null && validUntil === null) fail('valid_until must be null or an RFC 3339 UTC time ending in Z')
    const revokedAt = k.revoked_at === null ? null : parseInstantUtc(k.revoked_at)
    if (k.revoked_at !== null && revokedAt === null) fail('revoked_at must be null or an RFC 3339 UTC time ending in Z')
    byId.set(k.key_id, { keyId: k.key_id, spkiBytes, validFrom, validUntil, revokedAt, raw: { valid_from: k.valid_from, valid_until: k.valid_until, revoked_at: k.revoked_at } })
  }
  return byId
}

/**
 * The key-window rules for one key against the payload's signed observed_at,
 * as the failure reason or null. The envelope carries no signing time, so
 * observed_at (inside the signed payload) is the one signed instant there is.
 *   - revoked_at set: always fails, whatever the time. A revoked key means a
 *     compromise: whoever holds the key can sign any observed_at they like.
 *   - observed_at before valid_from: fails.
 *   - valid_until set and observed_at after it: fails. observed_at == valid_until passes.
 *   - observed_at missing or not an RFC 3339 UTC time: fails (valid_from is always set).
 * Both ends are inclusive and compared as epoch milliseconds.
 */
function keyWindowFailure(key, observedAtMs, observedAtRaw) {
  const { raw } = key
  if (key.revokedAt !== null) {
    return `key ${key.keyId} was revoked at ${raw.revoked_at}; signatures made with a revoked key are never accepted, whatever their observed_at`
  }
  if (observedAtMs === null) {
    return `the payload's observed_at (${observedAtRaw === undefined ? 'missing' : JSON.stringify(observedAtRaw)}) is not an RFC 3339 UTC time, so it cannot be checked against key ${key.keyId}'s valid_from ${raw.valid_from}`
  }
  if (observedAtMs < key.validFrom) {
    return `observed_at ${observedAtRaw} is before key ${key.keyId}'s valid_from ${raw.valid_from}`
  }
  if (key.validUntil !== null && observedAtMs > key.validUntil) {
    return `observed_at ${observedAtRaw} is after key ${key.keyId}'s valid_until ${raw.valid_until}`
  }
  return null
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) printUsageAndExit(0)
  if (!args.envelope || (!args.pubkey && !args.keys)) {
    console.error('--envelope and one of --keys / --pubkey are required')
    printUsageAndExit(1)
  }
  if (args.pubkey && args.keys) {
    console.error('give either --keys or --pubkey, not both')
    printUsageAndExit(1)
  }

  let envelope
  try {
    const raw = readFileSync(args.envelope, 'utf8')
    envelope = JSON.parse(raw)
  } catch (error) {
    console.error(`failed to read/parse envelope file ${args.envelope}: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }

  if (
    typeof envelope !== 'object' || envelope === null ||
    typeof envelope.payloadType !== 'string' ||
    typeof envelope.payload !== 'string' ||
    !Array.isArray(envelope.signatures)
  ) {
    console.error('envelope must be a DSSE envelope: { payloadType: string, payload: string (base64), signatures: [{sig, keyid?}, ...] }')
    process.exit(1)
  }

  // Exactly one key source. keyById (--keys) maps key_id -> validated key;
  // singleKey (--pubkey) is the one given key and its derived keyid.
  let keyById = null
  let singleKey = null
  if (args.keys) {
    try {
      keyById = await loadKeyDocument(args.keys)
    } catch (error) {
      console.error(`invalid keys file: ${error instanceof Error ? error.message : String(error)}`)
      process.exit(1)
    }
  } else {
    try {
      const spkiBase64 = resolvePubkeyBase64(args.pubkey)
      const spkiBytes = new Uint8Array(Buffer.from(spkiBase64, 'base64'))
      const cryptoKey = await crypto.subtle.importKey('spki', spkiBytes, { name: 'Ed25519' }, false, ['verify'])
      singleKey = { cryptoKey, keyId: await keyIdOfSpki(spkiBytes) }
    } catch (error) {
      console.error(`failed to import public key from --pubkey ${args.pubkey}: ${error instanceof Error ? error.message : String(error)}`)
      process.exit(1)
    }
  }

  // Refuse unknown payloadTypes before any signature work.
  if (!ALLOWED_PAYLOAD_TYPES.includes(envelope.payloadType)) {
    console.log(`envelope:    ${args.envelope}`)
    console.log(`payloadType: ${envelope.payloadType}`)
    console.log(`payloadType check: FAIL (not one of the types this verifier accepts: ${ALLOWED_PAYLOAD_TYPES.join(', ')})`)
    console.log('\nRESULT: FAIL')
    console.error('verify-attestation: verification FAILED — see summary above')
    process.exitCode = 1
    return
  }

  const payloadBytes = new Uint8Array(Buffer.from(envelope.payload, 'base64'))
  const preAuth = pae(envelope.payloadType, payloadBytes)

  // Parse the payload once: --keys needs its observed_at, and step 2 reuses it.
  let parsedPayload
  let payloadParseError = null
  try {
    parsedPayload = JSON.parse(new TextDecoder().decode(payloadBytes))
  } catch (e) {
    payloadParseError = `payload bytes are not valid JSON: ${e instanceof Error ? e.message : String(e)}`
  }
  const observedAtRaw = parsedPayload !== null && typeof parsedPayload === 'object' ? parsedPayload.observed_at : undefined
  const observedAtMs = parseInstantUtc(observedAtRaw)

  const importedKeys = new Map()
  const sigResults = []
  for (let i = 0; i < envelope.signatures.length; i++) {
    const signature = envelope.signatures[i]
    const keyid = typeof signature?.keyid === 'string' ? signature.keyid : null
    const result = { index: i, keyid, ok: false, error: null, keyError: null, key: null }
    sigResults.push(result)

    let cryptoKey = null
    if (keyById !== null) {
      const key = keyid === null ? undefined : keyById.get(keyid)
      if (key === undefined) {
        result.keyError = keyid === null
          ? 'signature carries no keyid, so it cannot be looked up in the published key set'
          : `keyid ${keyid} is not in the published key set`
        continue
      }
      result.key = key
      result.keyError = keyWindowFailure(key, observedAtMs, observedAtRaw)
      if (result.keyError !== null) continue
      try {
        if (!importedKeys.has(key.keyId)) {
          importedKeys.set(key.keyId, await crypto.subtle.importKey('spki', key.spkiBytes, { name: 'Ed25519' }, false, ['verify']))
        }
        cryptoKey = importedKeys.get(key.keyId)
      } catch (e) {
        result.keyError = `cannot import key ${key.keyId}: ${e instanceof Error ? e.message : String(e)}`
        continue
      }
    } else {
      if (keyid !== singleKey.keyId) {
        result.keyError = `keyid ${keyid ?? '(none)'} does not match the given public key (its keyid is ${singleKey.keyId})`
        continue
      }
      cryptoKey = singleKey.cryptoKey
    }

    try {
      const sigBytes = new Uint8Array(Buffer.from(String(signature?.sig ?? ''), 'base64'))
      result.ok = await crypto.subtle.verify({ name: 'Ed25519' }, cryptoKey, sigBytes, preAuth)
    } catch (e) {
      result.error = e instanceof Error ? e.message : String(e)
    }
  }
  const anySignatureOk = sigResults.some((r) => r.ok)
  // A signature that names the wrong key, an unpublished key, a revoked key or
  // a key whose window does not cover observed_at fails the whole envelope,
  // even when another signature verifies: nothing is skipped silently.
  const keysOk = sigResults.every((r) => r.keyError === null)

  let canonicalOk = false
  let canonicalError = null
  if (payloadParseError !== null) {
    canonicalError = payloadParseError
  } else {
    try {
      const recomputed = canonicalBytes(parsedPayload)
      canonicalOk = bytesEqual(recomputed, payloadBytes)
      if (!canonicalOk) {
        canonicalError =
          "payload bytes parse as JSON but are not byte-identical to @mcpcheckup/canonicalizer's canonical (nfc-jcs/v1) encoding of that JSON — the payload was never actually canonical, or was tampered with in a way that still parses"
      }
    } catch (e) {
      canonicalError = `canonicalizer rejected the payload's parsed JSON: ${e instanceof Error ? e.message : String(e)}`
    }
  }

  console.log(`envelope:    ${args.envelope}`)
  console.log(`payloadType: ${envelope.payloadType}`)
  if (keyById !== null) console.log(`observed_at: ${observedAtMs === null ? '(missing or not an RFC 3339 UTC time)' : observedAtRaw}`)
  console.log(`signatures (${sigResults.length}):`)
  if (sigResults.length === 0) console.log('  (none)')
  for (const r of sigResults) {
    console.log(`  [${r.index}] keyid=${r.keyid ?? '(none)'} -> ${r.ok ? 'PASS' : 'FAIL'}${r.keyError ?? r.error ? ` (${r.keyError ?? r.error})` : ''}`)
    if (r.key !== null) {
      const show = (v) => (v === null ? '(none)' : v)
      console.log(`      key: key_id=${r.key.keyId} valid_from=${r.key.raw.valid_from} valid_until=${show(r.key.raw.valid_until)} revoked_at=${show(r.key.raw.revoked_at)}`)
    }
  }
  console.log(`key check (every signature's key must be ${keyById !== null ? 'in the published set, unrevoked and valid at observed_at' : 'the given public key'}): ${keysOk ? 'PASS' : 'FAIL'}`)
  console.log(`signature verification (>=1 of ${sigResults.length} must pass): ${anySignatureOk ? 'PASS' : 'FAIL'}`)
  console.log(`canonical-bytes comparison: ${canonicalOk ? 'PASS' : 'FAIL'}${canonicalError ? ` (${canonicalError})` : ''}`)

  const overallOk = keysOk && anySignatureOk && canonicalOk
  console.log(`\nRESULT: ${overallOk ? 'PASS' : 'FAIL'}`)

  if (!overallOk) {
    console.error('verify-attestation: verification FAILED — see summary above')
  }
  // process.exitCode (not process.exit()) so the process ends naturally once
  // stdout has actually finished flushing — process.exit() right after a
  // console.log can truncate piped output (this script is meant to be run
  // under `| tee` by a human collecting output).
  process.exitCode = overallOk ? 0 : 1
}

await main()
