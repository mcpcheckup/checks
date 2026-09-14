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
 *   node packages/verifier/verify-attestation.mjs --envelope <path-to-envelope.json> --pubkey <spki-base64-string-or-path>
 *
 * --pubkey accepts either a raw base64 SPKI string, or a path to a file
 * whose entire contents (trimmed) is that string — whichever is more
 * convenient for whoever is running this by hand.
 *
 * Checks performed, in order (exit code 0 only if both pass):
 *   1. At least one signature in envelope.signatures verifies, under the
 *      given public key, over PAE(envelope.payloadType, base64-decoded
 *      payload) — DSSE's own "at least one signature" semantics.
 *   2. The payload bytes are themselves exactly nfc-jcs/v1's canonical
 *      encoding (via @mcpcheckup/canonicalizer's canonicalBytes) of the
 *      JSON they parse to. A payload that is valid JSON, correctly signed,
 *      but not byte-identical to its own canonical form is still a
 *      reportable finding: either `payload.canonicalization` was never
 *      actually true, or the payload was altered in a way that happens to
 *      still parse as the same JSON.
 *
 * This script never writes any file — it only reads the envelope (and,
 * optionally, the pubkey file) and prints a summary to stdout/stderr.
 */
import { readFileSync, existsSync } from 'node:fs'

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

function printUsageAndExit(code) {
  const usage = `Usage: node packages/verifier/verify-attestation.mjs --envelope <path.json> --pubkey <spki-base64-string-or-path>

  --envelope   path to a DSSE envelope JSON file: { payloadType, payload, signatures }
  --pubkey     an Ed25519 public key, SPKI-encoded, base64 — either given
               directly as a string, or a path to a file containing it

Requires Node.js >= 22.18 or >= 24 — this script imports
@mcpcheckup/canonicalizer's .ts source directly and relies on Node's
unflagged native TypeScript type-stripping support to run it, with no build
step of its own.

Exit code 0 only if at least one signature verifies AND the payload bytes are
exactly @mcpcheckup/canonicalizer's canonical (nfc-jcs/v1) encoding of their
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

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) printUsageAndExit(0)
  if (!args.envelope || !args.pubkey) {
    console.error('both --envelope and --pubkey are required')
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

  let publicKey
  try {
    const spkiBase64 = resolvePubkeyBase64(args.pubkey)
    const spkiBytes = new Uint8Array(Buffer.from(spkiBase64, 'base64'))
    publicKey = await crypto.subtle.importKey('spki', spkiBytes, { name: 'Ed25519' }, false, ['verify'])
  } catch (error) {
    console.error(`failed to import public key from --pubkey ${args.pubkey}: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }

  const payloadBytes = new Uint8Array(Buffer.from(envelope.payload, 'base64'))
  const preAuth = pae(envelope.payloadType, payloadBytes)

  const sigResults = []
  for (let i = 0; i < envelope.signatures.length; i++) {
    const signature = envelope.signatures[i]
    let ok = false
    let error = null
    try {
      const sigBytes = new Uint8Array(Buffer.from(String(signature?.sig ?? ''), 'base64'))
      ok = await crypto.subtle.verify({ name: 'Ed25519' }, publicKey, sigBytes, preAuth)
    } catch (e) {
      error = e instanceof Error ? e.message : String(e)
    }
    sigResults.push({ index: i, keyid: signature?.keyid ?? null, ok, error })
  }
  const anySignatureOk = sigResults.some((r) => r.ok)

  let canonicalOk = false
  let canonicalError = null
  try {
    const parsedPayload = JSON.parse(new TextDecoder().decode(payloadBytes))
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
  } catch (e) {
    canonicalError = `payload bytes are not valid JSON: ${e instanceof Error ? e.message : String(e)}`
  }

  console.log(`envelope:    ${args.envelope}`)
  console.log(`payloadType: ${envelope.payloadType}`)
  console.log(`signatures (${sigResults.length}):`)
  if (sigResults.length === 0) console.log('  (none)')
  for (const r of sigResults) {
    console.log(`  [${r.index}] keyid=${r.keyid ?? '(none)'} -> ${r.ok ? 'PASS' : 'FAIL'}${r.error ? ` (${r.error})` : ''}`)
  }
  console.log(`signature verification (>=1 of ${sigResults.length} must pass): ${anySignatureOk ? 'PASS' : 'FAIL'}`)
  console.log(`canonical-bytes comparison: ${canonicalOk ? 'PASS' : 'FAIL'}${canonicalError ? ` (${canonicalError})` : ''}`)

  const overallOk = anySignatureOk && canonicalOk
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
