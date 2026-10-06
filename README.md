# mcpcheckup/checks

[![MCP Checkup](https://mcpcheckup.com/badge/mcpcheckup/mcp.svg)](https://mcpcheckup.com/check/mcpcheckup/mcp)

## Use MCP Checkup from your agent

MCP Checkup watches public MCP servers and publishes what it observed: reachability, protocol revision, tool and schema fingerprints, publicly observable auth metadata, and tool-description hygiene signals. Every check is reported as VERIFIED, FAILED, OBSERVED_RISK or UNVERIFIED; results are never combined into one number or a verdict.

The directory is at [mcpcheckup.com/servers](https://mcpcheckup.com/servers). Agents can query the same data over MCP, with no authentication:

```json
{ "mcpServers": { "mcpcheckup": { "type": "http", "url": "https://mcpcheckup.com/mcp" } } }
```

Listed in the official MCP Registry as `com.mcpcheckup/mcp`.

Tools: `check_mcps`, `get_mcp_report`, `get_mcp_history`, `get_attestation`, `search_mcps`, and `request_check` (the only one that contacts a third-party server). The endpoint is rate limited; a 429 response carries Retry-After.

Maintainers: your server may already have a report page. See [mcpcheckup.com/maintainers](https://mcpcheckup.com/maintainers) for what claiming changes, and [mcpcheckup.com/probe](https://mcpcheckup.com/probe) for our user agent, request budget, and how to opt out.

The rest of this README is about checking our work: recomputing `suite_digest` and verifying a signed attestation offline.

The check suite behind [mcpcheckup.com](https://mcpcheckup.com): the
protocol-contract checks MCP Checkup runs against MCP servers, the
canonicalizer and schema its signed attestations use, and an offline verifier
for those attestations.

This repository is published as snapshots of a private monorepo. Apart from the first commit, which added the license, each commit here is one snapshot of the `packages/` directories listed below, at the same paths and as the same git tree objects they have in the monorepo. No commit of the monorepo is included in this history. The `keys/` directory holds a copy of the published key document; see "Verifying a signed attestation" below.

## Packages

- `packages/checks`: the check definitions (`checks.json`) and the code that runs them.
- `packages/canonicalizer`: NFC normalization plus RFC 8785 (JCS) canonicalization, and the SHA-256 fingerprints computed over it.
- `packages/attestation-schema`: the JSON Schema and TypeScript types of a signed attestation payload.
- `packages/ssrf-guard`: the rules that decide which URLs the prober may fetch, re-checked on every redirect.
- `packages/fixtures`: simulated MCP servers, each declaring the results the checks must produce against it.
- `packages/verifier`: an offline verifier for signed attestation envelopes.
- `packages/toolset-diff`: deterministic per-tool comparison of two MCP tool lists: tools added, removed, description changed, input schema changed.

## Recomputing `suite_digest`

An attestation payload names the code that produced it with `suite_commit` and
`suite_digest`. In a clone of this repository, replace `<commit>` with the
payload's `suite_commit` and run:

```sh
git ls-tree -r -z --full-tree <commit> -- packages/checks | openssl dgst -sha512 -binary | openssl base64 -A
```

Prefix the output with `sha512-` and compare it with the payload's
`suite_digest`. The command reads committed git objects only, so the result
does not depend on your line endings, your platform or any build step.

This works only when `suite_commit` is a commit in this repository.
A payload that carries a `suite_commit` but was signed before the probe began naming commits of this repository names a commit of the private monorepo, which is not available here.

## Verifying a signed attestation

The published key document is available from two places:

- the live document at `https://mcpcheckup.com/.well-known/mcpcheckup-keys.json`;
- the copy in this repository, `keys/mcpcheckup-keys.json`.

With the live document:

```sh
curl -fsS https://mcpcheckup.com/.well-known/mcpcheckup-keys.json -o keys.json
node packages/verifier/verify-attestation.mjs --envelope <file> --keys keys.json
```

Offline, with the copy in this repository:

```sh
node packages/verifier/verify-attestation.mjs --envelope <file> --keys keys/mcpcheckup-keys.json
```

This needs Node.js 22.18 or later on the 22 line, or Node.js 24 or later; there is no install step.
`keys.json` is the published key document. The verifier makes no network request itself.
For every signature it checks that the `keyid` is in the document, that the key is not
revoked, and that the payload's `observed_at` lies within the key's `valid_from` and
`valid_until` (both ends inclusive). It also rejects a `payloadType` it does not know.
`--pubkey <key>` checks against one Ed25519 public key, SPKI-encoded and base64 (or a
path to a file containing it), and requires every `keyid` to equal the first 16 hex
characters of sha256 over that key's SPKI bytes.

### Comparing the two copies

The copy in this repository is written from the same key list the live document serves. When a key is added, retired or revoked, the copy is regenerated and published with the next snapshot, so until then the live document can be newer than the copy in your clone. To compare them:

```sh
curl -fsS https://mcpcheckup.com/.well-known/mcpcheckup-keys.json | cmp - keys/mcpcheckup-keys.json
```

`cmp` prints nothing and exits 0 when the two are byte for byte the same. If it reports a difference, the two are not the same list. Update your clone first, since the live document changes before the snapshot does. If a difference remains, look at what differs: a key that appears, or gains a `valid_until` or `revoked_at`, only in the live document is a change the next snapshot will carry. Any other difference is worth reporting; see [SECURITY.md](SECURITY.md) for how.

## License

Copyright 2026 Clear Data Decisions, LLC.

Apache License 2.0. See [LICENSE](LICENSE).

The RFC 8785 test fixtures under `packages/canonicalizer/test/fixtures/rfc8785/` are copied unchanged from `cyberphone/json-canonicalization`, Copyright 2018 Anders Rundgren, Apache License 2.0; see the `UPSTREAM_README.md` in that directory.

## Issues

Issues are welcome. This repository is published as snapshots, so pull
requests are not merged here.
