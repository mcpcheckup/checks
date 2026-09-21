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

This repository is published as snapshots of a private monorepo. Apart from the first commit, which added the license, each commit here is one snapshot of the `packages/` directories listed below, at the same paths and as the same git tree objects they have in the monorepo. No commit of the monorepo is included in this history.

## Packages

- `packages/checks`: the check definitions (`checks.json`) and the code that runs them.
- `packages/canonicalizer`: NFC normalization plus RFC 8785 (JCS) canonicalization, and the SHA-256 fingerprints computed over it.
- `packages/attestation-schema`: the JSON Schema and TypeScript types of a signed attestation payload.
- `packages/ssrf-guard`: the rules that decide which URLs the prober may fetch, re-checked on every redirect.
- `packages/fixtures`: simulated MCP servers, each declaring the results the checks must produce against it.
- `packages/verifier`: an offline verifier for signed attestation envelopes.

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

```sh
node packages/verifier/verify-attestation.mjs --envelope <file> --pubkey <key>
```

This needs Node.js 22.18 or later on the 22 line, or Node.js 24 or later; there is no install step.
`<key>` is the
Ed25519 public key, SPKI-encoded and base64, or a path to a file containing
it. The signing public key is not published yet.

## License

Copyright 2026 Clear Data Decisions, LLC.

Apache License 2.0. See [LICENSE](LICENSE).

The RFC 8785 test fixtures under `packages/canonicalizer/test/fixtures/rfc8785/` are copied unchanged from `cyberphone/json-canonicalization`, Copyright 2018 Anders Rundgren, Apache License 2.0; see the `UPSTREAM_README.md` in that directory.

## Issues

Issues are welcome. This repository is published as snapshots, so pull
requests are not merged here.
