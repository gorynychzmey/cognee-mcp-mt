# cognee-mcp-mt

Multi-tenant fork of [cognee-mcp](https://github.com/topoteretes/cognee) with a
built-in OAuth 2.1 authorization server for Claude.ai. Goal: **one MCP instance →
N users** (each with their own graph), where the server acts as its own OAuth 2.1
authorization server — **without** an external `mcp-auth-proxy` and without a
separate wrapper. Result: one container instead of three.

## Documents
- **[SPEC.md](SPEC.md)** — full specification: motivation, source analysis (what's
  already there / what's missing), target architecture, scope of work, upstream
  strategy, open questions, steps.
- **[UPSTREAM.md](UPSTREAM.md)** — fork-base provenance (image, digest, SDK version)
  and the vendoring rule.

## Layout
```
upstream/     unmodified fork base (from the cognee/cognee-mcp:main image)
SPEC.md       project specification
UPSTREAM.md   base provenance
```

## Status
Bootstrap. Fork code not written yet — spec and vendored base are in place.
Next step — PR-1 (per-request token), see SPEC.md §9.

## Context
Grew out of a practical need: give several users access to a single self-hosted
cognee from cloud Claude.ai with per-user graph isolation. Fork tracking lives in
beads in this repo (`bd list`).
