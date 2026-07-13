# Черновики PR в topoteretes/cognee (база: dev)

> Их шаблон требует: Description (человеческий!), Acceptance Criteria, Type of Change,
> скриншот прохождения тестов, чеклист. Ниже — фактологическая основа; перед отправкой
> отредактируй своими словами.

---

## PR-0 — ветка `fix/mcp-dockerfile-layer-dedup`

> **SUBMITTED:** https://github.com/topoteretes/cognee/pull/4045 (2026-07-13)

**Title:** fix(cognee-mcp): image is twice its content size — hand /app ownership to COPY --chown

**Description (основа):**
The cognee-mcp image is ~18GB while its filesystem holds ~8.6GB. The final stage
COPYs /app (~8.6GB) and then runs a separate `chown -R cognee:cognee /app`:
overlayfs materialises a second full copy of the tree in the chown layer.

Fix: create the user **before** the COPY, hand ownership to `COPY --chown`, and keep a
non-recursive `chown` of the still-empty WORKDIR — /app doubles as HOME, so the
runtime user must be able to write dotfiles/caches there (Kuzu extension cache).

Measured on podman: 18GB -> 9.12GB, one 8.9GB layer instead of two; container
still runs as uid 1000 `cognee`; /app writable; MCP smoke test (health,
.well-known, tool call) runs green.

**Acceptance criteria:** image size halves; `podman history` shows a single big
layer; container starts as non-root `cognee`; /app writable as HOME.

**Type:** Bug fix.

---

## PR-1 — ветка `feat/mcp-per-request-api-token`

> **SUBMITTED:** https://github.com/topoteretes/cognee/pull/4046 (2026-07-13)

**Title:** feat(cognee-mcp): per-request cognee-API token in API mode (multi-user)

**Description (основа):**
In API mode the client pins `--api-token` once at process start, so one MCP
instance can be used only by one cognee-API user, even though cognee-API itself is multi-user.
This PR resolves the caller's token on every request instead:

1. explicit contextvar override (`src/auth_context.py`) — a hook for auth
   layers sitting in front of the server;
2. the `Authorization: Bearer` header of the HTTP request that delivered the
   current MCP message — read via `request_ctx`, NOT via ASGI middleware:
   tool handlers run in the MCP session task, so a middleware-set contextvar
   would not propagate in stateful streamable HTTP. Both streamable-HTTP and
   SSE attach the starlette Request to `request_ctx`;
3. fallback to the static `--api-token` — existing single-user behaviour is
   unchanged (stdio always lands here).

The only production change besides the new module is `_get_headers()` in
`cognee_client.py` preferring the per-request token. Relates to the operator
note at server.py:1846 ("enforce auth at the transport layer"): with this
change, whatever the transport-layer auth passes through as a Bearer token
reaches cognee-API per caller.

**Acceptance criteria:** one API-mode instance serves two JWTs -> two cognee-API
users. Proven by the included full-stack test (real uvicorn + MCP client over
streamable HTTP, MockTransport at the cognee-API boundary): two sessions with
different Bearer tokens produce two different Authorization headers on outgoing
cognee-API calls. 11 new tests; existing suite untouched and green.

**Type:** New feature.

---

## PR-2 — ветка `feat/mcp-builtin-oauth-as` (stacked на PR-1)

> **NOT YET SUBMITTED** — ждём реакции на PR-1 (#4046), затем отправляем (тактика SPEC §7).

**Title:** feat(cognee-mcp): built-in OAuth 2.1 AS (Google login) + cognee-API identity bridge

**Description (основа):**
MCP clients that require OAuth 2.1 with DCR (f.e. Claude.ai web/mobile connectors)
currently need an external auth proxy in front of cognee-mcp, and even then all
users collapse into one cognee identity. This PR makes the MCP server itself an
OAuth 2.1 AS using the SDK's native `auth_server_provider` support, and bridges
the authenticated identity to cognee-API — each end user gets their own cognee
user and private datasets. Off by default (`MCP_OAUTH_ENABLED=true` to enable);
zero behaviour change when disabled.

- `oauth_provider.py` — `OAuthAuthorizationServerProvider` delegating login to
  Google: DCR, PKCE (SDK-verified), single-use codes, refresh rotation,
  closed-by-default allowlist (Workspace `hd` claim / email domain / exact email).
- `oauth_store.py` — persistent clients/codes/tokens (SQLAlchemy async; sqlite
  file by default, Postgres via `MCP_OAUTH_DB_URL`); token values stored only as
  sha256 hashes.
- `identity_bridge.py` — email -> cognee user: auto-provisions via the stock
  `/api/v1/auth/register`, mints fastapi_users-compatible HS256 JWTs with the
  shared `FASTAPI_USERS_JWT_SECRET`; cognee-API stays completely untouched.
- `auth_context.py` — the exchanged cognee token rides the SDK AccessToken in
  ASGI scope["user"] (duck-typed) and precedes the raw Bearer header.
- `server.py` — ~30 lines of wiring behind the env flag.

Deployed and verified on a self-hosted cognee: Claude.ai connects directly
(DCR/PKCE/Google), two Google users -> two cognee users -> disjoint datasets,
auth proxy container removed.

**Acceptance criteria:** with OAuth disabled, the full existing suite passes
unchanged. With it enabled: .well-known metadata served, /mcp Bearer-gated
(401 without token), full flow DCR -> authorize -> Google -> callback -> token
(PKCE) -> authenticated tool call covered by an e2e test with a fake Google;
compatibility of minted JWTs proven against the real fastapi_users
JWTStrategy.read_token; opt-in Postgres store tests (TEST_PG_DSN).

**Type:** New feature.

**Note for reviewers:** stacked on the per-request-token PR; only the last
commit is new relative to it.
