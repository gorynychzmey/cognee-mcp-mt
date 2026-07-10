# SPEC: cognee-mcp-mt — multi-tenant cognee-MCP fork with built-in OAuth 2.1

> **Status:** specification for a new project. Written from an analysis of a live
> self-hosted cognee deployment and the sources of the `cognee/cognee-mcp:main`
> image (July 2026).

---

## 1. In one line

Fork the upstream `cognee-mcp` so that **one MCP instance** serves **multiple users**
(each with their own graph/datasets) and **acts as its own** OAuth 2.1 authorization
server for Claude.ai — i.e. **without** an external `mcp-auth-proxy` and **without** a
separate wrapper. Target result: **one container** instead of three.

---

## 2. Motivation and goal

### What we want
- **Minimum:** separate private graphs for two users (from different Google Workspace
  domains) — each accesses cognee from their own Claude.ai and sees only their own data.
- **Maximum:** personal graphs + an optional shared graph with ACL.
- Access from **cloud Claude.ai** as an MCP connector (OAuth 2.1 / DCR / PKCE).
- **A single service**, minimum moving parts, cognee-API stays vanilla.

### The key requirement that is missing today
> **One MCP instance → N users, identity resolved per-request.**

This is exactly what neither the current setup nor off-the-shelf proxies solve.

---

## 3. How it works TODAY (baseline)

A typical self-hosted cognee deployment. In brief:

- **Application host** (`host-app`). Systemd service `cognee.service` = podman kube pod.
- **Pod of 3 containers:**
  | Container | Image | Port | Role |
  |---|---|---|---|
  | `cognee-cognee-api` | `cognee/cognee:main` (v1.2.2) | :8000 (host) | cognee FastAPI, real multi-user (fastapi_users) |
  | `cognee-cognee-mcp` | `cognee/cognee-mcp:main` (v1.1.0, `--no-migration`) | :8001 (pod-only) | MCP server |
  | `cognee-mcp-auth-proxy` | `ghcr.io/sigbit/mcp-auth-proxy:latest` | :8002 (host) | OAuth 2.1 gateway in front of MCP |
- **Storage:** a single Postgres (on a separate `host-db`) — relational + pgvector +
  graph (`GRAPH_DATABASE_PROVIDER=postgres`, tables `graph_node`/`graph_edge`).
- **LLM:** extractor via a LiteLLM-compatible proxy (provider prefix required);
  embedder `bge-m3` via Ollama.
- **Access from Claude.ai:** `https://mcp.example.tld/mcp`
  → OAuth2.1/PKCE + Google Workspace allowlist (`GOOGLE_ALLOWED_WORKSPACES=<domains>`)
  → reverse proxy (Traefik) → mcp-auth-proxy :8002 → cognee-MCP :8001.

### Why it is single-user today
MCP runs in **direct mode** (no `--api-url`). In this mode identity comes from
`get_default_user()` — a single default user for the whole process. cognee ACL
(`ENABLE_BACKEND_ACCESS_CONTROL`) is deliberately off. Whoever comes through the
proxy allowlist, inside cognee they all become the same default user, one shared graph.

---

## 4. Source analysis: what's already there, what's missing

Sources extracted from the `cognee/cognee-mcp:main` image (digest `14732afe08f0`,
~2 weeks old as of July 2026). Key files: `src/server.py` (~2019 lines),
`src/cognee_client.py` (610 lines).

### 4.1 The multi-user backbone is ALREADY built in — it's the API mode
MCP has two operating modes (`CogneeClient`, `cognee_client.py`):
- **direct** (our current one, no `--api-url`) → direct `cognee.*` calls,
  `get_default_user()` → single-user.
- **API mode** (`--api-url http://localhost:8000 --api-token <JWT>`) → every method
  (`add`/`search`/`cognify`/`remember`/…) makes an HTTP call to cognee-API and **puts
  the token in a header**. cognee-API resolves the user from the token → **multi-user
  by design**.

Headers are built like this (`cognee_client.py:70-85`):
```python
def _get_headers(self, include_content_type=True):
    headers = {...}
    if self.api_token:
        if self.tenant_id:                 # cloud/tenant mode
            headers["X-Api-Key"] = self.api_token
            headers["X-Tenant-Id"] = self.tenant_id
        else:                              # self-hosted
            headers["Authorization"] = f"Bearer {self.api_token}"
    return headers
```

### 4.2 The one real blocker — a static token
The token is fixed ONCE at process start (`server.py:1942`):
```python
cognee_client = CogneeClient(api_url=args.api_url, api_token=args.api_token)
```
`api_token` comes from a CLI argument and lives for the whole process → "token is
static per instance" → one instance = one user. **This is what must become per-request.**

### 4.3 MCP ALREADY reads the per-request context
In two places (`server.py:1714`, `1738`) the code already calls `request_ctx.get()`
and reads `clientInfo.name` (for agent scoping: `cursor_memory`, `claude_code_memory`,
etc.). So the machinery to reach the incoming request context **exists and is in use** —
all that's missing is reaching from `request_ctx` to the HTTP headers and injecting the
caller's token.

### 4.4 The SDK already does OAuth 2.1 — it's the official `mcp` SDK
Upstream MCP is built on **`mcp.server.FastMCP`, `mcp` == 1.27.0** (NOT the separate
`fastmcp` package by jlowin, but the OAuth-capable official SDK). Verified against the
image's venv files:

- `FastMCP.__init__` **natively accepts** `auth_server_provider`, `token_verifier`,
  `AuthSettings` — the OAuth attachment point is already in the constructor.
- `mcp/server/auth/handlers/` contains the **full set of OAuth endpoints**:
  `/authorize`, `/token`, **`/register` (DCR)**, `/revoke`, plus
  `.well-known/oauth-authorization-server` and `.well-known/oauth-protected-resource`
  (RFC 9728).
- `AuthSettings` → `ClientRegistrationOptions(enabled=True)` = **Dynamic Client
  Registration**, exactly what Claude.ai requires and what bare cognee doesn't offer.
- The `OAuthAuthorizationServerProvider` interface (Protocol, `mcp/server/auth/provider.py`)
  — ~10 methods to implement: `get_client`, `register_client`, `authorize`,
  `load_authorization_code`, `exchange_authorization_code`, `load_refresh_token`,
  `exchange_refresh_token`, `load_access_token`, `revoke_token`.

**Conclusion:** `mcp-auth-proxy` can be dropped entirely — the SDK can do the
DCR/PKCE front + Google delegation itself; we only need to implement a provider over
Google (the same "OAuth Proxy → Google" pattern the sigbit proxy does, but inside the
MCP process).

### 4.5 The tools are already implemented (no need to rewrite)
`server.py` already has 11 tools, including: `cognify_file`, `create_dataset_json`,
`list_datasets_json`, `list_dataset_data_json`, `get_client_info_json`,
`visualize_graph_ui`, `upload_file_ui`, `open_cognee_workspace`, `coding_agent_rules`,
plus v2: `remember`/`recall`/`forget`/`improve`/`search`. All accept `dataset_name`/
`datasets` → addressing a specific graph is already possible.

### 4.6 A cognee-API fact to account for
cognee-API (`get_authenticated_user`) trusts **only a real JWT/api-key** via
`fastapi_users` (crypto/DB). There is **NO** "trust an external `X-User-Id`" branch on
the server (the `X-User-Id` in the cognee CLI is a client-side stub for an honour
mechanism that doesn't exist server-side). So identity must be introduced into cognee
in a way it considers **valid**: either a per-user api-key, or a custom JWT backend in
cognee that trusts our RS256 JWT with `sub=email` (`JWTStrategy.read_token` resolves
identity only from the `sub` claim).

---

## 5. Target architecture (MVP = everything at once)

```
Claude.ai (user A)  ─┐
Claude.ai (user B)  ─┴─→ reverse-proxy ─→ cognee-mcp-mt  ─→ cognee-API (:8000, multi-user JWT)
                                          (ONE container)       └→ Postgres (host-db)
```

`cognee-mcp-mt` combines in one process what used to be three components:

1. **OAuth 2.1 AS + DCR** (built-in SDK mechanism; we implement
   `OAuthAuthorizationServerProvider` delegating to Google + a Workspace allowlist).
   → **replaces `mcp-auth-proxy`**.
2. **Per-request token** (a contextvar instead of the static `api_token` in `CogneeClient`).
   → **gives multi-tenancy**.
3. **Identity bridge:** `authorize`/`exchange` issue a token from which the per-request
   layer extracts `sub=email` and forms a JWT/api-key valid for cognee-API.

> Note: this is exactly the "FastMCP wrapper" discussed earlier — but not as a separate
> service, rather **inside the forked upstream MCP**. Tools don't need to be generated
> via `from_openapi` — they're already in `server.py`.

---

## 6. Scope of work (what exactly changes in the fork)

| # | Component | File(s) | What we do | Estimate |
|---|---|---|---|---|
| 1 | Per-request token | `cognee_client.py`, `server.py` | `api_token` → read from a contextvar on every `_get_headers()`; keep the shared httpx client (auth-stateless) | tens of lines |
| 2 | Identity-extraction middleware | `server.py` (`run_http_with_cors`, ~:187) | on each incoming request pull `Authorization: Bearer <jwt>` → put into a contextvar | tens of lines |
| 3 | OAuth 2.1 AS | new module + `FastMCP(auth_server_provider=…, auth=AuthSettings(...))` | implement `OAuthAuthorizationServerProvider` with Google delegation, a store for clients/codes/tokens, Workspace allowlist | **the main part, hundreds of lines, but a bounded interface (~10 methods)** |
| 4 | Identity bridge into cognee | option A: per-user api-key (set up once) **or** option B: a custom `fastapi_users` JWT backend in cognee trusting our RS256 JWT (`sub=email`) | decide during design; B is cleaner (no api-keys), but patches cognee | medium |

**Overall estimate:** comparable in effort to writing a separate FastMCP wrapper, but
the fork is cheaper to write (tools and modes already exist) and costlier to maintain
(third-party, actively updated code).

---

## 7. Upstream strategy (removes the rebase burden)

Idea: if our code is accepted into `cognee/cognee-mcp` main — nothing to rebase, we
live on upstream. Signs a PR would "land":
- They've **already invested in the multi-user backbone** (API mode, `X-Api-Key`/
  `X-Tenant-Id`, tenant-URL parsing) — groundwork for their cloud/tenant offering;
  per-request identity is a direct continuation of their own vector.
- They **already use** `request_ctx` and an OAuth-capable SDK.
- A comment in their code (`server.py:1846`): *"Operators exposing this tool over
  HTTP/SSE must enforce auth at the transport layer"* — they know about the gap and
  left it external.

**Tactic — two separate PRs (not one giant one):**
- **PR-1: per-request token in API mode** (items 1-2). Small, uncontroversial, a clean
  multi-tenancy improvement. High chance of merge.
- **PR-2: built-in OAuth 2.1 AS** (item 3). Bigger and more contentious — they may
  prefer keeping OAuth external. If not accepted — it stays our isolated fork layer;
  rebasing PR-2 on top of a merged PR-1 is trivial.

Even in the worst case the rebase burden shrinks from "the whole fork" to "just the
OAuth layer".

**Practical implication for code structure:** keep the per-request changes (PR-1) and
the OAuth layer (PR-2) in separate modules/commits from the start, so PRs split cleanly.

---

## 8. Open questions / decisions to make at the start

1. **Identity bridge — option A (per-user api-key) or B (custom JWT backend in cognee)?**
   B is more elegant (no api-keys, cognee trusts our `sub=email` token), but patches
   cognee → its own drift risk. A is simpler but requires a per-user api-key.
2. **OAuth state storage** (clients after DCR, codes, refresh tokens): in-memory at the
   start vs. persistent (the same Postgres)? Restarts need persistence.
3. **Version drift:** the MCP image lags (v1.1.0) behind cognee-API (v1.2.2) and shares
   one DB; the API owns the schema, MCP starts with `--no-migration`. The fork must
   preserve this separation.
4. **The reverse proxy may live on a separate host** — collapsing to 1 container changes
   the router's upstream port (was :8002 proxy → becomes the MCP's own port).
5. **Formats:** pdf/txt/md/csv/json/yaml work; pptx/docx (needs `cognee[docling]`) and
   html (`bs4`) aren't installed — out of MVP scope.

---

## 9. Next steps

1. `git init`, vendor the `cognee/cognee-mcp:main` sources as the fork base (pin the
   upstream digest `14732afe08f0` and version `mcp==1.27.0`).
2. Implement PR-1 (per-request token) + a local run in API mode against cognee-API.
3. Implement PR-2 (OAuth 2.1 AS + Google delegation + Workspace allowlist).
4. Decide the identity bridge (option A/B), wire the end-to-end path
   Claude.ai → cognee-mcp-mt → cognee-API.
5. Build the image, update the pod's kube manifest (drop `mcp-auth-proxy`, repoint the
   reverse proxy).
6. E2E check with two accounts (user A / user B) → separate graphs.
7. Prepare upstream PR-1, then PR-2.

---

## 10. References and context sources

- **Fork-base sources:** image `docker.io/cognee/cognee-mcp:main` (digest
  `14732afe08f0`), files `src/server.py`, `src/cognee_client.py`.
- **SDK:** `mcp==1.27.0`, module `mcp/server/auth/` (handlers: authorize/token/register/
  revoke/metadata; provider.py — the `OAuthAuthorizationServerProvider` interface).

> Internal deployment notes (specific hosts, IPs, manifests) are kept in private infra
> documentation, not in this public repository.
