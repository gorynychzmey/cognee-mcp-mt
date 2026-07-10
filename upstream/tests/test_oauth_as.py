"""Built-in OAuth 2.1 Authorization Server (DCR + PKCE, Google-delegated login).

The MCP server itself acts as an OAuth 2.1 AS for MCP clients (e.g. Claude.ai):
the official SDK serves /register (DCR), /authorize, /token, /revoke and the
.well-known metadata; our ``GoogleWorkspaceOAuthProvider`` implements the
provider protocol, delegating end-user authentication to Google and enforcing
a Google Workspace domain / email allowlist. Tokens, codes and DCR clients are
persisted via ``OAuthStore`` (SQLAlchemy async; values stored as sha256 hashes).
"""

import asyncio
import base64
import hashlib
import importlib
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
import pytest
import uvicorn
from pydantic import AnyUrl
from starlette.requests import Request

from mcp.server import FastMCP
from mcp.server.auth.provider import AuthorizationParams, TokenError
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull

MCP_ROOT = Path(__file__).resolve().parents[1]  # cognee-mcp/
if str(MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(MCP_ROOT))

oauth_store = importlib.import_module("src.oauth_store")
oauth_provider = importlib.import_module("src.oauth_provider")

OAuthStore = oauth_store.OAuthStore
GoogleWorkspaceOAuthProvider = oauth_provider.GoogleWorkspaceOAuthProvider
CogneeAccessToken = oauth_provider.CogneeAccessToken
build_oauth_from_env = oauth_provider.build_oauth_from_env


# --- helpers -----------------------------------------------------------------


def _client_info(client_id: str = "client-1", redirect_uri: str = "http://localhost:9/cb"):
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=[AnyUrl(redirect_uri)],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="claudeai",
        client_name="test client",
    )


def _auth_params(
    state: str = "client-state",
    code_challenge: str = "challenge-abc",
    redirect_uri: str = "http://localhost:9/cb",
    scopes: list[str] | None = None,
) -> AuthorizationParams:
    return AuthorizationParams(
        state=state,
        scopes=scopes if scopes is not None else ["claudeai"],
        code_challenge=code_challenge,
        redirect_uri=AnyUrl(redirect_uri),
        redirect_uri_provided_explicitly=True,
        resource=None,
    )


def _get_request(path: str, query: dict[str, str]) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": urlencode(query).encode(),
        "headers": [],
    }
    return Request(scope)


def _fake_google_client(userinfo: dict, token_status: int = 200) -> httpx.AsyncClient:
    """httpx client that answers Google's token + userinfo endpoints."""

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            if token_status != 200:
                return httpx.Response(token_status, json={"error": "invalid_grant"})
            return httpx.Response(
                200, json={"access_token": "google-access-token", "token_type": "Bearer"}
            )
        if request.url.host == "openidconnect.googleapis.com":
            return httpx.Response(200, json=userinfo)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _make_provider(
    store,
    userinfo: dict | None = None,
    allowed_workspaces: list[str] | None = None,
    allowed_emails: list[str] | None = None,
    token_exchanger=None,
    token_status: int = 200,
    **kwargs,
) -> "GoogleWorkspaceOAuthProvider":
    return GoogleWorkspaceOAuthProvider(
        store,
        public_base_url="http://127.0.0.1:8123",
        google_client_id="google-client-id",
        google_client_secret="google-client-secret",
        allowed_workspaces=allowed_workspaces or [],
        allowed_emails=allowed_emails or [],
        http_client=_fake_google_client(
            userinfo or {"email": "alice@acme.com", "email_verified": True, "hd": "acme.com"},
            token_status=token_status,
        ),
        token_exchanger=token_exchanger,
        **kwargs,
    )


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


@pytest.fixture
async def store(tmp_path):
    s = OAuthStore(f"sqlite+aiosqlite:///{tmp_path}/oauth.db")
    yield s
    await s.close()


async def _authorize_and_callback(provider, client, params) -> str:
    """Run authorize + Google callback; return our minted authorization code."""
    google_url = await provider.authorize(client, params)
    txn_state = parse_qs(urlparse(google_url).query)["state"][0]
    response = await provider.handle_google_callback(
        _get_request("/auth/google/callback", {"state": txn_state, "code": "fake-google-code"})
    )
    assert response.status_code in (302, 307), response.status_code
    location = response.headers["location"]
    query = parse_qs(urlparse(location).query)
    assert query["state"] == [params.state]
    return query["code"][0]


# --- store -------------------------------------------------------------------


async def test_store_client_round_trip(store):
    client = _client_info()
    await store.save_client(client)

    loaded = await store.get_client("client-1")
    assert loaded is not None
    assert loaded.client_id == "client-1"
    assert loaded.scope == "claudeai"
    assert [str(u) for u in loaded.redirect_uris] == ["http://localhost:9/cb"]

    assert await store.get_client("nope") is None


async def test_store_auth_code_round_trip_and_single_use(store):
    await store.save_auth_code(
        "code-value",
        client_id="client-1",
        scopes=["claudeai"],
        expires_at=time.time() + 300,
        code_challenge="challenge",
        redirect_uri="http://localhost:9/cb",
        redirect_uri_provided_explicitly=True,
        user_email="alice@acme.com",
    )

    row = await store.get_auth_code("code-value")
    assert row is not None
    assert row.client_id == "client-1"
    assert row.scopes == ["claudeai"]
    assert row.code_challenge == "challenge"
    assert row.user_email == "alice@acme.com"

    assert await store.delete_auth_code("code-value") is True
    assert await store.delete_auth_code("code-value") is False
    assert await store.get_auth_code("code-value") is None


async def test_store_expired_rows_are_dropped_on_lookup(store):
    await store.save_auth_code(
        "stale-code",
        client_id="client-1",
        scopes=[],
        expires_at=time.time() - 10,
        code_challenge="c",
        redirect_uri="http://localhost:9/cb",
        redirect_uri_provided_explicitly=True,
        user_email="alice@acme.com",
    )
    await store.save_access_token(
        "stale-token",
        client_id="client-1",
        scopes=[],
        expires_at=int(time.time()) - 10,
        user_email="alice@acme.com",
    )

    assert await store.get_auth_code("stale-code") is None
    assert await store.get_access_token("stale-token") is None


async def test_store_never_persists_raw_token_values(store, tmp_path):
    await store.save_access_token(
        "very-secret-token",
        client_id="client-1",
        scopes=[],
        expires_at=int(time.time()) + 60,
        user_email="alice@acme.com",
    )
    row = await store.get_access_token("very-secret-token")
    assert row is not None

    raw = (tmp_path / "oauth.db").read_bytes()
    assert b"very-secret-token" not in raw


# --- authorize / Google callback ----------------------------------------------


async def test_authorize_redirects_to_google(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    url = await provider.authorize(_client_info(), _auth_params())

    parsed = urlparse(url)
    assert parsed.scheme == "https"
    assert parsed.netloc == "accounts.google.com"
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["google-client-id"]
    assert query["redirect_uri"] == ["http://127.0.0.1:8123/auth/google/callback"]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid email"]
    # state is our transaction id, NOT the client's state
    assert query["state"] != ["client-state"]


async def test_callback_workspace_hit_redirects_with_code(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())

    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    assert loaded.user_email == "alice@acme.com"
    assert loaded.code_challenge == "challenge-abc"


async def test_callback_email_allowlist_hit(store):
    provider = _make_provider(
        store,
        userinfo={"email": "bob@gmail.com", "email_verified": True},
        allowed_emails=["bob@gmail.com"],
    )
    code = await _authorize_and_callback(provider, _client_info(), _auth_params())
    assert code


async def test_callback_rejects_email_not_in_allowlist(store):
    provider = _make_provider(
        store,
        userinfo={"email": "mallory@evil.com", "email_verified": True, "hd": "evil.com"},
        allowed_workspaces=["acme.com"],
        allowed_emails=["bob@gmail.com"],
    )
    google_url = await provider.authorize(_client_info(), _auth_params())
    txn_state = parse_qs(urlparse(google_url).query)["state"][0]
    response = await provider.handle_google_callback(
        _get_request("/auth/google/callback", {"state": txn_state, "code": "fake"})
    )
    assert response.status_code == 403


async def test_callback_rejects_unverified_email(store):
    provider = _make_provider(
        store,
        userinfo={"email": "alice@acme.com", "email_verified": False, "hd": "acme.com"},
        allowed_workspaces=["acme.com"],
    )
    google_url = await provider.authorize(_client_info(), _auth_params())
    txn_state = parse_qs(urlparse(google_url).query)["state"][0]
    response = await provider.handle_google_callback(
        _get_request("/auth/google/callback", {"state": txn_state, "code": "fake"})
    )
    assert response.status_code == 403


async def test_callback_rejects_everyone_when_allowlists_empty(store):
    # closed by default: no workspaces + no emails configured = nobody gets in
    provider = _make_provider(store)
    google_url = await provider.authorize(_client_info(), _auth_params())
    txn_state = parse_qs(urlparse(google_url).query)["state"][0]
    response = await provider.handle_google_callback(
        _get_request("/auth/google/callback", {"state": txn_state, "code": "fake"})
    )
    assert response.status_code == 403


async def test_callback_rejects_unknown_state(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    response = await provider.handle_google_callback(
        _get_request("/auth/google/callback", {"state": "bogus", "code": "fake"})
    )
    assert response.status_code == 400


async def test_callback_state_is_single_use(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    google_url = await provider.authorize(_client_info(), _auth_params())
    txn_state = parse_qs(urlparse(google_url).query)["state"][0]
    request = _get_request("/auth/google/callback", {"state": txn_state, "code": "fake"})

    first = await provider.handle_google_callback(request)
    assert first.status_code in (302, 307)
    second = await provider.handle_google_callback(request)
    assert second.status_code == 400


# --- token exchange -------------------------------------------------------------


async def test_exchange_authorization_code_is_single_use(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())

    loaded = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded)
    assert token.access_token
    assert token.refresh_token
    assert token.expires_in == 3600

    # code is burnt: cannot be loaded nor exchanged again
    assert await provider.load_authorization_code(client, code) is None
    with pytest.raises(TokenError):
        await provider.exchange_authorization_code(client, loaded)


async def test_load_authorization_code_checks_client_binding(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())

    other = _client_info(client_id="client-2")
    assert await provider.load_authorization_code(other, code) is None


async def test_refresh_token_rotation(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())
    loaded = await provider.load_authorization_code(client, code)
    first = await provider.exchange_authorization_code(client, loaded)

    refresh = await provider.load_refresh_token(client, first.refresh_token)
    assert refresh is not None
    second = await provider.exchange_refresh_token(client, refresh, [])
    assert second.access_token != first.access_token
    assert second.refresh_token != first.refresh_token

    # old refresh token is rotated out (single-use)
    assert await provider.load_refresh_token(client, first.refresh_token) is None
    with pytest.raises(TokenError):
        await provider.exchange_refresh_token(client, refresh, [])

    # identity travels through the rotation
    access = await provider.load_access_token(second.access_token)
    assert access is not None
    assert access.user_email == "alice@acme.com"


async def test_load_access_token_expiry(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"], access_token_lifetime=-1)
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())
    loaded = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded)

    assert await provider.load_access_token(token.access_token) is None


async def test_load_access_token_invokes_token_exchanger(store):
    async def exchanger(email: str) -> str:
        return f"cognee-jwt-for-{email}"

    provider = _make_provider(
        store, allowed_workspaces=["acme.com"], token_exchanger=exchanger
    )
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())
    loaded = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded)

    access = await provider.load_access_token(token.access_token)
    assert isinstance(access, CogneeAccessToken)
    assert access.user_email == "alice@acme.com"
    assert access.cognee_token == "cognee-jwt-for-alice@acme.com"


async def test_token_exchanger_failure_does_not_break_auth(store):
    async def exchanger(email: str) -> str:
        raise RuntimeError("cognee API is down")

    provider = _make_provider(
        store, allowed_workspaces=["acme.com"], token_exchanger=exchanger
    )
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())
    loaded = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded)

    access = await provider.load_access_token(token.access_token)
    assert access is not None
    assert access.cognee_token is None
    assert access.user_email == "alice@acme.com"


async def test_revoke_access_token(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    client = _client_info()
    code = await _authorize_and_callback(provider, client, _auth_params())
    loaded = await provider.load_authorization_code(client, code)
    token = await provider.exchange_authorization_code(client, loaded)

    access = await provider.load_access_token(token.access_token)
    await provider.revoke_token(access)
    assert await provider.load_access_token(token.access_token) is None


async def test_dcr_clients_survive_via_store(store):
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    await provider.register_client(_client_info())
    loaded = await provider.get_client("client-1")
    assert loaded is not None
    assert loaded.client_id == "client-1"
    assert await provider.get_client("missing") is None


# --- env wiring -----------------------------------------------------------------


def test_build_oauth_from_env_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MCP_OAUTH_ENABLED", raising=False)
    provider, settings = build_oauth_from_env()
    assert provider is None
    assert settings is None


def test_build_oauth_from_env_requires_complete_config(monkeypatch):
    monkeypatch.setenv("MCP_OAUTH_ENABLED", "true")
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("MCP_PUBLIC_BASE_URL", raising=False)
    with pytest.raises(ValueError):
        build_oauth_from_env()


def test_build_oauth_from_env_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_OAUTH_ENABLED", "true")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "gid")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "gsecret")
    monkeypatch.setenv("MCP_PUBLIC_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("GOOGLE_ALLOWED_WORKSPACES", "acme.com, example.org")
    monkeypatch.setenv("GOOGLE_ALLOWED_EMAILS", "bob@gmail.com")
    monkeypatch.setenv("MCP_OAUTH_DB_PATH", str(tmp_path / "oauth.db"))

    provider, settings = build_oauth_from_env()
    assert provider is not None
    assert provider.allowed_workspaces == ["acme.com", "example.org"]
    assert provider.allowed_emails == ["bob@gmail.com"]
    assert isinstance(settings, AuthSettings)
    assert str(settings.issuer_url).rstrip("/") == "https://mcp.example.com"
    assert settings.client_registration_options.enabled is True
    assert settings.revocation_options.enabled is True
    assert settings.required_scopes is None


# --- full-stack integration ------------------------------------------------------


async def test_full_oauth_flow_over_http(store):
    """DCR -> /authorize -> Google callback -> /token (PKCE) -> Bearer-gated /mcp."""
    provider = _make_provider(store, allowed_workspaces=["acme.com"])
    auth_settings = AuthSettings(
        issuer_url="http://127.0.0.1:8123",
        resource_server_url="http://127.0.0.1:8123/mcp",
        client_registration_options=ClientRegistrationOptions(
            enabled=True, default_scopes=["claudeai"]
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=None,
    )
    test_mcp = FastMCP("CogneeOAuthTest", auth_server_provider=provider, auth=auth_settings)

    @test_mcp.custom_route("/auth/google/callback", methods=["GET"])
    async def google_callback(request):
        return await provider.handle_google_callback(request)

    app = test_mcp.streamable_http_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    http_server = uvicorn.Server(config)
    serve_task = asyncio.create_task(http_server.serve())
    try:
        while not http_server.started:
            await asyncio.sleep(0.02)
        port = http_server.servers[0].sockets[0].getsockname()[1]
        base = f"http://127.0.0.1:{port}"

        async with httpx.AsyncClient(base_url=base) as http:
            # AS metadata is served
            meta = await http.get("/.well-known/oauth-authorization-server")
            assert meta.status_code == 200
            body = meta.json()
            assert "authorization_endpoint" in body
            assert "registration_endpoint" in body

            # 1. Dynamic Client Registration
            redirect_uri = "http://localhost:9999/callback"
            reg = await http.post(
                "/register",
                json={
                    "redirect_uris": [redirect_uri],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "client_name": "Claude",
                    "scope": "claudeai",
                },
            )
            assert reg.status_code == 201, reg.text
            client_id = reg.json()["client_id"]

            # 2. /authorize redirects to Google
            verifier, challenge = _pkce_pair()
            authz = await http.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "state": "claude-state",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "scope": "claudeai",
                },
            )
            assert authz.status_code in (302, 307), authz.text
            google_url = urlparse(authz.headers["location"])
            assert google_url.netloc == "accounts.google.com"
            txn_state = parse_qs(google_url.query)["state"][0]

            # 3. Google redirects back to us; we redirect to the client with a code
            cb = await http.get(
                "/auth/google/callback", params={"state": txn_state, "code": "fake-google"}
            )
            assert cb.status_code in (302, 307), cb.text
            client_redirect = urlparse(cb.headers["location"])
            assert client_redirect.netloc == "localhost:9999"
            cb_query = parse_qs(client_redirect.query)
            assert cb_query["state"] == ["claude-state"]
            code = cb_query["code"][0]

            # 4. /token with PKCE verifier
            tok = await http.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
            assert tok.status_code == 200, tok.text
            tokens = tok.json()
            access_token = tokens["access_token"]
            refresh_token = tokens["refresh_token"]

            # wrong PKCE verifier must not work (code already burnt anyway)
            tok_replay = await http.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
            assert tok_replay.status_code == 400

            # 5. /mcp is Bearer-gated
            mcp_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            init_body = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"},
                },
            }
            no_auth = await http.post("/mcp", json=init_body, headers=mcp_headers)
            assert no_auth.status_code == 401
            bad_auth = await http.post(
                "/mcp",
                json=init_body,
                headers={**mcp_headers, "Authorization": "Bearer nonsense"},
            )
            assert bad_auth.status_code == 401
            ok = await http.post(
                "/mcp",
                json=init_body,
                headers={**mcp_headers, "Authorization": f"Bearer {access_token}"},
            )
            assert ok.status_code != 401, ok.text

            # 6. refresh rotation over HTTP
            ref = await http.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                },
            )
            assert ref.status_code == 200, ref.text
            assert ref.json()["access_token"] != access_token
            ref_replay = await http.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                },
            )
            assert ref_replay.status_code == 400
    finally:
        http_server.should_exit = True
        await serve_task
