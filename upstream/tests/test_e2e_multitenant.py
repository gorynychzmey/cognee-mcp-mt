"""End-to-end multi-tenant path: OAuth AS + identity bridge + per-request token.

The epic's acceptance shape, fully in-process: two Google users go through the
built-in OAuth 2.1 AS (DCR + PKCE + fake Google), call an MCP tool over real
streamable HTTP with their opaque access tokens, and the outgoing cognee-API
requests carry two *different* bridge-minted JWTs whose ``sub`` claims are the
UUIDs cognee assigned at auto-registration.

Also covers the server.py glue that attaches the identity bridge to the OAuth
provider (``_attach_identity_bridge``).
"""

import asyncio
import base64
import hashlib
import importlib
import secrets
import sys
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import jwt as pyjwt
import pytest
import uvicorn

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP

MCP_ROOT = Path(__file__).resolve().parents[1]  # cognee-mcp/
if str(MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(MCP_ROOT))

CogneeClient = importlib.import_module("src.cognee_client").CogneeClient
identity_bridge = importlib.import_module("src.identity_bridge")
oauth_provider = importlib.import_module("src.oauth_provider")
oauth_store = importlib.import_module("src.oauth_store")

JWT_SECRET = "shared-test-secret"


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


class FakeGoogle:
    """Google token + userinfo endpoints; the 'logged in' user is mutable."""

    def __init__(self):
        self.userinfo: dict = {}

    def client(self) -> httpx.AsyncClient:
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "oauth2.googleapis.com":
                return httpx.Response(
                    200, json={"access_token": "google-access-token", "token_type": "Bearer"}
                )
            if request.url.host == "openidconnect.googleapis.com":
                return httpx.Response(200, json=self.userinfo)
            return httpx.Response(404)

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class FakeCogneeApi:
    """Registration + datasets endpoints; records what it saw."""

    def __init__(self):
        self.registered: dict[str, str] = {}  # email -> uuid
        self.register_calls: list[str] = []
        self.datasets_auth: list[str | None] = []

    def client(self) -> httpx.AsyncClient:
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v1/auth/register":
                import json as _json

                email = _json.loads(request.content)["email"]
                self.register_calls.append(email)
                if email in self.registered:
                    return httpx.Response(400, json={"detail": "REGISTER_USER_ALREADY_EXISTS"})
                self.registered[email] = str(uuid.uuid4())
                return httpx.Response(201, json={"id": self.registered[email], "email": email})
            if request.url.path == "/api/v1/datasets":
                self.datasets_auth.append(request.headers.get("authorization"))
                return httpx.Response(200, json=[])
            return httpx.Response(404)

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _oauth_login(http: httpx.AsyncClient, client_id: str, redirect_uri: str) -> str:
    """Run authorize -> Google callback -> token exchange; returns an access token."""
    verifier, challenge = _pkce_pair()
    authz = await http.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": "client-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "claudeai",
        },
    )
    assert authz.status_code in (302, 307), authz.text
    txn_state = parse_qs(urlparse(authz.headers["location"]).query)["state"][0]

    cb = await http.get("/auth/google/callback", params={"state": txn_state, "code": "fake"})
    assert cb.status_code in (302, 307), cb.text
    code = parse_qs(urlparse(cb.headers["location"]).query)["code"][0]

    token = await http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    return token.json()["access_token"]


@pytest.mark.asyncio
async def test_two_google_users_reach_cognee_api_as_two_users(tmp_path):
    """Claude.ai-shaped flow x2 -> two distinct bridge-minted cognee JWTs."""
    google = FakeGoogle()
    cognee_api = FakeCogneeApi()

    bridge = identity_bridge.CogneeIdentityBridge(
        api_url="http://cognee.local",
        jwt_secret=JWT_SECRET,
        store_dsn=f"sqlite+aiosqlite:///{tmp_path}/identity.db",
        http_client=cognee_api.client(),
    )
    store = oauth_store.OAuthStore(f"sqlite+aiosqlite:///{tmp_path}/oauth.db")
    provider = oauth_provider.GoogleWorkspaceOAuthProvider(
        store,
        public_base_url="http://127.0.0.1:8123",
        google_client_id="gid",
        google_client_secret="gsecret",
        allowed_workspaces=["acme.com"],
        allowed_emails=[],
        http_client=google.client(),
        token_exchanger=bridge.cognee_token_for,
    )
    auth_settings = AuthSettings(
        issuer_url="http://127.0.0.1:8123",
        resource_server_url="http://127.0.0.1:8123/mcp",
        client_registration_options=ClientRegistrationOptions(
            enabled=True, default_scopes=["claudeai"]
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=None,
    )
    test_mcp = FastMCP("CogneeE2E", auth_server_provider=provider, auth=auth_settings)

    @test_mcp.custom_route("/auth/google/callback", methods=["GET"])
    async def google_callback(request):
        return await provider.handle_google_callback(request)

    # A production-shaped tool: goes through CogneeClient -> auth_context.
    tool_client = CogneeClient(api_url="http://cognee.local", api_token="static-token")
    await tool_client.client.aclose()
    tool_client.client = cognee_api.client()

    @test_mcp.tool(name="list_datasets_probe")
    async def list_datasets_probe() -> str:
        result = await tool_client.list_datasets()
        return f"{len(result)} dataset(s)"

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
            reg = await http.post(
                "/register",
                json={
                    "redirect_uris": ["http://localhost:9999/cb"],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "client_name": "Claude",
                    "scope": "claudeai",
                },
            )
            assert reg.status_code == 201, reg.text
            client_id = reg.json()["client_id"]

            google.userinfo = {"email": "a@acme.com", "email_verified": True, "hd": "acme.com"}
            token_a = await _oauth_login(http, client_id, "http://localhost:9999/cb")
            google.userinfo = {"email": "b@acme.com", "email_verified": True, "hd": "acme.com"}
            token_b = await _oauth_login(http, client_id, "http://localhost:9999/cb")

        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        async def call_tool_as(access_token: str) -> None:
            import contextlib

            async with contextlib.AsyncExitStack() as stack:
                mcp_http = httpx.AsyncClient(
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                read, write, _ = await stack.enter_async_context(
                    streamable_http_client(f"{base}/mcp", http_client=mcp_http)
                )
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                result = await session.call_tool("list_datasets_probe", {})
                assert not result.isError

        await call_tool_as(token_a)
        await call_tool_as(token_b)
    finally:
        http_server.should_exit = True
        await serve_task
        await tool_client.close()
        await bridge.close()
        await store.close()

    # Both users were auto-provisioned exactly once
    assert sorted(cognee_api.register_calls) == ["a@acme.com", "b@acme.com"]

    # The outgoing cognee-API calls carried two DIFFERENT bridge-minted JWTs
    assert len(cognee_api.datasets_auth) == 2
    subs = []
    for auth_header in cognee_api.datasets_auth:
        assert auth_header and auth_header.startswith("Bearer ")
        claims = pyjwt.decode(
            auth_header.removeprefix("Bearer "),
            JWT_SECRET,
            algorithms=["HS256"],
            audience=["fastapi-users:auth"],
        )
        subs.append(claims["sub"])
    assert subs[0] == cognee_api.registered["a@acme.com"]
    assert subs[1] == cognee_api.registered["b@acme.com"]
    assert subs[0] != subs[1]


# --- server.py glue -----------------------------------------------------------


class _StubProvider:
    token_exchanger = None


def test_attach_identity_bridge_wires_exchanger(monkeypatch, tmp_path):
    server = importlib.import_module("src.server")
    provider = _StubProvider()
    monkeypatch.setattr(server, "_oauth_provider", provider)
    monkeypatch.setenv("FASTAPI_USERS_JWT_SECRET", JWT_SECRET)
    monkeypatch.setenv("MCP_IDENTITY_DB_PATH", str(tmp_path / "identity.db"))

    bridge = server._attach_identity_bridge(api_url="http://cognee.local")

    assert bridge is not None
    assert provider.token_exchanger == bridge.cognee_token_for


def test_attach_identity_bridge_without_oauth_is_noop(monkeypatch):
    server = importlib.import_module("src.server")
    monkeypatch.setattr(server, "_oauth_provider", None)
    monkeypatch.setenv("FASTAPI_USERS_JWT_SECRET", JWT_SECRET)

    assert server._attach_identity_bridge(api_url="http://cognee.local") is None


def test_attach_identity_bridge_without_bridge_config_warns_and_noops(monkeypatch):
    server = importlib.import_module("src.server")
    provider = _StubProvider()
    monkeypatch.setattr(server, "_oauth_provider", provider)
    monkeypatch.delenv("FASTAPI_USERS_JWT_SECRET", raising=False)
    monkeypatch.delenv("COGNEE_API_URL", raising=False)

    assert server._attach_identity_bridge(api_url=None) is None
    assert provider.token_exchanger is None
