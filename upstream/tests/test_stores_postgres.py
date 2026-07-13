"""Persistence-layer tests against a real Postgres (opt-in).

The regular store tests run on sqlite+aiosqlite, which silently accepts type
combinations Postgres rejects — e.g. an offset-aware datetime in a naive
TIMESTAMP column, the exact bug that broke the identity bridge's very first
production write while 80 sqlite-backed tests stayed green (commit 36797e0).

These tests exercise every table's insert/read path of both stores on a real
Postgres, catching sqlite/postgres type-mapping drift. They are skipped unless
``TEST_PG_DSN`` points at a *scratch* database, e.g.:

    podman run --rm -d -p 127.0.0.1:15432:5432 -e POSTGRES_USER=t \
        -e POSTGRES_PASSWORD=t -e POSTGRES_DB=storetests postgres:16-alpine
    TEST_PG_DSN=postgresql+asyncpg://t:t@127.0.0.1:15432/storetests \
        uv run pytest tests/test_stores_postgres.py

All store tables are dropped before and after each test — never point
TEST_PG_DSN at a database you care about.
"""

import importlib
import os
import sys
import time
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

MCP_ROOT = Path(__file__).resolve().parents[1]  # cognee-mcp/
if str(MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(MCP_ROOT))

identity_bridge = importlib.import_module("src.identity_bridge")
oauth_store = importlib.import_module("src.oauth_store")

TEST_PG_DSN = os.getenv("TEST_PG_DSN")

pytestmark = pytest.mark.skipif(
    not TEST_PG_DSN,
    reason="TEST_PG_DSN not set (scratch Postgres required; see module docstring)",
)


@pytest.fixture
async def pg_dsn():
    """The scratch-Postgres DSN, with all store tables dropped before and after."""
    engine = create_async_engine(TEST_PG_DSN)

    async def drop_everything():
        async with engine.begin() as conn:
            await conn.run_sync(oauth_store.metadata.drop_all)
            await conn.run_sync(identity_bridge._Base.metadata.drop_all)

    await drop_everything()
    try:
        yield TEST_PG_DSN
    finally:
        await drop_everything()
        await engine.dispose()


# --- identity bridge ----------------------------------------------------------


def _bridge(dsn: str, cognee_api: httpx.MockTransport) -> "identity_bridge.CogneeIdentityBridge":
    return identity_bridge.CogneeIdentityBridge(
        api_url="http://cognee.local",
        jwt_secret="pg-test-secret",
        store_dsn=dsn,
        http_client=httpx.AsyncClient(transport=cognee_api),
    )


@pytest.mark.asyncio
async def test_identity_mapping_survives_postgres_round_trip(pg_dsn):
    """The production path that broke on sqlite-tested code: auto-provision a
    user, persist the email->uuid mapping (incl. the created_at default), then
    read it back through a FRESH bridge instance with no HTTP fallback."""
    register_calls = []

    async def api(request: httpx.Request) -> httpx.Response:
        register_calls.append(request.url.path)
        return httpx.Response(201, json={"id": "8f1e8a4e-0000-4000-8000-000000000042"})

    first = _bridge(pg_dsn, httpx.MockTransport(api))
    try:
        token = await first.cognee_token_for("pg-user@example.com")
        assert token
    finally:
        await first.close()
    assert register_calls == ["/api/v1/auth/register"]

    async def api_must_not_be_called(request: httpx.Request) -> httpx.Response:
        raise AssertionError("mapping should come from Postgres, not registration")

    second = _bridge(pg_dsn, httpx.MockTransport(api_must_not_be_called))
    try:
        token = await second.cognee_token_for("pg-user@example.com")
        assert token
    finally:
        await second.close()


# --- oauth store ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_oauth_client_round_trip_on_postgres(pg_dsn):
    from mcp.shared.auth import OAuthClientInformationFull

    store = oauth_store.OAuthStore(pg_dsn)
    try:
        client = OAuthClientInformationFull(
            client_id="client-pg",
            redirect_uris=["http://localhost:9/cb"],
            token_endpoint_auth_method="none",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            client_name="pg test",
        )
        await store.save_client(client)
        loaded = await store.get_client("client-pg")
        assert loaded is not None
        assert loaded.client_id == "client-pg"
        assert str(loaded.redirect_uris[0]) == "http://localhost:9/cb"
        assert await store.get_client("missing") is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_oauth_auth_code_round_trip_and_single_use_on_postgres(pg_dsn):
    store = oauth_store.OAuthStore(pg_dsn)
    try:
        await store.save_auth_code(
            "code-pg",
            client_id="client-pg",
            scopes=["claudeai"],
            expires_at=time.time() + 300,
            code_challenge="challenge",
            redirect_uri="http://localhost:9/cb",
            redirect_uri_provided_explicitly=True,
            user_email="pg-user@example.com",
            resource=None,
        )
        row = await store.get_auth_code("code-pg")
        assert row is not None
        assert row.user_email == "pg-user@example.com"
        assert row.scopes == ["claudeai"]

        assert await store.delete_auth_code("code-pg") is True
        assert await store.delete_auth_code("code-pg") is False  # single-use
        assert await store.get_auth_code("code-pg") is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_oauth_tokens_round_trip_and_expiry_purge_on_postgres(pg_dsn):
    store = oauth_store.OAuthStore(pg_dsn)
    try:
        await store.save_access_token(
            "at-live",
            client_id="client-pg",
            scopes=["claudeai"],
            expires_at=int(time.time()) + 3600,
            user_email="pg-user@example.com",
        )
        await store.save_access_token(
            "at-expired",
            client_id="client-pg",
            scopes=[],
            expires_at=int(time.time()) - 10,
            user_email="pg-user@example.com",
        )
        await store.save_refresh_token(
            "rt-live",
            client_id="client-pg",
            scopes=["claudeai"],
            expires_at=None,  # non-expiring refresh token
            user_email="pg-user@example.com",
        )

        live = await store.get_access_token("at-live")
        assert live is not None and live.user_email == "pg-user@example.com"
        assert await store.get_access_token("at-expired") is None  # lazily purged

        refresh = await store.get_refresh_token("rt-live")
        assert refresh is not None and refresh.expires_at is None

        assert await store.delete_refresh_token("rt-live") is True
        assert await store.delete_refresh_token("rt-live") is False
    finally:
        await store.close()
