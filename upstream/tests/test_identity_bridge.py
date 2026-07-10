"""Identity bridge: authenticated end-user email -> cognee-API-valid JWT.

The MCP process and the vanilla cognee-API share ``FASTAPI_USERS_JWT_SECRET``,
so the bridge can mint Bearer JWTs the API's stock fastapi_users JWTStrategy
accepts (HS256, aud "fastapi-users:auth", sub = user UUID). Unknown emails are
auto-provisioned via the stock register endpoint and the email -> UUID mapping
is persisted so registration happens once per user.
"""

import asyncio
import importlib
import json
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from fastapi_users import exceptions as fastapi_users_exceptions
from fastapi_users.authentication import JWTStrategy

MCP_ROOT = Path(__file__).resolve().parents[1]  # cognee-mcp/
if str(MCP_ROOT) not in sys.path:
    sys.path.insert(0, str(MCP_ROOT))

identity_bridge = importlib.import_module("src.identity_bridge")
CogneeIdentityBridge = identity_bridge.CogneeIdentityBridge
UnknownCogneeUserError = identity_bridge.UnknownCogneeUserError
build_identity_bridge_from_env = identity_bridge.build_identity_bridge_from_env

SECRET = "test-shared-fastapi-users-secret"
API_URL = "http://cognee.local"


class _FakeClock:
    """Injectable clock so token-lifetime tests do not sleep."""

    def __init__(self, start: float = 1_700_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _RegisterAPI:
    """MockTransport handler mimicking cognee-API's stock register router."""

    def __init__(self):
        self.calls: list[dict[str, Any]] = []
        self.users: dict[str, str] = {}  # email -> uuid str

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == f"{API_URL}/api/v1/auth/register"
        body = json.loads(request.content)
        self.calls.append(body)
        email = body["email"]
        if email in self.users:
            return httpx.Response(400, json={"detail": "REGISTER_USER_ALREADY_EXISTS"})
        user_id = str(uuid.uuid4())
        self.users[email] = user_id
        return httpx.Response(
            201,
            json={
                "id": user_id,
                "email": email,
                "is_active": True,
                "is_superuser": False,
                "is_verified": False,
            },
        )


def _bridge(tmp_path: Path, handler, clock=None, **kwargs) -> CogneeIdentityBridge:
    return CogneeIdentityBridge(
        api_url=API_URL,
        jwt_secret=SECRET,
        store_dsn=f"sqlite+aiosqlite:///{tmp_path / 'identity.db'}",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        time_func=clock or _FakeClock(),
        **kwargs,
    )


def _decode(token: str) -> dict[str, Any]:
    return pyjwt.decode(
        token,
        SECRET,
        audience=["fastapi-users:auth"],
        algorithms=["HS256"],
        options={"verify_exp": False},
    )


# --- registration + persistence ----------------------------------------------


async def test_new_email_is_registered_and_token_carries_returned_id(tmp_path):
    api = _RegisterAPI()
    bridge = _bridge(tmp_path, api)
    try:
        token = await bridge.cognee_token_for("alice@example.com")
    finally:
        await bridge.close()

    assert api.calls and api.calls[0]["email"] == "alice@example.com"
    # throwaway password: random, present, never the email
    assert api.calls[0]["password"] and api.calls[0]["password"] != "alice@example.com"
    claims = _decode(token)
    assert claims["sub"] == api.users["alice@example.com"]
    assert claims["aud"] == ["fastapi-users:auth"]
    assert "exp" in claims


async def test_mapping_persists_across_bridge_instances(tmp_path):
    api = _RegisterAPI()
    bridge = _bridge(tmp_path, api)
    try:
        first = await bridge.cognee_token_for("alice@example.com")
    finally:
        await bridge.close()

    async def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError("second instance must not hit the API")

    bridge2 = _bridge(tmp_path, refuse)
    try:
        second = await bridge2.cognee_token_for("alice@example.com")
    finally:
        await bridge2.close()

    assert _decode(second)["sub"] == _decode(first)["sub"]


async def test_email_is_normalized_before_lookup_and_registration(tmp_path):
    api = _RegisterAPI()
    bridge = _bridge(tmp_path, api)
    try:
        t1 = await bridge.cognee_token_for("  Alice@Example.COM ")
        t2 = await bridge.cognee_token_for("alice@example.com")
    finally:
        await bridge.close()

    assert len(api.calls) == 1
    assert api.calls[0]["email"] == "alice@example.com"
    assert _decode(t1)["sub"] == _decode(t2)["sub"]


async def test_already_registered_unknown_user_raises_actionable_error(tmp_path):
    api = _RegisterAPI()
    api.users["taken@example.com"] = str(uuid.uuid4())  # exists in cognee, unknown to us
    bridge = _bridge(tmp_path, api)
    try:
        with pytest.raises(UnknownCogneeUserError, match="COGNEE_USER_MAP"):
            await bridge.cognee_token_for("taken@example.com")
    finally:
        await bridge.close()


async def test_unexpected_api_error_is_raised(tmp_path):
    async def boom(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "kaboom"})

    bridge = _bridge(tmp_path, boom)
    try:
        with pytest.raises(Exception, match="500"):
            await bridge.cognee_token_for("alice@example.com")
    finally:
        await bridge.close()


# --- seed map -----------------------------------------------------------------


async def test_seed_map_avoids_http_entirely(tmp_path):
    seeded_id = str(uuid.uuid4())

    async def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError("seeded email must not hit the API")

    bridge = _bridge(tmp_path, refuse, seed_map={"bob@example.com": seeded_id})
    try:
        token = await bridge.cognee_token_for("Bob@Example.com")
    finally:
        await bridge.close()

    assert _decode(token)["sub"] == seeded_id


# --- token caching ------------------------------------------------------------


async def test_token_is_cached_until_80_percent_of_lifetime(tmp_path):
    api = _RegisterAPI()
    clock = _FakeClock()
    bridge = _bridge(tmp_path, api, clock=clock, jwt_lifetime_seconds=600)
    try:
        first = await bridge.cognee_token_for("alice@example.com")
        clock.advance(479)  # < 80% of 600s
        assert await bridge.cognee_token_for("alice@example.com") == first
        clock.advance(2)  # >= 80% of 600s
        renewed = await bridge.cognee_token_for("alice@example.com")
    finally:
        await bridge.close()

    assert renewed != first
    assert _decode(renewed)["sub"] == _decode(first)["sub"]
    assert len(api.calls) == 1  # registration happened once, only the JWT was re-minted


async def test_exp_claim_matches_injected_clock_and_lifetime(tmp_path):
    api = _RegisterAPI()
    clock = _FakeClock(start=1_700_000_000.0)
    bridge = _bridge(tmp_path, api, clock=clock, jwt_lifetime_seconds=600)
    try:
        token = await bridge.cognee_token_for("alice@example.com")
    finally:
        await bridge.close()

    assert _decode(token)["exp"] == 1_700_000_000 + 600


# --- concurrency --------------------------------------------------------------


async def test_concurrent_calls_for_new_email_register_once(tmp_path):
    api_calls = 0

    async def slow_register(request: httpx.Request) -> httpx.Response:
        nonlocal api_calls
        api_calls += 1
        await asyncio.sleep(0.02)  # widen the race window
        return httpx.Response(201, json={"id": str(uuid.uuid4()), "email": "x"})

    bridge = _bridge(tmp_path, slow_register)
    try:
        tokens = await asyncio.gather(
            *(bridge.cognee_token_for("alice@example.com") for _ in range(10))
        )
    finally:
        await bridge.close()

    assert api_calls == 1
    assert len({_decode(t)["sub"] for t in tokens}) == 1


# --- THE compatibility test ----------------------------------------------------


class _StubUserManager:
    """parse_id/get exactly as cognee's UserManager inherits them.

    cognee's ``UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID])``
    inherits ``parse_id`` from ``UUIDIDMixin`` (uuid.UUID(value) or InvalidID)
    and ``get`` from ``BaseUserManager`` (user_db.get; UserNotExists if None).
    """

    def __init__(self, known: dict[uuid.UUID, Any]):
        self.known = known
        self.requested: list[uuid.UUID] = []

    def parse_id(self, value: Any) -> uuid.UUID:
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(value)
        except ValueError as e:
            raise fastapi_users_exceptions.InvalidID() from e

    async def get(self, id: uuid.UUID) -> Any:
        self.requested.append(id)
        user = self.known.get(id)
        if user is None:
            raise fastapi_users_exceptions.UserNotExists()
        return user


async def test_minted_token_round_trips_through_real_fastapi_users_jwt_strategy(tmp_path):
    import time

    api = _RegisterAPI()
    # real wall clock: the REAL strategy must accept the exp claim as unexpired
    bridge = _bridge(tmp_path, api, clock=time.time)
    try:
        token = await bridge.cognee_token_for("alice@example.com")
    finally:
        await bridge.close()

    user_id = uuid.UUID(api.users["alice@example.com"])
    user = SimpleNamespace(id=user_id, email="alice@example.com", is_active=True)
    manager = _StubUserManager({user_id: user})

    # exactly how cognee builds it: APIJWTStrategy(secret, lifetime_seconds=...)
    strategy = JWTStrategy(secret=SECRET, lifetime_seconds=3600)
    resolved = await strategy.read_token(token, manager)

    assert resolved is user
    assert manager.requested == [user_id]

    # wrong secret (i.e. operator misconfiguration) must NOT authenticate
    wrong = JWTStrategy(secret="another-secret", lifetime_seconds=3600)
    assert await wrong.read_token(token, manager) is None


# --- env construction -----------------------------------------------------------


def test_build_from_env_returns_none_without_secret_or_api_url(monkeypatch):
    for var in ("FASTAPI_USERS_JWT_SECRET", "COGNEE_API_URL"):
        monkeypatch.delenv(var, raising=False)
    assert build_identity_bridge_from_env() is None

    monkeypatch.setenv("FASTAPI_USERS_JWT_SECRET", SECRET)
    assert build_identity_bridge_from_env() is None  # api_url still missing

    monkeypatch.delenv("FASTAPI_USERS_JWT_SECRET", raising=False)
    assert build_identity_bridge_from_env(api_url=API_URL) is None  # secret missing


async def test_build_from_env_reads_config_and_seed_map(monkeypatch, tmp_path):
    seeded_id = str(uuid.uuid4())
    monkeypatch.setenv("FASTAPI_USERS_JWT_SECRET", SECRET)
    monkeypatch.setenv("COGNEE_API_URL", API_URL)
    monkeypatch.setenv("MCP_IDENTITY_DB_PATH", str(tmp_path / "ids.db"))
    monkeypatch.delenv("MCP_IDENTITY_DB_URL", raising=False)
    monkeypatch.setenv("COGNEE_USER_MAP", f" Carol@Example.com : {seeded_id} ")

    bridge = build_identity_bridge_from_env()
    assert bridge is not None
    try:
        token = await bridge.cognee_token_for("carol@example.com")
    finally:
        await bridge.close()

    assert _decode(token)["sub"] == seeded_id


def test_build_from_env_prefers_explicit_dsn(monkeypatch, tmp_path):
    monkeypatch.setenv("FASTAPI_USERS_JWT_SECRET", SECRET)
    monkeypatch.setenv("MCP_IDENTITY_DB_URL", f"sqlite+aiosqlite:///{tmp_path / 'x.db'}")
    bridge = build_identity_bridge_from_env(api_url=API_URL)
    assert bridge is not None
    assert bridge.store_dsn == f"sqlite+aiosqlite:///{tmp_path / 'x.db'}"
