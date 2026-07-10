"""Identity bridge: authenticated end-user email -> cognee-API-valid Bearer JWT.

The MCP server authenticates end users itself (OAuth), but the co-located
vanilla cognee-API only trusts its own fastapi_users credentials. Both
processes share ``FASTAPI_USERS_JWT_SECRET`` (one pod, one env file), so this
bridge mints JWTs directly in the exact shape cognee's stock
``JWTStrategy.read_token`` accepts: HS256, ``aud=["fastapi-users:auth"]``,
``sub`` = the user's UUID, ``exp`` = now + lifetime.

The email -> UUID mapping is resolved in order:

1. in-memory cache,
2. persistent store (small SQLAlchemy table; sqlite file by default),
3. static seed map (``COGNEE_USER_MAP`` — for cognee users that pre-date us),
4. auto-provisioning: ``POST /api/v1/auth/register`` with a random throwaway
   password (never stored or logged — the JWT is minted from the returned id,
   we never log in with the password).

If cognee reports the email as already registered and we have no mapping, we
cannot discover its UUID (there is no lookup endpoint for non-superusers), so
we fail with instructions to seed ``COGNEE_USER_MAP``.
"""

import asyncio
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

import httpx
import jwt as pyjwt
from cognee.shared.logging_utils import get_logger
from sqlalchemy import Column, DateTime, String, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

logger = get_logger()

DEFAULT_JWT_AUDIENCE = ["fastapi-users:auth"]
DEFAULT_JWT_LIFETIME_SECONDS = 600
REGISTER_PATH = "/api/v1/auth/register"
_CACHE_REUSE_FRACTION = 0.8  # re-mint once 80% of the token lifetime has elapsed


class UnknownCogneeUserError(RuntimeError):
    """The email exists in cognee-API but we have no UUID mapping for it."""


class _Base(DeclarativeBase):
    pass


class _IdentityMapping(_Base):
    """Persistent email -> cognee user UUID mapping."""

    __tablename__ = "mcp_identity_map"

    email = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _store_dsn_from_env() -> str:
    dsn = os.getenv("MCP_IDENTITY_DB_URL")
    if dsn:
        return dsn
    path = os.getenv("MCP_IDENTITY_DB_PATH", "./identity.db")
    return f"sqlite+aiosqlite:///{path}"


def parse_user_map(raw: str) -> Dict[str, str]:
    """Parse COGNEE_USER_MAP: ``email:uuid,email:uuid`` (whitespace tolerated)."""
    mapping: Dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        email, sep, user_id = entry.partition(":")
        if not sep or not email.strip() or not user_id.strip():
            raise ValueError(f"COGNEE_USER_MAP entry not in 'email:uuid' form: {entry!r}")
        mapping[_normalize_email(email)] = user_id.strip()
    return mapping


class CogneeIdentityBridge:
    """Maps an authenticated end-user email to a Bearer JWT cognee-API accepts."""

    def __init__(
        self,
        api_url: str,
        jwt_secret: str,
        store_dsn: Optional[str] = None,
        jwt_lifetime_seconds: int = DEFAULT_JWT_LIFETIME_SECONDS,
        jwt_audience: Optional[List[str]] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        seed_map: Optional[Dict[str, str]] = None,
        time_func: Callable[[], float] = time.time,
    ):
        self.api_url = api_url.rstrip("/")
        self.jwt_secret = jwt_secret
        self.store_dsn = store_dsn or _store_dsn_from_env()
        self.jwt_lifetime_seconds = jwt_lifetime_seconds
        self.jwt_audience = list(jwt_audience) if jwt_audience else list(DEFAULT_JWT_AUDIENCE)
        self.http_client = http_client or httpx.AsyncClient()
        self._seed_map = {_normalize_email(k): v for k, v in (seed_map or {}).items()}
        self._time = time_func

        self._user_ids: Dict[str, str] = {}  # email -> uuid str (in-memory cache)
        self._tokens: Dict[str, tuple] = {}  # email -> (token, minted_at)
        self._email_locks: Dict[str, asyncio.Lock] = {}
        self._engine = None
        self._sessionmaker = None
        self._store_ready = False
        self._store_init_lock = asyncio.Lock()

    # --- persistent store -------------------------------------------------

    async def _get_sessionmaker(self):
        if not self._store_ready:
            async with self._store_init_lock:
                if not self._store_ready:
                    self._engine = create_async_engine(self.store_dsn)
                    async with self._engine.begin() as conn:
                        await conn.run_sync(_Base.metadata.create_all)
                    self._sessionmaker = async_sessionmaker(self._engine, expire_on_commit=False)
                    self._store_ready = True
        return self._sessionmaker

    async def _store_get(self, email: str) -> Optional[str]:
        sessionmaker = await self._get_sessionmaker()
        async with sessionmaker() as session:
            row = (
                await session.execute(
                    select(_IdentityMapping).where(_IdentityMapping.email == email)
                )
            ).scalar_one_or_none()
            return row.user_id if row else None

    async def _store_put(self, email: str, user_id: str) -> None:
        sessionmaker = await self._get_sessionmaker()
        async with sessionmaker() as session:
            await session.merge(_IdentityMapping(email=email, user_id=user_id))
            await session.commit()

    # --- provisioning -------------------------------------------------------

    async def _register(self, email: str) -> str:
        """Auto-provision the user in cognee-API; returns the new user's UUID."""
        password = secrets.token_urlsafe(24)  # throwaway: never stored, never used again
        response = await self.http_client.post(
            f"{self.api_url}{REGISTER_PATH}",
            json={"email": email, "password": password},
        )
        if response.status_code == 400:
            detail = None
            try:
                detail = response.json().get("detail")
            except Exception:
                pass
            if detail == "REGISTER_USER_ALREADY_EXISTS":
                raise UnknownCogneeUserError(
                    f"cognee-API already has a user for {email!r} but this bridge has no "
                    "UUID mapping for it (a user we did not create cannot be looked up). "
                    "Fix: add 'email:uuid' to the COGNEE_USER_MAP environment variable."
                )
        if response.status_code != 201:
            raise RuntimeError(
                f"cognee-API user registration for {email!r} failed: "
                f"HTTP {response.status_code}: {response.text[:200]}"
            )
        user_id = str(response.json()["id"])
        logger.info(f"Auto-provisioned cognee-API user for {email} (id={user_id})")
        return user_id

    async def _resolve_user_id(self, email: str) -> str:
        """cache -> persistent store -> seed map -> register."""
        user_id = self._user_ids.get(email)
        if user_id:
            return user_id
        user_id = await self._store_get(email)
        if not user_id:
            user_id = self._seed_map.get(email)
            if not user_id:
                user_id = await self._register(email)
            await self._store_put(email, user_id)
        self._user_ids[email] = user_id
        return user_id

    # --- token minting --------------------------------------------------------

    def _mint(self, user_id: str) -> str:
        """Mint the exact JWT cognee's stock fastapi_users JWTStrategy accepts."""
        now = self._time()
        payload = {
            "sub": user_id,
            "aud": self.jwt_audience,
            "exp": int(now) + self.jwt_lifetime_seconds,
        }
        return pyjwt.encode(payload, self.jwt_secret, algorithm="HS256")

    async def cognee_token_for(self, email: str) -> str:
        """Return a cognee-API-valid Bearer JWT for the given end-user email.

        Concurrency-safe per email: parallel calls for a NEW email register
        the user exactly once. Minted tokens are reused until 80% of their
        lifetime has elapsed.
        """
        email = _normalize_email(email)
        lock = self._email_locks.setdefault(email, asyncio.Lock())
        async with lock:
            cached = self._tokens.get(email)
            if cached is not None:
                token, minted_at = cached
                if self._time() - minted_at < self.jwt_lifetime_seconds * _CACHE_REUSE_FRACTION:
                    return token
            user_id = await self._resolve_user_id(email)
            token = self._mint(user_id)
            self._tokens[email] = (token, self._time())
            return token

    async def close(self) -> None:
        """Release the HTTP client (the bridge owns it, injected or not) and the store."""
        await self.http_client.aclose()
        if self._engine is not None:
            await self._engine.dispose()


def build_identity_bridge_from_env(api_url: Optional[str] = None) -> Optional[CogneeIdentityBridge]:
    """Build a bridge from environment config, or None when not configured.

    Requires ``FASTAPI_USERS_JWT_SECRET`` (the secret shared with cognee-API)
    and an API base URL (explicit ``api_url`` argument or ``COGNEE_API_URL``).
    Optional: ``MCP_IDENTITY_DB_URL`` / ``MCP_IDENTITY_DB_PATH`` (store),
    ``MCP_COGNEE_JWT_LIFETIME_SECONDS`` (default 600), ``COGNEE_USER_MAP``
    (seed mapping ``email:uuid,email:uuid`` for pre-existing cognee users).
    """
    secret = os.getenv("FASTAPI_USERS_JWT_SECRET")
    api_url = api_url or os.getenv("COGNEE_API_URL")
    if not secret or not api_url:
        return None
    seed_map = parse_user_map(os.getenv("COGNEE_USER_MAP", ""))
    lifetime = int(os.getenv("MCP_COGNEE_JWT_LIFETIME_SECONDS", str(DEFAULT_JWT_LIFETIME_SECONDS)))
    return CogneeIdentityBridge(
        api_url=api_url,
        jwt_secret=secret,
        store_dsn=_store_dsn_from_env(),
        jwt_lifetime_seconds=lifetime,
        seed_map=seed_map,
    )
