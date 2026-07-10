"""Persistent storage for the built-in OAuth 2.1 Authorization Server.

Holds everything the AS must remember across restarts: dynamically registered
clients (RFC 7591 DCR), authorization codes, access tokens and refresh tokens.
Backed by SQLAlchemy async so the same code runs on SQLite (default, via
aiosqlite) and Postgres (via asyncpg) — the backend is chosen purely by DSN.

Security properties:

- Token and code *values* are never persisted: rows are keyed by the sha256
  hex digest of the value, so a leaked database does not leak usable tokens.
- Expired rows are lazily purged on every lookup (``DELETE WHERE expires_at <
  now``), so the tables do not grow without bound.

Configuration (used by the default constructor):

- ``MCP_OAUTH_DB_URL``: full SQLAlchemy async DSN
  (e.g. ``postgresql+asyncpg://user:pass@host/db``). Takes precedence.
- ``MCP_OAUTH_DB_PATH``: path of the SQLite file (default ``./oauth.db``)
  used when no DSN is given.
"""

import asyncio
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import Boolean, Column, Float, MetaData, String, Table, Text, delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp.shared.auth import OAuthClientInformationFull

metadata = MetaData()

oauth_clients = Table(
    "oauth_clients",
    metadata,
    Column("client_id", String(255), primary_key=True),
    Column("client_metadata", Text, nullable=False),
)

oauth_auth_codes = Table(
    "oauth_auth_codes",
    metadata,
    Column("code_hash", String(64), primary_key=True),
    Column("client_id", String(255), nullable=False),
    Column("scopes", Text, nullable=False, default=""),
    Column("expires_at", Float, nullable=False),
    Column("code_challenge", Text, nullable=False),
    Column("redirect_uri", Text, nullable=False),
    Column("redirect_uri_provided_explicitly", Boolean, nullable=False),
    Column("user_email", Text, nullable=False),
    Column("resource", Text, nullable=True),
)

oauth_access_tokens = Table(
    "oauth_access_tokens",
    metadata,
    Column("token_hash", String(64), primary_key=True),
    Column("client_id", String(255), nullable=False),
    Column("scopes", Text, nullable=False, default=""),
    Column("expires_at", Float, nullable=True),
    Column("user_email", Text, nullable=False),
    Column("resource", Text, nullable=True),
)

oauth_refresh_tokens = Table(
    "oauth_refresh_tokens",
    metadata,
    Column("token_hash", String(64), primary_key=True),
    Column("client_id", String(255), nullable=False),
    Column("scopes", Text, nullable=False, default=""),
    Column("expires_at", Float, nullable=True),
    Column("user_email", Text, nullable=False),
    Column("resource", Text, nullable=True),
)


@dataclass
class StoredAuthCode:
    """An authorization code row (the code value itself is never stored)."""

    client_id: str
    scopes: list[str]
    expires_at: float
    code_challenge: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    user_email: str
    resource: Optional[str] = None


@dataclass
class StoredToken:
    """An access/refresh token row (the token value itself is never stored)."""

    client_id: str
    scopes: list[str]
    expires_at: Optional[int]
    user_email: str
    resource: Optional[str] = None


def _default_dsn() -> str:
    dsn = os.getenv("MCP_OAUTH_DB_URL")
    if dsn:
        return dsn
    db_path = os.getenv("MCP_OAUTH_DB_PATH", "./oauth.db")
    return f"sqlite+aiosqlite:///{db_path}"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _join_scopes(scopes: list[str]) -> str:
    return " ".join(scopes)


def _split_scopes(raw: str) -> list[str]:
    return raw.split() if raw else []


class OAuthStore:
    """Async CRUD over the OAuth AS tables, with lazy schema creation."""

    def __init__(self, dsn: Optional[str] = None):
        self._dsn = dsn or _default_dsn()
        self._engine: Optional[AsyncEngine] = None
        self._schema_ready = False
        self._init_lock = asyncio.Lock()

    async def _get_engine(self) -> AsyncEngine:
        """Create the engine and the schema on first use."""
        if self._engine is None or not self._schema_ready:
            async with self._init_lock:
                if self._engine is None:
                    self._engine = create_async_engine(self._dsn)
                if not self._schema_ready:
                    async with self._engine.begin() as conn:
                        await conn.run_sync(metadata.create_all)
                    self._schema_ready = True
        return self._engine

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._schema_ready = False

    # --- clients (DCR) --------------------------------------------------------

    async def save_client(self, client_info: OAuthClientInformationFull) -> None:
        engine = await self._get_engine()
        async with engine.begin() as conn:
            await conn.execute(
                delete(oauth_clients).where(oauth_clients.c.client_id == client_info.client_id)
            )
            await conn.execute(
                oauth_clients.insert().values(
                    client_id=client_info.client_id,
                    client_metadata=client_info.model_dump_json(),
                )
            )

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        engine = await self._get_engine()
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(oauth_clients.c.client_metadata).where(
                        oauth_clients.c.client_id == client_id
                    )
                )
            ).first()
        if row is None:
            return None
        return OAuthClientInformationFull.model_validate_json(row.client_metadata)

    # --- authorization codes ---------------------------------------------------

    async def save_auth_code(
        self,
        code: str,
        *,
        client_id: str,
        scopes: list[str],
        expires_at: float,
        code_challenge: str,
        redirect_uri: str,
        redirect_uri_provided_explicitly: bool,
        user_email: str,
        resource: Optional[str] = None,
    ) -> None:
        engine = await self._get_engine()
        async with engine.begin() as conn:
            await conn.execute(
                oauth_auth_codes.insert().values(
                    code_hash=_hash(code),
                    client_id=client_id,
                    scopes=_join_scopes(scopes),
                    expires_at=expires_at,
                    code_challenge=code_challenge,
                    redirect_uri=redirect_uri,
                    redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
                    user_email=user_email,
                    resource=resource,
                )
            )

    async def get_auth_code(self, code: str) -> Optional[StoredAuthCode]:
        engine = await self._get_engine()
        async with engine.begin() as conn:
            await conn.execute(
                delete(oauth_auth_codes).where(oauth_auth_codes.c.expires_at < time.time())
            )
            row = (
                await conn.execute(
                    select(oauth_auth_codes).where(oauth_auth_codes.c.code_hash == _hash(code))
                )
            ).first()
        if row is None:
            return None
        return StoredAuthCode(
            client_id=row.client_id,
            scopes=_split_scopes(row.scopes),
            expires_at=row.expires_at,
            code_challenge=row.code_challenge,
            redirect_uri=row.redirect_uri,
            redirect_uri_provided_explicitly=row.redirect_uri_provided_explicitly,
            user_email=row.user_email,
            resource=row.resource,
        )

    async def delete_auth_code(self, code: str) -> bool:
        """Delete a code; returns False when it was already gone (single-use check)."""
        engine = await self._get_engine()
        async with engine.begin() as conn:
            result = await conn.execute(
                delete(oauth_auth_codes).where(oauth_auth_codes.c.code_hash == _hash(code))
            )
        return result.rowcount > 0

    # --- access / refresh tokens -------------------------------------------------

    async def save_access_token(
        self,
        token: str,
        *,
        client_id: str,
        scopes: list[str],
        expires_at: Optional[int],
        user_email: str,
        resource: Optional[str] = None,
    ) -> None:
        await self._save_token(
            oauth_access_tokens, token, client_id, scopes, expires_at, user_email, resource
        )

    async def get_access_token(self, token: str) -> Optional[StoredToken]:
        return await self._get_token(oauth_access_tokens, token)

    async def delete_access_token(self, token: str) -> bool:
        return await self._delete_token(oauth_access_tokens, token)

    async def save_refresh_token(
        self,
        token: str,
        *,
        client_id: str,
        scopes: list[str],
        expires_at: Optional[int],
        user_email: str,
        resource: Optional[str] = None,
    ) -> None:
        await self._save_token(
            oauth_refresh_tokens, token, client_id, scopes, expires_at, user_email, resource
        )

    async def get_refresh_token(self, token: str) -> Optional[StoredToken]:
        return await self._get_token(oauth_refresh_tokens, token)

    async def delete_refresh_token(self, token: str) -> bool:
        return await self._delete_token(oauth_refresh_tokens, token)

    async def _save_token(
        self,
        table: Table,
        token: str,
        client_id: str,
        scopes: list[str],
        expires_at: Optional[int],
        user_email: str,
        resource: Optional[str],
    ) -> None:
        engine = await self._get_engine()
        async with engine.begin() as conn:
            await conn.execute(
                table.insert().values(
                    token_hash=_hash(token),
                    client_id=client_id,
                    scopes=_join_scopes(scopes),
                    expires_at=expires_at,
                    user_email=user_email,
                    resource=resource,
                )
            )

    async def _get_token(self, table: Table, token: str) -> Optional[StoredToken]:
        engine = await self._get_engine()
        async with engine.begin() as conn:
            await conn.execute(
                delete(table).where(
                    table.c.expires_at.is_not(None), table.c.expires_at < time.time()
                )
            )
            row = (
                await conn.execute(select(table).where(table.c.token_hash == _hash(token)))
            ).first()
        if row is None:
            return None
        return StoredToken(
            client_id=row.client_id,
            scopes=_split_scopes(row.scopes),
            expires_at=int(row.expires_at) if row.expires_at is not None else None,
            user_email=row.user_email,
            resource=row.resource,
        )

    async def _delete_token(self, table: Table, token: str) -> bool:
        engine = await self._get_engine()
        async with engine.begin() as conn:
            result = await conn.execute(delete(table).where(table.c.token_hash == _hash(token)))
        return result.rowcount > 0
