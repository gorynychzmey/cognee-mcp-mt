"""Built-in OAuth 2.1 Authorization Server, delegating login to Google.

The official MCP SDK already ships the whole AS front (RFC 7591 Dynamic Client
Registration, /authorize, /token with PKCE verification, /revoke and the
.well-known metadata endpoints) — it only needs an
``OAuthAuthorizationServerProvider`` implementation. This module provides one
that authenticates the end user at Google (OpenID Connect, scope
``openid email``) and gates access with a Google Workspace domain / email
allowlist, replacing the external ``mcp-auth-proxy`` container:

    Claude.ai -> [this AS] -> Google login -> callback -> our code
    Claude.ai -> /token (PKCE, SDK-verified) -> our access + refresh tokens

Every token is bound to the authenticated user's email. ``load_access_token``
returns a :class:`CogneeAccessToken` carrying that email, and — when a
``token_exchanger`` callable is configured — a cognee-API token for the user,
so downstream layers can forward the caller's identity to cognee-API.

Enable via env (see :func:`build_oauth_from_env`):

- ``MCP_OAUTH_ENABLED``: "true" to enable (default: disabled).
- ``GOOGLE_OAUTH_CLIENT_ID`` / ``GOOGLE_OAUTH_CLIENT_SECRET``: Google OAuth
  web-application credentials; the authorized redirect URI must be
  ``$MCP_PUBLIC_BASE_URL/auth/google/callback``.
- ``MCP_PUBLIC_BASE_URL``: public base URL of this server (the OAuth issuer).
- ``GOOGLE_ALLOWED_WORKSPACES``: comma-separated Workspace (hd) domains.
- ``GOOGLE_ALLOWED_EMAILS``: comma-separated additional individual emails.
  Both lists empty means nobody is allowed (closed by default).
"""

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

import httpx
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from cognee.shared.logging_utils import get_logger

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

try:
    from .oauth_store import OAuthStore
except ImportError:
    from oauth_store import OAuthStore

logger = get_logger()

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

DEFAULT_ACCESS_TOKEN_LIFETIME = 3600  # 1 hour
DEFAULT_REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600  # 30 days
AUTH_CODE_LIFETIME = 300  # 5 minutes
TRANSACTION_TTL = 600  # pending Google logins expire after 10 minutes


class CogneeAccessToken(AccessToken):
    """Access token enriched with the caller's identity for downstream layers."""

    user_email: Optional[str] = None
    cognee_token: Optional[str] = None


class GoogleAuthorizationCode(AuthorizationCode):
    """Authorization code bound to the Google-authenticated user."""

    user_email: Optional[str] = None


class GoogleRefreshToken(RefreshToken):
    """Refresh token bound to the Google-authenticated user."""

    user_email: Optional[str] = None


@dataclass
class _PendingAuthorization:
    """An /authorize request waiting for the user to come back from Google."""

    client_id: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    code_challenge: str
    scopes: list[str]
    client_state: Optional[str]
    resource: Optional[str]
    created_at: float = field(default_factory=time.time)


class GoogleWorkspaceOAuthProvider(
    OAuthAuthorizationServerProvider[GoogleAuthorizationCode, GoogleRefreshToken, CogneeAccessToken]
):
    """OAuth 2.1 AS provider that delegates end-user login to Google.

    The SDK handles the protocol mechanics (DCR, PKCE verification, redirect
    URI validation); this class persists clients/codes/tokens in
    :class:`OAuthStore`, runs the Google leg, and enforces the allowlist.
    """

    def __init__(
        self,
        store: OAuthStore,
        *,
        public_base_url: str,
        google_client_id: str,
        google_client_secret: str,
        allowed_workspaces: Optional[list[str]] = None,
        allowed_emails: Optional[list[str]] = None,
        access_token_lifetime: int = DEFAULT_ACCESS_TOKEN_LIFETIME,
        refresh_token_lifetime: int = DEFAULT_REFRESH_TOKEN_LIFETIME,
        google_auth_url: str = GOOGLE_AUTH_URL,
        google_token_url: str = GOOGLE_TOKEN_URL,
        google_userinfo_url: str = GOOGLE_USERINFO_URL,
        http_client: Optional[httpx.AsyncClient] = None,
        token_exchanger: Optional[Callable[[str], Awaitable[Optional[str]]]] = None,
    ):
        self.store = store
        self.public_base_url = public_base_url.rstrip("/")
        self.google_client_id = google_client_id
        self.google_client_secret = google_client_secret
        self.allowed_workspaces = [w.lower() for w in (allowed_workspaces or [])]
        self.allowed_emails = [e.lower() for e in (allowed_emails or [])]
        self.access_token_lifetime = access_token_lifetime
        self.refresh_token_lifetime = refresh_token_lifetime
        self.google_auth_url = google_auth_url
        self.google_token_url = google_token_url
        self.google_userinfo_url = google_userinfo_url
        self.http_client = http_client or httpx.AsyncClient()
        self.token_exchanger = token_exchanger
        # Pending /authorize transactions, keyed by our own state value. These
        # only need to survive one Google round-trip, so in-memory is enough.
        self._transactions: dict[str, _PendingAuthorization] = {}

    # --- client registration (DCR) ---------------------------------------------

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        return await self.store.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        await self.store.save_client(client_info)
        logger.info(f"OAuth: registered client {client_info.client_id} ({client_info.client_name})")

    # --- authorize: redirect the user to Google ----------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        self._prune_transactions()
        txn_id = secrets.token_urlsafe(32)
        self._transactions[txn_id] = _PendingAuthorization(
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            scopes=params.scopes or [],
            client_state=params.state,
            resource=params.resource,
        )
        return construct_redirect_uri(
            self.google_auth_url,
            client_id=self.google_client_id,
            redirect_uri=f"{self.public_base_url}/auth/google/callback",
            response_type="code",
            scope="openid email",
            state=txn_id,
            access_type="online",
        )

    def _prune_transactions(self) -> None:
        cutoff = time.time() - TRANSACTION_TTL
        stale = [state for state, txn in self._transactions.items() if txn.created_at < cutoff]
        for state in stale:
            del self._transactions[state]

    # --- Google callback: authenticate, allowlist, mint our code -----------------

    async def handle_google_callback(self, request: Request) -> Response:
        """Handle GET /auth/google/callback (registered as an MCP custom route)."""
        self._prune_transactions()
        error = request.query_params.get("error")
        if error:
            logger.warning(f"OAuth: Google returned error on callback: {error}")
            return PlainTextResponse(f"Google sign-in failed: {error}", status_code=400)

        state = request.query_params.get("state")
        code = request.query_params.get("code")
        if not state or not code:
            return PlainTextResponse("Missing state or code parameter", status_code=400)

        txn = self._transactions.pop(state, None)
        if txn is None:
            return PlainTextResponse("Unknown or expired authorization request", status_code=400)

        userinfo = await self._fetch_google_userinfo(code)
        if userinfo is None:
            return PlainTextResponse("Failed to verify Google sign-in", status_code=502)

        email = (userinfo.get("email") or "").lower()
        verified = userinfo.get("email_verified") in (True, "true")
        hd = userinfo.get("hd")
        if not email or not verified or not self._is_allowed(email, hd):
            logger.warning(
                f"OAuth: access denied for {email or '<no email>'} "
                f"(hd={hd}, verified={verified})"
            )
            return PlainTextResponse(
                "Access denied: your Google account is not allowed to use this server.",
                status_code=403,
            )

        our_code = f"mcp_ac_{secrets.token_urlsafe(32)}"
        await self.store.save_auth_code(
            our_code,
            client_id=txn.client_id,
            scopes=txn.scopes,
            expires_at=time.time() + AUTH_CODE_LIFETIME,
            code_challenge=txn.code_challenge,
            redirect_uri=txn.redirect_uri,
            redirect_uri_provided_explicitly=txn.redirect_uri_provided_explicitly,
            user_email=email,
            resource=txn.resource,
        )
        logger.info(f"OAuth: authenticated {email} for client {txn.client_id}")
        return RedirectResponse(
            construct_redirect_uri(txn.redirect_uri, code=our_code, state=txn.client_state),
            status_code=302,
        )

    async def _fetch_google_userinfo(self, code: str) -> Optional[dict]:
        """Exchange the Google code for tokens and fetch the userinfo claims."""
        try:
            token_response = await self.http_client.post(
                self.google_token_url,
                data={
                    "code": code,
                    "client_id": self.google_client_id,
                    "client_secret": self.google_client_secret,
                    "redirect_uri": f"{self.public_base_url}/auth/google/callback",
                    "grant_type": "authorization_code",
                },
            )
            if token_response.status_code != 200:
                logger.error(
                    f"OAuth: Google token exchange failed with {token_response.status_code}"
                )
                return None
            google_access_token = token_response.json().get("access_token")
            if not google_access_token:
                logger.error("OAuth: Google token response had no access_token")
                return None

            userinfo_response = await self.http_client.get(
                self.google_userinfo_url,
                headers={"Authorization": f"Bearer {google_access_token}"},
            )
            if userinfo_response.status_code != 200:
                logger.error(
                    f"OAuth: Google userinfo failed with {userinfo_response.status_code}"
                )
                return None
            return userinfo_response.json()
        except httpx.HTTPError as exc:
            logger.error(f"OAuth: Google request failed: {exc}")
            return None

    def _is_allowed(self, email: str, hd: Optional[str]) -> bool:
        """Allowlist check: explicit email, or Workspace/email domain. Closed by default."""
        if email in self.allowed_emails:
            return True
        domains = {hd.lower()} if hd else set()
        if "@" in email:
            domains.add(email.split("@", 1)[1])
        return any(domain in self.allowed_workspaces for domain in domains)

    # --- code and token exchange ---------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[GoogleAuthorizationCode]:
        record = await self.store.get_auth_code(authorization_code)
        if record is None or record.client_id != client.client_id:
            return None
        return GoogleAuthorizationCode(
            code=authorization_code,
            scopes=record.scopes,
            expires_at=record.expires_at,
            client_id=record.client_id,
            code_challenge=record.code_challenge,
            redirect_uri=AnyUrl(record.redirect_uri),
            redirect_uri_provided_explicitly=record.redirect_uri_provided_explicitly,
            resource=record.resource,
            user_email=record.user_email,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: GoogleAuthorizationCode
    ) -> OAuthToken:
        # Single-use: the atomic delete is the replay check.
        if not await self.store.delete_auth_code(authorization_code.code):
            raise TokenError("invalid_grant", "Authorization code already used or expired")
        return await self._issue_token_pair(
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            user_email=authorization_code.user_email,
            resource=authorization_code.resource,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[GoogleRefreshToken]:
        record = await self.store.get_refresh_token(refresh_token)
        if record is None or record.client_id != client.client_id:
            return None
        return GoogleRefreshToken(
            token=refresh_token,
            client_id=record.client_id,
            scopes=record.scopes,
            expires_at=record.expires_at,
            user_email=record.user_email,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: GoogleRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotation: the old refresh token is burnt atomically before a new pair
        # is issued, so a replayed refresh token fails with invalid_grant.
        if not await self.store.delete_refresh_token(refresh_token.token):
            raise TokenError("invalid_grant", "Refresh token already used or expired")
        return await self._issue_token_pair(
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
            user_email=refresh_token.user_email,
        )

    async def _issue_token_pair(
        self,
        *,
        client_id: str,
        scopes: list[str],
        user_email: Optional[str],
        resource: Optional[str] = None,
    ) -> OAuthToken:
        access_token = f"mcp_at_{secrets.token_urlsafe(32)}"
        refresh_token = f"mcp_rt_{secrets.token_urlsafe(32)}"
        now = int(time.time())
        await self.store.save_access_token(
            access_token,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + self.access_token_lifetime,
            user_email=user_email or "",
            resource=resource,
        )
        await self.store.save_refresh_token(
            refresh_token,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + self.refresh_token_lifetime,
            user_email=user_email or "",
            resource=resource,
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.access_token_lifetime,
            scope=" ".join(scopes) if scopes else None,
            refresh_token=refresh_token,
        )

    # --- resource-server side: bearer token verification -----------------------------

    async def load_access_token(self, token: str) -> Optional[CogneeAccessToken]:
        record = await self.store.get_access_token(token)
        if record is None:
            return None

        cognee_token: Optional[str] = None
        if self.token_exchanger is not None and record.user_email:
            try:
                cognee_token = await self.token_exchanger(record.user_email)
            except Exception as exc:
                # An identity-bridge outage must not turn into a 500 on /mcp:
                # authentication stands, only the cognee identity is missing.
                logger.error(
                    f"OAuth: token exchange for {record.user_email} failed: {exc}"
                )
        return CogneeAccessToken(
            token=token,
            client_id=record.client_id,
            scopes=record.scopes,
            expires_at=record.expires_at,
            resource=record.resource,
            user_email=record.user_email or None,
            cognee_token=cognee_token,
        )

    async def revoke_token(self, token: CogneeAccessToken | GoogleRefreshToken) -> None:
        # RFC 7009: revocation of unknown tokens is a no-op; try both tables so
        # a revoked access token cannot come back through its refresh sibling.
        await self.store.delete_access_token(token.token)
        await self.store.delete_refresh_token(token.token)


def build_oauth_from_env() -> tuple[Optional[GoogleWorkspaceOAuthProvider], Optional[AuthSettings]]:
    """Build the OAuth AS provider and AuthSettings from environment variables.

    Returns (None, None) unless ``MCP_OAUTH_ENABLED=true``. When enabled,
    ``GOOGLE_OAUTH_CLIENT_ID``, ``GOOGLE_OAUTH_CLIENT_SECRET`` and
    ``MCP_PUBLIC_BASE_URL`` are required; a missing one raises ValueError so a
    misconfigured deployment fails at startup instead of running open or dead.
    """
    if os.getenv("MCP_OAUTH_ENABLED", "false").lower() != "true":
        return None, None

    required = ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "MCP_PUBLIC_BASE_URL")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        message = f"MCP_OAUTH_ENABLED=true but required env vars are missing: {', '.join(missing)}"
        logger.error(message)
        raise ValueError(message)

    public_base_url = os.getenv("MCP_PUBLIC_BASE_URL").rstrip("/")
    allowed_workspaces = [
        w.strip() for w in os.getenv("GOOGLE_ALLOWED_WORKSPACES", "").split(",") if w.strip()
    ]
    allowed_emails = [
        e.strip() for e in os.getenv("GOOGLE_ALLOWED_EMAILS", "").split(",") if e.strip()
    ]
    if not allowed_workspaces and not allowed_emails:
        logger.warning(
            "OAuth enabled but GOOGLE_ALLOWED_WORKSPACES and GOOGLE_ALLOWED_EMAILS are both "
            "empty — every sign-in will be rejected (closed by default)"
        )

    provider = GoogleWorkspaceOAuthProvider(
        OAuthStore(),
        public_base_url=public_base_url,
        google_client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
        google_client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
        allowed_workspaces=allowed_workspaces,
        allowed_emails=allowed_emails,
    )
    auth_settings = AuthSettings(
        issuer_url=public_base_url,
        resource_server_url=f"{public_base_url}/mcp",
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            # Claude.ai registers with scope "claudeai" or none at all; give
            # scopeless clients a default so later scoped /authorize calls pass
            # the SDK's client-scope validation. No valid_scopes restriction.
            default_scopes=["claudeai"],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=None,
    )
    logger.info(
        f"OAuth 2.1 AS enabled: issuer={public_base_url}, "
        f"workspaces={allowed_workspaces}, emails={len(allowed_emails)}"
    )
    return provider, auth_settings
