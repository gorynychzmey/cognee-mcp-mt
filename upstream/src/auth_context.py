"""Per-request cognee-API token resolution.

In API mode one MCP process can serve many users: each outgoing cognee-API
call must carry the *caller's* token, not only the static ``--api-token``
given at startup. The caller's token is resolved per request:

1. An explicit override set via :func:`set_request_token` (contextvar).
   Used by auth layers that exchange the transport credential for a
   cognee-API token, and by tests.
2. A ``cognee_token`` carried by the authenticated user in the ASGI scope:
   ``scope["user"].access_token.cognee_token``. The SDK's bearer-auth
   middleware puts an ``AuthenticatedUser`` (with ``.access_token``) into
   ``scope["user"]``; the OAuth layer's access-token object additionally
   carries the cognee-API JWT exchanged for the caller's identity. Resolved
   purely via ``getattr`` — no OAuth-module imports. This must precede the
   header step: with the built-in OAuth AS the Bearer header holds OUR
   opaque token, which cognee-API would reject.
3. The ``Authorization: Bearer`` header of the HTTP request that delivered
   the current MCP message. The SDK's streamable-HTTP and SSE transports
   attach the starlette ``Request`` to the per-message ``request_ctx``, so
   this works inside tool handlers even though they run outside the ASGI
   request task.
4. ``None`` — callers fall back to the static token (single-user behaviour
   is unchanged; stdio transport always lands here).
"""

from contextvars import ContextVar, Token
from typing import Optional

from mcp.server.lowlevel.server import request_ctx

_request_token: ContextVar[Optional[str]] = ContextVar("cognee_request_token", default=None)


def set_request_token(token: Optional[str]) -> Token:
    """Explicitly set the caller's token; returns a Token for reset."""
    return _request_token.set(token)


def reset_request_token(token: Token) -> None:
    """Undo a previous :func:`set_request_token`."""
    _request_token.reset(token)


def _token_from_scope_user() -> Optional[str]:
    """Extract an exchanged cognee token from the authenticated ASGI scope user."""
    try:
        ctx = request_ctx.get()
    except LookupError:
        return None
    scope = getattr(getattr(ctx, "request", None), "scope", None)
    if not isinstance(scope, dict):
        return None
    access_token = getattr(scope.get("user"), "access_token", None)
    return getattr(access_token, "cognee_token", None)


def _token_from_request_ctx() -> Optional[str]:
    """Extract a Bearer token from the HTTP request behind the current MCP message."""
    try:
        ctx = request_ctx.get()
    except LookupError:
        return None
    headers = getattr(getattr(ctx, "request", None), "headers", None)
    if headers is None:
        return None
    authorization = headers.get("authorization")
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    return value.strip() or None


def get_request_token() -> Optional[str]:
    """Return the current caller's API token, or None if not in a request."""
    token = _request_token.get()
    if token is not None:
        return token
    token = _token_from_scope_user()
    if token is not None:
        return token
    return _token_from_request_ctx()
