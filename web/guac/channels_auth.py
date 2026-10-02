"""Backend-agnostic websocket authentication for guac-web.

guac-web is a deliberately MINIMAL ASGI process (``web.guac_settings``) that shares the
main web's session/auth store so the live-VM Guacamole tunnel resolves to the SAME
logged-in ``User`` the browser holds on the main web. channels' stock
``AuthMiddlewareStack`` populates ``scope["user"]`` via ``django.contrib.auth.get_user()``,
which ``load_backend()``s the EXACT auth backend the session was created with. For an
OIDC/allauth session that means importing ``allauth.account.*`` — but ``guac_settings``
does not (and should not) install the allauth app stack, so the import raises::

    RuntimeError: Model class allauth.account.models.EmailAddress doesn't declare an
    explicit app_label and isn't in an application in INSTALLED_APPS

and the websocket handshake 500s for every OIDC user. Local/superuser sessions use
``ModelBackend`` and load fine, so it looked like interactive attach worked — it only
worked for local admins.

The tunnel only needs the caller's IDENTITY (to gate ``can_manage_task``), never the auth
METHOD. So resolve the ``User`` straight from the session — user id plus the session
auth-hash check, the same security guarantee ``django.contrib.auth.get_user`` enforces —
without loading the session's backend. This works for ANY backend (ModelBackend, allauth,
future) and keeps guac-web free of the allauth app stack.
"""
from channels.db import database_sync_to_async
from channels.sessions import CookieMiddleware, SessionMiddleware
from django.contrib.auth import HASH_SESSION_KEY, SESSION_KEY, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.utils.crypto import constant_time_compare


def resolve_session_user(session):
    """Return the authenticated ``User`` for a Django ``session`` mapping, else ``AnonymousUser``.

    Backend-agnostic: reads the user id from the session and verifies the session
    auth-hash against the user (identical to the verification
    ``django.contrib.auth.get_user`` performs after loading the backend), but never
    ``load_backend()``s the session's auth backend. ``session`` may be any Mapping that
    supports ``__getitem__`` / ``.get`` (a Django ``SessionBase`` or a plain dict in tests).
    """
    try:
        user_id = session[SESSION_KEY]
    except (KeyError, TypeError):
        return AnonymousUser()

    user_model = get_user_model()
    try:
        user = user_model._default_manager.get(pk=user_id)
    except (user_model.DoesNotExist, ValueError, TypeError):
        return AnonymousUser()

    if not user.is_active:
        return AnonymousUser()

    # Session auth-hash check: proves the session belongs to THIS user and has not been
    # invalidated (password change / logout). This is the security gate — the backend
    # loading channels does is incidental (ModelBackend.get_user is just a pk lookup, which
    # is what we do above). Shared SECRET_KEY => hashes match across the main web and guac-web.
    session_hash = session.get(HASH_SESSION_KEY)
    if not (
        session_hash
        and hasattr(user, "get_session_auth_hash")
        and constant_time_compare(session_hash, user.get_session_auth_hash())
    ):
        return AnonymousUser()

    return user


class BackendAgnosticAuthMiddleware:
    """Populate ``scope["user"]`` from the session without loading its auth backend.

    Must sit inside ``SessionMiddleware`` (it reads ``scope["session"]``).
    """

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        scope["user"] = await database_sync_to_async(resolve_session_user)(scope["session"])
        return await self.inner(scope, receive, send)


def GuacAuthMiddlewareStack(inner):
    """Drop-in replacement for ``channels.auth.AuthMiddlewareStack``.

    Same cookie+session unwrap, but resolves the user backend-agnostically (see module
    docstring) so an OIDC/allauth session no longer crashes guac-web's websocket handshake.
    """
    return CookieMiddleware(SessionMiddleware(BackendAgnosticAuthMiddleware(inner)))
