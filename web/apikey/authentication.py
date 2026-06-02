"""DRF authentication class backed by the multi-key ``ApiKey`` model.

Wire-format compatible with DRF's built-in ``TokenAuthentication`` —
both expect ``Authorization: Token <key>``. Falls through to the legacy
``rest_framework.authentication.TokenAuthentication`` when a key isn't
found in our model, so any tokens previously issued via
``/apiv2/api-token-auth/`` keep working without migration.
"""

from django.utils import timezone
from rest_framework.authentication import (
    BaseAuthentication,
    TokenAuthentication,
    get_authorization_header,
)
from rest_framework.exceptions import AuthenticationFailed

from .models import ApiKey, hash_key


class ApiKeyAuthentication(BaseAuthentication):
    """Authenticate via ``Authorization: Token <key>``.

    Lookup order:
      1. ``ApiKey`` model (per-user, labeled, individually revocable)
      2. DRF's legacy ``Token`` model (one-token-per-user, kept for back-compat)

    Failures in (1) — invalid key, revoked key, disabled user — return 401
    immediately rather than falling through, so an attacker can't probe
    the legacy table by sending a key that happens to look like one of
    ours but matches a legacy token.
    """

    keyword = "Token"

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword.lower().encode():
            # Not our header; let other auth classes handle it.
            return None
        if len(auth) == 1:
            raise AuthenticationFailed("Invalid token header. No credentials provided.")
        if len(auth) > 2:
            raise AuthenticationFailed("Invalid token header. Token string should not contain spaces.")
        try:
            key = auth[1].decode()
        except UnicodeError:
            raise AuthenticationFailed("Invalid token header. Token string contains invalid characters.")

        # Try our multi-key model first. We store only the SHA-256 hash of the
        # raw key, so hash the presented token before looking it up.
        try:
            apikey = ApiKey.objects.select_related("user").get(key=hash_key(key))
        except ApiKey.DoesNotExist:
            apikey = None

        if apikey is not None:
            if apikey.revoked_at is not None:
                raise AuthenticationFailed("API key has been revoked.")
            if not apikey.user.is_active:
                # Defense in depth: even if the disable-cascade signal didn't
                # fire (e.g. user deactivated via direct SQL), the runtime
                # check still shuts the key down.
                raise AuthenticationFailed("User inactive or deleted.")
            # Throttle last_used_at writes to at most once per minute. Writing
            # on every request causes needless write load and lock contention,
            # especially painful on SQLite (CAPE's default web-auth DB).
            now = timezone.now()
            if apikey.last_used_at is None or (now - apikey.last_used_at).total_seconds() > 60:
                ApiKey.objects.filter(pk=apikey.pk).update(last_used_at=now)
            return (apikey.user, apikey)

        # Fall through to the legacy DRF Token model. Anyone with an
        # existing CAPE-issued token continues to authenticate normally.
        return TokenAuthentication().authenticate_credentials(key)

    def authenticate_header(self, request):
        return self.keyword
