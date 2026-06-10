import logging
import requests
import threading
import time

from allauth.account.adapter import DefaultAccountAdapter
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.signals import email_confirmed, user_logged_in, user_signed_up
from django import forms
from django.conf import settings
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.shortcuts import render
from django.utils.translation import gettext as _


log = logging.getLogger(__name__)


# ── OIDC IdP-response cache ──────────────────────────────────────────────────
# allauth fetches the OIDC discovery document and the JWKS on every login
# (cached only per-adapter, i.e. per-request) with no timeouts. A transient
# IdP hiccup or slow response then surfaces as a 500 to the user.
#
# This cache makes both fetches:
#   • process-wide with a 1-hour TTL (5 minutes for JWKS so key rotation is
#     picked up quickly)
#   • bounded by 5 s connect / 10 s read timeouts
#   • served from a stale entry on transient fetch errors instead of crashing
#   • issuer-validated per RFC 8414 §3 (discovery only)
#   • double-checked-locked so concurrent cold-start requests still see fresh data

_OIDC_CACHE: dict = {}
_OIDC_CACHE_LOCK = threading.Lock()
_DISCOVERY_TTL = 3600
_JWKS_TTL = 300
# Asymmetric signing algorithms accepted for ID tokens when the provider's
# discovery doc doesn't advertise `id_token_signing_alg_values_supported`.
# Deliberately excludes "none" and the HMAC family to avoid algorithm-confusion.
_DEFAULT_OIDC_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]


def _cached_fetch(cache_key: str, url: str, ttl: int, validate=None) -> dict:
    """Fetch `url` as JSON with a process-wide TTL cache and stale-on-error.

    `validate(doc)` runs once on a freshly-fetched doc and may raise to reject
    it; on rejection we fall back to the previously cached doc if any.
    """
    now = time.monotonic()
    with _OIDC_CACHE_LOCK:
        entry = _OIDC_CACHE.get(cache_key)
        if entry and (now - entry["ts"]) < ttl:
            return entry["doc"]

    try:
        resp = requests.get(url, timeout=(5, 10))
        resp.raise_for_status()
        doc = resp.json()
        if validate is not None:
            validate(doc)
    except (requests.RequestException, ValueError) as e:
        # Re-read under the lock: another thread may have populated the cache
        # while our fetch was in flight (concurrent cold start). Prefer any
        # cached value — stale or freshly-won — over failing the login.
        with _OIDC_CACHE_LOCK:
            latest = _OIDC_CACHE.get(cache_key)
        if latest is not None:
            log.warning(
                "OIDC fetch failed for %s (%s); serving cached value",
                url, e,
            )
            return latest["doc"]
        log.error("OIDC fetch failed for %s with no cached fallback: %s", url, e)
        raise

    with _OIDC_CACHE_LOCK:
        existing = _OIDC_CACHE.get(cache_key)
        if not existing or (time.monotonic() - existing["ts"]) >= ttl:
            _OIDC_CACHE[cache_key] = {"doc": doc, "ts": time.monotonic()}
        else:
            doc = existing["doc"]

    return doc


def _get_cached_openid_config(server_url: str) -> dict:
    def _validate_issuer(doc):
        expected = server_url.replace("/.well-known/openid-configuration", "").rstrip("/")
        actual = (doc.get("issuer") or "").rstrip("/")
        if actual and actual != expected:
            raise ValueError(
                f"OIDC discovery issuer mismatch: expected {expected!r}, got {actual!r}"
            )

    return _cached_fetch(
        cache_key=f"discovery:{server_url}",
        url=server_url,
        ttl=_DISCOVERY_TTL,
        validate=_validate_issuer,
    )


def _get_cached_jwks(jwks_url: str) -> dict:
    return _cached_fetch(
        cache_key=f"jwks:{jwks_url}",
        url=jwks_url,
        ttl=_JWKS_TTL,
    )


try:
    from allauth.socialaccount.providers.openid_connect.views import (
        OpenIDConnectOAuth2Adapter as _BaseOIDCAdapter,
    )
    from allauth.socialaccount.providers.openid_connect.provider import (
        OpenIDConnectProvider as _BaseOIDCProvider,
    )
    from allauth.socialaccount.internal import jwtkit

    class CachedOpenIDConnectOAuth2Adapter(_BaseOIDCAdapter):
        """Serves the OIDC discovery doc and JWKS from a process-level cache,
        with bounded timeouts and stale-on-error fallback. Without this an IdP
        blip produces a 500 on the login flow."""

        @property
        def openid_config(self):
            if not hasattr(self, "_openid_config"):
                self._openid_config = _get_cached_openid_config(
                    self.get_provider().server_url
                )
            return self._openid_config

        def _decode_id_token(self, app, id_token):
            # Mirror allauth's default but route JWKS through our cache.
            verify_signature = not self.did_fetch_access_token
            keys_url = self.openid_config["jwks_uri"]
            issuer = self.openid_config["issuer"]
            if not verify_signature:
                return jwtkit.verify_and_decode(
                    credential=id_token,
                    keys_url=keys_url,
                    issuer=issuer,
                    audience=app.client_id,
                    lookup_kid=jwtkit.lookup_kid_jwk,
                    verify_signature=verify_signature,
                )

            import jwt as _jwt
            header = _jwt.get_unverified_header(id_token)
            kid = header["kid"]
            keys_data = _get_cached_jwks(keys_url)
            key = jwtkit.lookup_kid_jwk(keys_data, kid)
            if key is None:
                # cache miss on a freshly-rotated kid — force a refresh
                with _OIDC_CACHE_LOCK:
                    _OIDC_CACHE.pop(f"jwks:{keys_url}", None)
                keys_data = _get_cached_jwks(keys_url)
                key = jwtkit.lookup_kid_jwk(keys_data, kid)
            if key is None:
                from allauth.socialaccount.providers.oauth2.client import OAuth2Error
                raise OAuth2Error(f"Invalid 'kid': '{kid}'")
            # Pin accepted algorithms to the provider's advertised set rather
            # than reflecting the token header's untrusted `alg`. PyJWT rejects
            # a token whose alg isn't in this list, blocking "none"/HS* confusion.
            allowed_algs = self.openid_config.get("id_token_signing_alg_values_supported") or _DEFAULT_OIDC_ALGS
            data = _jwt.decode(
                id_token, key=key, algorithms=allowed_algs,
                issuer=issuer, audience=app.client_id,
                leeway=30,
            )
            jwtkit.verify_jti(data)
            return data

    class CachedOpenIDConnectProvider(_BaseOIDCProvider):
        """OpenID Connect provider using the cached adapter.

        Registered via SOCIALACCOUNT_PROVIDERS["openid_connect"]["provider_class"]
        in settings.py — the officially-supported allauth override path.
        """
        oauth2_adapter_class = CachedOpenIDConnectOAuth2Adapter

        @classmethod
        def get_package(cls):
            # allauth derives the URL module from get_package(); must point at
            # the real openid_connect package so its urls.py is picked up by
            # build_provider_urlpatterns(), not this module's package ("web").
            return "allauth.socialaccount.providers.openid_connect"

except ImportError:
    pass  # openid_connect provider not installed — no-op


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_groups(extra: dict) -> set:
    """Return the set of IdP group names from token extra data."""
    oidc_cfg = getattr(settings, "OIDC_CFG", None) or {}
    claim = oidc_cfg.get("groups_claim") or "groups"
    raw = extra.get(claim) or []
    if isinstance(raw, str):
        raw = [raw]
    elif not isinstance(raw, (list, tuple, set)):
        # Unexpected claim shape (int/bool/dict/…) — don't crash the login.
        log.warning("OIDC groups claim %r has unexpected type %s; ignoring", claim, type(raw).__name__)
        return set()
    return {g for g in raw if isinstance(g, str)}


def _group_set(config_key: str) -> set:
    """Parse a comma-separated group list from OIDC_CFG into a set."""
    oidc_cfg = getattr(settings, "OIDC_CFG", None) or {}
    return {
        g.strip()
        for g in (oidc_cfg.get(config_key) or "").split(",")
        if g.strip()
    }


def _apply_idp_roles_and_email(user, extra: dict) -> bool:
    """Reconcile a user's email and is_staff/is_superuser against the IdP's
    claims/groups, mutating `user` in place. Returns True if anything changed
    (the caller is responsible for saving).

    Role mapping is applied only when admin_groups / superadmin_groups are
    configured; otherwise roles are left untouched so they can be managed
    manually in Django. When configured, membership is authoritative — a user
    removed from the admin group in the IdP is demoted on their next login.

    Guard: if the groups claim is entirely *absent* from the token (scope or
    claim-mapping misconfiguration, or a provider that drops it), role
    reconciliation is skipped rather than silently demoting everyone. A present
    but empty claim is honoured (the user really is in no groups → demote).
    """
    changed = False

    email = extra.get("email") or ""
    if email and user.email != email:
        user.email = email
        changed = True

    admin_groups = _group_set("admin_groups")
    super_groups = _group_set("superadmin_groups")
    if admin_groups or super_groups:
        oidc_cfg = getattr(settings, "OIDC_CFG", None) or {}
        claim = oidc_cfg.get("groups_claim") or "groups"
        if claim not in extra:
            log.warning(
                "OIDC groups claim %r absent from token for %s; skipping role reconciliation",
                claim, user.username,
            )
        else:
            user_groups = _extract_groups(extra)
            new_staff = bool(user_groups & (admin_groups | super_groups))
            new_super = bool(user_groups & super_groups)
            if user.is_staff != new_staff or user.is_superuser != new_super:
                user.is_staff = new_staff
                user.is_superuser = new_super
                changed = True

    return changed


# ── Account adapters ──────────────────────────────────────────────────────────

disposable_domain_list = []
if hasattr(settings, "DISPOSABLE_DOMAIN_LIST"):
    with open(settings.DISPOSABLE_DOMAIN_LIST, "r") as f:
        disposable_domain_list = [domain.strip() for domain in f]


class DisposableEmails(DefaultAccountAdapter):
    def clean_email(self, email):
        if email.rsplit("@", 1)[-1] in disposable_domain_list:
            raise forms.ValidationError("Admin banned disposable email services")
        return email

    def is_open_for_signup(self, request):
        return settings.REGISTRATION_ENABLED


if not settings.EMAIL_CONFIRMATION:

    @receiver(user_signed_up)
    def user_signed_up_(request, user, **kwargs):
        user.is_active = not settings.MANUAL_APPROVE
        user.save()


@receiver(email_confirmed)
def email_confirmed_(request, email_address, **kwargs):
    user = User.objects.get(email=email_address.email)
    user.is_active = not settings.MANUAL_APPROVE
    user.save()


class MySocialAccountAdapter(DefaultSocialAccountAdapter):

    def pre_social_login(self, request, sociallogin):
        """Reject IdP accounts whose email domain doesn't match the configured
        allowlist. Silently skipped when social_auth_email_domain is blank.

        Raises ImmediateHttpResponse — caught by allauth's complete_login
        wrapper and rendered as a user-facing error page (a bare
        ValidationError here would bubble up as a 500)."""
        user_email = sociallogin.account.extra_data.get("email") or ""
        if settings.SOCIAL_AUTH_EMAIL_DOMAIN:
            if not user_email:
                # Fail closed: a domain allowlist is configured but the IdP sent
                # no email, so we can't verify the domain. Don't provision.
                raise ImmediateHttpResponse(
                    render(
                        request,
                        "socialaccount/authentication_error.html",
                        {"reason": _("An email address is required to sign in.")},
                        status=403,
                    )
                )
            domain = user_email.rsplit("@", 1)[-1]
            if domain != settings.SOCIAL_AUTH_EMAIL_DOMAIN:
                raise ImmediateHttpResponse(
                    render(
                        request,
                        "socialaccount/authentication_error.html",
                        {"reason": _("Please use an email with domain: %(domain)s")
                         % {"domain": settings.SOCIAL_AUTH_EMAIL_DOMAIN}},
                        status=403,
                    )
                )

    def is_open_for_signup(self, request, sociallogin):
        """Gate account provisioning on IdP group membership.

        When required_groups is blank, any IdP-authenticated user gets a CAPE
        account (appropriate when the Okta app assignment is the access gate).
        When set, only users in at least one listed group are provisioned —
        useful when the app is assigned broadly but CAPE access should be
        restricted to a subset.
        """
        required = _group_set("required_groups")
        if not required:
            return True
        return bool(_extract_groups(sociallogin.account.extra_data or {}) & required)

    def save_user(self, request, sociallogin, form=None):
        """Provision a new SSO user: derive a stable username and apply the
        initial email + IdP-group roles.

        This runs once, when the social identity is first linked. Email and
        role reconciliation on *subsequent* logins is handled by the
        ``_reconcile_sso_user_on_login`` receiver below — allauth does not call
        save_user for returning users — so changes to a user's IdP group
        membership (e.g. removal from an admin group) take effect on their next
        sign-in.

        Username: derived from the email local-part. If that collides with an
        existing account (two identities sharing a local-part across different
        domains), a short suffix from the IdP subject claim — or the user's pk
        if no subject is present — is appended to guarantee uniqueness.
        """
        user = super().save_user(request, sociallogin, form)
        extra = sociallogin.account.extra_data or {}

        # ── username (provisioning only — kept stable across later logins) ──
        identifier = (
            extra.get("email")
            or extra.get("preferred_username")
            or extra.get("sub")
            or user.username
            or ""
        )
        if identifier:
            base = (identifier.split("@")[0] if "@" in identifier else identifier)[:150]
            if User.objects.filter(username=base).exclude(pk=user.pk).exists():
                # Reserve room for the suffix so truncation can't drop the bit
                # that makes the name unique (and can't exceed the 150 limit).
                suffix = "_" + ((extra.get("sub") or "")[:8] or str(user.pk))
                base = base[: 150 - len(suffix)] + suffix
            user.username = base

        _apply_idp_roles_and_email(user, extra)
        user.save()
        return user


@receiver(user_logged_in)
def _reconcile_sso_user_on_login(sender, request, user, **kwargs):
    """Reconcile email + IdP-group roles on every SSO login.

    allauth fires ``user_logged_in`` after a successful login and, for social
    logins, passes the ``sociallogin``. Because ``save_user`` only runs at first
    provisioning, this receiver is what makes role demotion/promotion and email
    changes actually propagate when a returning user's IdP attributes change.
    Local (non-SSO) logins carry no ``sociallogin`` and are left untouched.
    """
    sociallogin = kwargs.get("sociallogin")
    if sociallogin is None:
        return
    extra = getattr(sociallogin.account, "extra_data", None) or {}
    if _apply_idp_roles_and_email(user, extra):
        user.save()
