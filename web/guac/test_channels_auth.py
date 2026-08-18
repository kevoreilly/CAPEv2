"""Regression tests for guac-web backend-agnostic websocket auth (guac/channels_auth.py).

The interactive Guacamole attach 500'd on the websocket handshake for every OIDC/allauth
user because channels' stock get_user() load_backend()s the session's exact auth backend
and importing allauth.account.* raises in guac-web (allauth not in guac_settings
INSTALLED_APPS). resolve_session_user must resolve the same User WITHOUT loading the
backend, while still enforcing the session auth-hash gate.
"""
import pytest
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY
from django.contrib.auth.models import AnonymousUser, User

from guac.channels_auth import resolve_session_user


@pytest.mark.django_db
def test_resolve_session_user_resolves_allauth_backed_session():
    """An OIDC/allauth-backed session (the backend that made channels get_user() 500)
    must still resolve to the same User over the websocket."""
    u = User.objects.create_user("wsuser", password="pw-12345")
    session = {
        SESSION_KEY: str(u.pk),
        BACKEND_SESSION_KEY: "allauth.account.auth_backends.AuthenticationBackend",
        HASH_SESSION_KEY: u.get_session_auth_hash(),
    }
    assert resolve_session_user(session) == u


@pytest.mark.django_db
def test_resolve_session_user_resolves_modelbackend_session():
    """Local/superuser (ModelBackend) sessions keep working — single-node/non-OIDC parity."""
    u = User.objects.create_user("localuser", password="pw-12345")
    session = {
        SESSION_KEY: str(u.pk),
        BACKEND_SESSION_KEY: "django.contrib.auth.backends.ModelBackend",
        HASH_SESSION_KEY: u.get_session_auth_hash(),
    }
    assert resolve_session_user(session) == u


@pytest.mark.django_db
def test_resolve_session_user_rejects_tampered_or_missing():
    u = User.objects.create_user("wsuser2", password="pw-12345")
    good = {SESSION_KEY: str(u.pk), HASH_SESSION_KEY: u.get_session_auth_hash()}
    assert resolve_session_user(good) == u

    # tampered / stale auth-hash -> anonymous (session not proven to belong to the user)
    tampered = dict(good, **{HASH_SESSION_KEY: "0" * 64})
    assert isinstance(resolve_session_user(tampered), AnonymousUser)

    # missing hash entirely -> anonymous (do NOT accept on user-id possession alone)
    assert isinstance(resolve_session_user({SESSION_KEY: str(u.pk)}), AnonymousUser)

    # no user id in session -> anonymous
    assert isinstance(resolve_session_user({}), AnonymousUser)

    # unknown user id -> anonymous
    assert isinstance(
        resolve_session_user({SESSION_KEY: "999999", HASH_SESSION_KEY: "x"}), AnonymousUser
    )


@pytest.mark.django_db
def test_resolve_session_user_rejects_inactive_user():
    u = User.objects.create_user("inactive", password="pw-12345")
    session = {SESSION_KEY: str(u.pk), HASH_SESSION_KEY: u.get_session_auth_hash()}
    assert resolve_session_user(session) == u
    u.is_active = False
    u.save()
    assert isinstance(resolve_session_user(session), AnonymousUser)
