"""Regression tests for guac-web backend-agnostic HTTP auth (guac.views.guac_login_required).

Companion to test_channels_auth.py. The websocket path already resolves identity WITHOUT
loading the session's auth backend, but the HTTP console views (guac/views.py) used Django's
stock ``login_required`` -> ``auth.get_user()``, which ``load_backend()``s the session's exact
backend. For an OIDC/allauth session that backend is not in guac-web's AUTHENTICATION_BACKENDS
(guac_settings deliberately does not install the allauth app stack), so ``get_user()`` returned
AnonymousUser and every interactive-console request for an OIDC user was bounced to the login
page -- even though the browser was logged in on the main web. ``guac_login_required`` must
resolve the same User backend-agnostically and redirect only a genuinely anonymous session.
"""
import pytest
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import RequestFactory

from guac.views import guac_login_required


def _view(request):
    return HttpResponse(getattr(request.user, "username", ""))


@pytest.mark.django_db
def test_guac_login_required_resolves_allauth_session_without_backend():
    """An OIDC/allauth-backed session -- the exact backend guac-web cannot load -- must
    resolve to the real User over HTTP, with no login redirect."""
    u = User.objects.create_user("consoleuser", password="pw-12345")
    request = RequestFactory().get("/guac/1/abc/")
    request.session = {
        SESSION_KEY: str(u.pk),
        BACKEND_SESSION_KEY: "allauth.account.auth_backends.AuthenticationBackend",
        HASH_SESSION_KEY: u.get_session_auth_hash(),
    }
    response = guac_login_required(_view)(request)
    assert response.status_code == 200
    assert response.content == b"consoleuser"
    assert request.user == u


@pytest.mark.django_db
def test_guac_login_required_resolves_modelbackend_session():
    """Local/superuser (ModelBackend) sessions keep working -- non-OIDC / single-node parity."""
    u = User.objects.create_user("localadmin", password="pw-12345")
    request = RequestFactory().get("/guac/1/abc/")
    request.session = {
        SESSION_KEY: str(u.pk),
        BACKEND_SESSION_KEY: "django.contrib.auth.backends.ModelBackend",
        HASH_SESSION_KEY: u.get_session_auth_hash(),
    }
    response = guac_login_required(_view)(request)
    assert response.status_code == 200
    assert request.user == u


@pytest.mark.django_db
def test_guac_login_required_redirects_anonymous():
    """No/invalid session identity -> redirect to the login page, exactly like login_required
    (fails closed: an unresolved session never reaches the console view)."""
    request = RequestFactory().get("/guac/1/abc/")
    request.session = {}  # anonymous
    response = guac_login_required(_view)(request)
    assert response.status_code == 302

    # a tampered/stale auth-hash must also fail closed (not just a missing session)
    u = User.objects.create_user("staleuser", password="pw-12345")
    request = RequestFactory().get("/guac/1/abc/")
    request.session = {SESSION_KEY: str(u.pk), HASH_SESSION_KEY: "0" * 64}
    response = guac_login_required(_view)(request)
    assert response.status_code == 302


@pytest.mark.django_db
def test_direct_vnc_views_reject_non_admin_viewer(monkeypatch):
    """Direct VNC HTTP views must enforce viewer.see_all even without TenancyMiddleware."""
    import types
    import guac.views as guac_views

    monkeypatch.setattr(guac_views, "is_vnc_console_enabled", lambda: True)
    monkeypatch.setattr(
        guac_views,
        "_resolve_guac_viewer",
        lambda _req: types.SimpleNamespace(see_all=False),
    )

    u = User.objects.create_user("regularuser", password="pw-12345")
    session = {
        SESSION_KEY: str(u.pk),
        BACKEND_SESSION_KEY: "django.contrib.auth.backends.ModelBackend",
        HASH_SESSION_KEY: u.get_session_auth_hash(),
    }

    for view_fn, kwargs in (
        (guac_views.direct_vnc_host_port, {"host": "127.0.0.1", "port": 5900}),
        (guac_views.direct_vnc_vm, {"vm_name": "win10_1"}),
        (guac_views.direct_vnc_vm_start, {"vm_name": "win10_1"}),
        (guac_views.direct_vnc_vm_shutdown, {"vm_name": "win10_1"}),
        (guac_views.direct_vnc_vm_route, {"vm_name": "win10_1"}),
        (guac_views.direct_vnc_vm_snapshots_list, {"vm_name": "win10_1"}),
        (guac_views.direct_vnc_vm_snapshot_create, {"vm_name": "win10_1"}),
        (guac_views.direct_vnc_vm_snapshot_delete, {"vm_name": "win10_1"}),
    ):
        req = RequestFactory().post("/guac/direct/")
        req.user = u
        req.session = dict(session)
        resp = view_fn(req, **kwargs)
        assert resp.status_code == 403

