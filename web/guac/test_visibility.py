import pytest
from django.contrib.auth.models import User
from django.http import HttpResponse

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)



class ForeignTask:
    id = 1
    user_id = 999      # owned by another tenant's user
    tenant_id = 10
    visibility = "private"


class PublicForeignTask:
    id = 1
    user_id = 999      # owned by someone else, but PUBLIC (readable by everyone)
    tenant_id = 10
    visibility = "public"


@pytest.mark.django_db
def test_guac_index_denies_cross_tenant(cape_db, mt_enabled, monkeypatch, client):
    """guac.index mints a live-VM session token from task_id. A cross-tenant
    viewer must be denied BEFORE any token is minted (no tunnel into another
    tenant's running malware VM)."""
    import guac.views as gv

    minted = []
    monkeypatch.setattr(gv.db, "view_task", lambda *a, **k: ForeignTask())
    monkeypatch.setattr(gv.db, "create_guac_session",
                        lambda **k: minted.append(k) or object(), raising=False)
    client.force_login(User.objects.create_user("gu", "gu@x.com", "x"))  # tenant-less

    r = client.get("/guac/1/AAAA/")
    assert minted == []              # no session token minted for a non-viewable task
    assert r.status_code == 200      # rendered the guac error page, not the session page


@pytest.mark.django_db
def test_guac_index_denies_readonly_viewer(cape_db, mt_enabled, monkeypatch, client):
    """A read-only VIEWER of a PUBLIC task (can_view_task=True) is NOT a manager,
    so must be denied the live-VM mint: keyboard/mouse/framebuffer control is a
    task action, gated on can_manage_task (owner/tenant-admin/break-glass), not
    passive report visibility."""
    import guac.views as gv

    minted = []
    monkeypatch.setattr(gv.db, "view_task", lambda *a, **k: PublicForeignTask())
    monkeypatch.setattr(gv.db, "create_guac_session",
                        lambda **k: minted.append(k) or object(), raising=False)
    client.force_login(User.objects.create_user("ro", "ro@x.com", "x"))  # can read public, can't manage

    r = client.get("/guac/1/AAAA/")
    assert minted == []              # a viewer who can SEE but not MANAGE mints nothing
    assert r.status_code == 200      # guac error page, not a live session


@pytest.mark.django_db
def test_guac_index_mt_off_does_not_apply_manage_gate(cape_db, mt_disabled, monkeypatch, client):
    """MT-OFF INVARIANT: with multitenancy disabled the new can_manage_task early gate
    is a NO-OP. guac.index must fall through to upstream's original ordering — the new
    'No analysis found with specified ID' early-return must NOT fire. A foreign/private
    task is treated exactly as upstream would (no top-of-view denial)."""
    import guac.views as gv

    # If the new gate leaked into MT-off it would call can_manage_task; make that explode
    # so any accidental invocation fails loudly rather than silently passing.
    def _boom(*a, **k):
        raise AssertionError("can_manage_task must not run when multitenancy is disabled")

    monkeypatch.setattr(gv, "can_manage_task", _boom)
    monkeypatch.setattr(gv.db, "view_task", lambda *a, **k: ForeignTask())
    # Force the upstream flow to a deterministic, early, MT-independent branch.
    monkeypatch.setattr(gv, "LIBVIRT_AVAILABLE", False)
    seen = {}
    monkeypatch.setattr(gv, "_error", lambda request, tid, msg: seen.update(msg=msg) or HttpResponse("ERR"))
    client.force_login(User.objects.create_user("mtoff", "mtoff@x.com", "x"))

    r = client.get("/guac/1/AAAA/")
    # Upstream ordering: libvirt check runs FIRST (the new gate did not short-circuit it),
    # so we get the upstream "Libvirt not available" message, NOT the MT denial message.
    assert seen.get("msg") == "Libvirt not available"
    assert r.content == b"ERR"


@pytest.mark.django_db
def test_guac_index_mt_off_missing_task_uses_upstream_message(cape_db, mt_disabled, monkeypatch, client):
    """MT-OFF: a genuinely missing task must surface upstream's exact existence message
    ('The specified task doesn't seem to exist'), reached via the upstream ordering
    (after libvirt + machinery checks), never the MT gate's message."""
    import guac.views as gv

    monkeypatch.setattr(gv, "can_manage_task",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("gate ran MT-off")))
    monkeypatch.setattr(gv, "LIBVIRT_AVAILABLE", True)
    monkeypatch.setattr(gv, "machinery", "kvm")
    monkeypatch.setattr(gv, "machinery_available", ["kvm", "qemu"])
    monkeypatch.setattr(gv.db, "view_task", lambda *a, **k: None)  # task does not exist
    seen = {}
    monkeypatch.setattr(gv, "_error", lambda request, tid, msg: seen.update(msg=msg) or HttpResponse("ERR"))
    client.force_login(User.objects.create_user("mtoff2", "mtoff2@x.com", "x"))

    r = client.get("/guac/1/AAAA/")
    assert seen.get("msg") == "The specified task doesn't seem to exist"
    assert r.content == b"ERR"


@pytest.mark.django_db
def test_direct_vnc_endpoints_deny_non_superuser(cape_db, mt_enabled, monkeypatch):
    """Direct VNC/VM operator endpoints mint task_id=0 sessions that bypass the
    per-task can_view_task tunnel gate (consumers.py gates only guac_task_id>0),
    and control arbitrary live VMs by name. They must be break-glass-admin only —
    a tenant user must not reach them, or they could VNC into / shut down / delete
    snapshots of another tenant's live VM."""
    import guac.views as gv
    from django.contrib.auth.models import User
    from django.test import RequestFactory

    monkeypatch.setattr(gv, "is_vnc_console_enabled", lambda: True)
    monkeypatch.setattr(gv, "_error", lambda request, tid, msg: ("ERR", msg))
    created = []
    monkeypatch.setattr(gv.db, "create_guac_session", lambda **k: created.append(k) or object())

    req = RequestFactory().get("/guac/vnc/vm/somevm/")
    req.user = User.objects.create_user("vncdeny", "vncdeny@x.com", "x")  # tenant-less, non-admin

    # _error-style endpoint (HTML)
    assert gv.direct_vnc_vm(req, "somevm") == ("ERR", "VNC Console is restricted to administrators")
    # JSON-style mutating endpoint
    resp = gv.direct_vnc_vm_shutdown(req, "somevm")
    assert getattr(resp, "status_code", None) == 403
    assert not created  # no session minted for a non-admin

    # positive control: a superuser (break-glass) passes the admin gate
    su = User.objects.create_user("vncadmin", "vncadmin@x.com", "x")
    su.is_superuser = True
    su.save()
    su = User.objects.get(pk=su.pk)
    req2 = RequestFactory().get("/guac/vnc/vm/somevm/")
    req2.user = su
    assert gv.direct_vnc_vm(req2, "somevm") != ("ERR", "VNC Console is restricted to administrators")
