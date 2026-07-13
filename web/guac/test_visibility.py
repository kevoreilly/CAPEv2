import pytest
from django.contrib.auth.models import User


class ForeignTask:
    id = 1
    user_id = 999      # owned by another tenant's user
    tenant_id = 10
    visibility = "private"


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
