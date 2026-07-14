import pytest
from django.contrib.auth.models import User


@pytest.mark.django_db
def test_submit_form_renders_visibility_control(cape_db, client):
    u = User.objects.create_user("a", "a@x.com", "x")
    client.force_login(u)
    try:
        from django.urls import reverse
        url = reverse("submission")
    except Exception:
        url = "/submit/"
    r = client.get(url)
    assert r.status_code == 200
    assert b'name="visibility"' in r.content


class PublicRunningTask:
    id = 1
    user_id = 999          # owned by someone else
    tenant_id = 10
    visibility = "public"  # a read-only viewer CAN see it
    status = "running"
    machine = "m1"


@pytest.mark.django_db
def test_remote_session_denies_readonly_viewer(cape_db, mt_enabled, monkeypatch, client):
    """remote_session mints the live-VM guac session_data (keyboard/mouse/frame-
    buffer control). A read-only VIEWER of a PUBLIC task (can_view=True but NOT a
    manager) must be denied — live-VM control follows can_manage_task, not read
    visibility."""
    import submission.views as sv

    monkeypatch.setattr(sv.db, "view_task", lambda *a, **k: PublicRunningTask())
    client.force_login(User.objects.create_user("rs", "rs@x.com", "x"))  # tenant-less, non-owner

    try:
        from django.urls import reverse
        url = reverse("remote_session", kwargs={"task_id": 1})
    except Exception:
        url = "/remote_session/1/"
    r = client.get(url)
    # manage-denied -> the generic error page (error.html), never the live-session
    # page. (The message apostrophe is HTML-escaped, so match escape-safe substrings.)
    assert b"ERROR :-(" in r.content          # error.html marker
    assert b"seem to exist" in r.content       # "...task doesn't seem to exist."
    assert b"session_data" not in r.content    # no live-VM token handed to a non-manager
