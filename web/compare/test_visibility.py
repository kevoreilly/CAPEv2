import pytest
from django.contrib.auth.models import User


class ForeignTask:
    id = 1
    user_id = 999      # owned by another tenant's user
    tenant_id = 10
    visibility = "private"


def _public_task(tid):
    class _T:
        id = tid
        user_id = 999
        tenant_id = 10
        visibility = "public"
    return _T()


@pytest.mark.django_db
def test_compare_both_denies_cross_tenant(cape_db, mt_enabled, monkeypatch, client):
    """compare.both reads two analyses by info.id; the seed gate must deny a
    viewer who can't read them (hidden == "No analysis found")."""
    import compare.views as cv

    class FakeDB:
        def view_task(self, tid):
            return ForeignTask()

    monkeypatch.setattr(cv, "Database", lambda: FakeDB())
    client.force_login(User.objects.create_user("cmp", "cmp@x.com", "x"))  # tenant-less

    r = client.get("/compare/1/2/")
    assert r.status_code == 200
    assert b"No analysis found" in r.content


@pytest.mark.django_db
def test_compare_left_denies_cross_tenant(cape_db, mt_enabled, monkeypatch, client):
    import compare.views as cv

    class FakeDB:
        def view_task(self, tid):
            return ForeignTask()

    monkeypatch.setattr(cv, "Database", lambda: FakeDB())
    client.force_login(User.objects.create_user("cl", "cl@x.com", "x"))

    r = client.get("/compare/1/")
    assert r.status_code == 200
    assert b"No analysis found" in r.content


@pytest.mark.django_db
def test_compare_left_es_backend_filters_cross_tenant(cape_db, mt_enabled, monkeypatch, client):
    """Regression for the #3 review finding: the Elasticsearch backend path
    (es_as_db) must post-filter the md5-pivot hits through can_view_task — the
    mongo $match isn't applied there. A cross-tenant private hit must be dropped."""
    import compare.views as cv

    user = User.objects.create_user("es", "es@x.com", "x")  # tenant-less

    # seed (left_id=1) is public -> viewable; pivot hit (task 2) is another
    # tenant's private analysis -> must be filtered out of `records`.
    def _view(tid):
        return _public_task(1) if int(tid) == 1 else ForeignTask()

    class FakeDB:
        view_task = staticmethod(_view)

    class FakeES:
        def search(self, index=None, query=None, body=None):
            if body is not None:  # md5 pivot
                return {"hits": {"hits": [{"_source": {"info": {"id": 2}, "target": {}}}]}}
            # seed lookup by info.id
            return {"hits": {"hits": [{"_source": {"info": {"id": 1}, "target": {"file": {"md5": "abc"}}}}]}}

    monkeypatch.setattr(cv, "Database", lambda: FakeDB())
    monkeypatch.setattr(cv, "es_as_db", True, raising=False)
    monkeypatch.setattr(cv, "es", FakeES(), raising=False)
    monkeypatch.setattr(cv, "enabledconf", {"mongodb": False, "elasticsearchdb": True}, raising=False)
    monkeypatch.setattr(cv, "get_analysis_index", lambda: "idx", raising=False)
    monkeypatch.setattr(cv, "get_query_by_info_id", lambda i: {}, raising=False)

    captured = {}
    real_render = cv.render
    monkeypatch.setattr(cv, "render", lambda req, tmpl, ctx=None: captured.update(ctx or {}) or real_render(req, tmpl, ctx))
    client.force_login(user)

    r = client.get("/compare/1/")
    assert r.status_code == 200
    # the foreign tenant's analysis (task 2) must NOT survive the post-filter
    assert all(rec.get("info", {}).get("id") != 2 for rec in captured.get("records", []))
    assert captured.get("records") == []
