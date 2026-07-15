import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)



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
def test_compare_left_mongo_materializes_cursor(cape_db, mt_enabled, monkeypatch, client):
    """Regression: the mongo md5-pivot cursor is iterated TWICE (collect ids, then
    build records). A PyMongo cursor is single-pass, so it must be materialized —
    else `records` is always empty for Mongo-backed compare. Mock mongo_find with a
    single-pass iterator so the bug reproduces without the list() fix."""
    import compare.views as cv

    user = User.objects.create_user("cmpm", "cmpm@x.com", "x")

    class FakeDB:
        view_task = staticmethod(lambda tid: _public_task(int(tid)))

        def list_tasks(self, task_ids=None, visible_to=None, **k):
            return [_public_task(t) for t in (task_ids or [])]  # all visible

    monkeypatch.setattr(cv, "Database", lambda: FakeDB())
    monkeypatch.setattr(cv, "es_as_db", False, raising=False)
    monkeypatch.setattr(cv, "enabledconf", {"mongodb": True, "elasticsearchdb": False}, raising=False)
    monkeypatch.setattr(cv, "mongo_find_one",
                        lambda *a, **k: {"info": {"id": 1}, "target": {"file": {"md5": "abc"}}}, raising=False)
    # single-pass iterator, exactly like a real PyMongo cursor
    monkeypatch.setattr(cv, "mongo_find",
                        lambda *a, **k: iter([{"info": {"id": 2}, "target": {}}]), raising=False)

    captured = {}
    real_render = cv.render
    monkeypatch.setattr(cv, "render", lambda req, tmpl, ctx=None: captured.update(ctx or {}) or real_render(req, tmpl, ctx))
    client.force_login(user)

    r = client.get("/compare/1/")
    assert r.status_code == 200
    # the visible md5-pivot hit (task 2) must survive — non-empty despite the double loop
    assert [rec.get("info", {}).get("id") for rec in captured.get("records", [])] == [2]


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

        def list_tasks(self, task_ids=None, visible_to=None, **k):
            # SoT emulation: the ES path now batches visibility via
            # list_tasks(visible_to=). For this tenant-less viewer only PUBLIC
            # tasks are visible, so the foreign private pivot (task 2) is dropped.
            return [_view(t) for t in (task_ids or []) if getattr(_view(t), "visibility", None) == "public"]

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


# --------------------------------------------------------------------------- #
# MT-OFF invariant: the new MT gates must be TRUE NO-OPS. With multitenancy
# disabled (the default) the compare views must behave byte-for-byte like
# upstream: NO SQL seed gate, NO list_tasks() intersection — mongo/ES-only
# analyses (which have no SQL row) must still render, and every md5-pivot hit
# must survive.
# --------------------------------------------------------------------------- #


class _ExplodingDB:
    """Any SQL touch (view_task / list_tasks) fails the test — proves the MT
    gate + intersection are skipped entirely when MT is off."""

    def view_task(self, tid):
        raise AssertionError("view_task must NOT be called when multitenancy is disabled")

    def list_tasks(self, *a, **k):
        raise AssertionError("list_tasks must NOT be called when multitenancy is disabled")


@pytest.mark.django_db
def test_compare_left_mt_off_mongo_only_analysis_renders(cape_db, mt_disabled, monkeypatch, client):
    """MT off: byte-for-byte upstream — the seed gate is skipped (mongo-only seed
    renders, no 404) AND the md5-pivot result is passed to the template UNCHANGED
    (records = mongo_find(...)), with no list()/list_tasks intersection. Pinned by
    identity so a regression to list(_raw) — which changes the template's
    `records|length` rendering vs upstream's len-less cursor — fails here."""
    import compare.views as cv

    monkeypatch.setattr(cv, "Database", lambda: _ExplodingDB())
    monkeypatch.setattr(cv, "es_as_db", False, raising=False)
    monkeypatch.setattr(cv, "enabledconf", {"mongodb": True, "elasticsearchdb": False}, raising=False)
    monkeypatch.setattr(cv, "mongo_find_one",
                        lambda *a, **k: {"info": {"id": 1}, "target": {"file": {"md5": "abc"}}}, raising=False)
    # sentinel md5-pivot result — MT off must pass THIS object through untouched
    _sentinel = [{"info": {"id": 2}, "target": {}}, {"info": {"id": 3}, "target": {}}]
    monkeypatch.setattr(cv, "mongo_find", lambda *a, **k: _sentinel, raising=False)

    captured = {}
    real_render = cv.render
    monkeypatch.setattr(cv, "render", lambda req, tmpl, ctx=None: captured.update(ctx or {}) or real_render(req, tmpl, ctx))
    client.force_login(User.objects.create_user("mo", "mo@x.com", "x"))

    r = client.get("/compare/1/")
    assert r.status_code == 200
    assert b"No analysis found" not in r.content              # seed gate skipped (no _ExplodingDB.view_task)
    assert captured.get("records") is _sentinel               # passed through unchanged (no list(), no list_tasks intersection)


@pytest.mark.django_db
def test_compare_left_mt_off_es_no_intersection(cape_db, mt_disabled, monkeypatch, client):
    """MT off, ES backend: every md5-pivot hit is appended, no list_tasks()."""
    import compare.views as cv

    class FakeES:
        def search(self, index=None, query=None, body=None):
            if body is not None:  # md5 pivot
                return {"hits": {"hits": [{"_source": {"info": {"id": 2}, "target": {}}},
                                          {"_source": {"info": {"id": 3}, "target": {}}}]}}
            return {"hits": {"hits": [{"_source": {"info": {"id": 1}, "target": {"file": {"md5": "abc"}}}}]}}

    monkeypatch.setattr(cv, "Database", lambda: _ExplodingDB())
    monkeypatch.setattr(cv, "es_as_db", True, raising=False)
    monkeypatch.setattr(cv, "es", FakeES(), raising=False)
    monkeypatch.setattr(cv, "enabledconf", {"mongodb": False, "elasticsearchdb": True}, raising=False)
    monkeypatch.setattr(cv, "get_analysis_index", lambda: "idx", raising=False)
    monkeypatch.setattr(cv, "get_query_by_info_id", lambda i: {}, raising=False)

    captured = {}
    real_render = cv.render
    monkeypatch.setattr(cv, "render", lambda req, tmpl, ctx=None: captured.update(ctx or {}) or real_render(req, tmpl, ctx))
    client.force_login(User.objects.create_user("eso", "eso@x.com", "x"))

    r = client.get("/compare/1/")
    assert r.status_code == 200
    assert [rec.get("info", {}).get("id") for rec in captured.get("records", [])] == [2, 3]


@pytest.mark.django_db
def test_compare_hash_mt_off_mongo_only_analysis_renders(cape_db, mt_disabled, monkeypatch, client):
    """MT off: compare.hash skips the seed gate + intersection and passes the
    md5-pivot result through unchanged (byte-for-byte upstream, pinned by identity)."""
    import compare.views as cv

    monkeypatch.setattr(cv, "Database", lambda: _ExplodingDB())
    monkeypatch.setattr(cv, "es_as_db", False, raising=False)
    monkeypatch.setattr(cv, "enabledconf", {"mongodb": True, "elasticsearchdb": False}, raising=False)
    monkeypatch.setattr(cv, "mongo_find_one",
                        lambda *a, **k: {"info": {"id": 1}, "target": {"file": {"md5": "abc"}}}, raising=False)
    _sentinel = [{"info": {"id": 2}, "target": {}}]
    monkeypatch.setattr(cv, "mongo_find", lambda *a, **k: _sentinel, raising=False)

    captured = {}
    real_render = cv.render
    monkeypatch.setattr(cv, "render", lambda req, tmpl, ctx=None: captured.update(ctx or {}) or real_render(req, tmpl, ctx))
    client.force_login(User.objects.create_user("hmo", "hmo@x.com", "x"))

    r = client.get("/compare/1/abc/")
    assert r.status_code == 200
    assert b"No analysis found" not in r.content
    assert captured.get("records") is _sentinel


@pytest.mark.django_db
def test_compare_both_mt_off_mongo_only_analysis_renders(cape_db, mt_disabled, monkeypatch, client):
    """MT off: compare.both skips the seed gate; mongo-only analyses (no SQL row) render."""
    import compare.views as cv

    monkeypatch.setattr(cv, "Database", lambda: _ExplodingDB())
    monkeypatch.setattr(cv, "es_as_db", False, raising=False)
    monkeypatch.setattr(cv, "enabledconf", {"mongodb": True, "elasticsearchdb": False}, raising=False)
    monkeypatch.setattr(cv, "mongo_find_one",
                        lambda coll, q, proj=None: {"info": {"id": q["info.id"]}, "target": {"file": {"md5": "abc"}}, "summary": {}},
                        raising=False)
    monkeypatch.setattr(cv.compare, "helper_percentages_mongo",
                        lambda l, r: {l: {}, r: {}}, raising=False)
    monkeypatch.setattr(cv.compare, "helper_summary_mongo", lambda l, r: {}, raising=False)

    client.force_login(User.objects.create_user("bmo", "bmo@x.com", "x"))

    r = client.get("/compare/1/2/")
    assert r.status_code == 200
    assert b"No analysis found" not in r.content
