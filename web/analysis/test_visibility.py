import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)



class ForeignTask:
    id = 1
    user_id = 999      # owned by someone else
    tenant_id = 10
    visibility = "private"


def _report_url():
    try:
        from django.urls import reverse
        return reverse("report", kwargs={"task_id": 1})
    except Exception:
        return "/analysis/1/"


@pytest.mark.django_db
def test_report_denies_cross_tenant_private(cape_db, mt_enabled, monkeypatch, client):
    """A cross-tenant private task is not shown. The denial is the generic
    "no analysis found" page (HTTP 200), INDISTINGUISHABLE from a missing task,
    so another tenant's task IDs can't be enumerated by status code."""
    import analysis.views as av

    monkeypatch.setattr(av.db, "view_task", lambda *a, **k: ForeignTask())
    other = User.objects.create_user("b", "b@x.com", "x")
    client.force_login(other)

    r = client.get(_report_url())
    assert r.status_code == 200
    assert b"No analysis found" in r.content


@pytest.mark.django_db
def test_report_missing_task_renders_error_200_mt_on(cape_db, mt_enabled, monkeypatch, client):
    """With MT ON, a missing/deleted task renders the same generic "No analysis
    found" error page at HTTP 200 as a hidden task (indistinguishability) — not a
    403 — so cross-tenant task IDs can't be enumerated by status/message."""
    import analysis.views as av
    monkeypatch.setattr(av.db, "view_task", lambda *a, **k: None)
    u = User.objects.create_user("c", "c@x.com", "x")
    client.force_login(u)
    r = client.get(_report_url())
    assert r.status_code == 200
    assert b"No analysis found" in r.content


@pytest.mark.django_db
def test_report_mt_off_falls_through_to_upstream_error(cape_db, mt_disabled, monkeypatch, client):
    """HARD INVARIANT: with MT OFF the whole SQL-existence pre-check is a NO-OP.
    A task with no SQL Task row (e.g. a mongo/ES-only analysis, or a fresh/empty
    DB) must NOT hit the new "No analysis found with specified ID" page; it falls
    straight through to upstream's original mongo/ES 'if not report:' path with its
    unchanged message and HTTP 200. (view_task is made to blow up to prove the
    pre-check never touches the DB when MT is disabled.)"""
    import analysis.views as av

    def _boom(*a, **k):
        raise AssertionError("report() must not run the SQL-existence pre-check when MT is off")

    monkeypatch.setattr(av.db, "view_task", _boom)
    u = User.objects.create_user("c", "c@x.com", "x")
    client.force_login(u)
    r = client.get(_report_url())
    assert r.status_code == 200
    # Upstream message, NOT the MT "No analysis found with specified ID" string.
    assert b"No analysis found with specified ID" not in r.content
    assert (
        b"The specified analysis does not exist or not finished yet." in r.content
        or b"enable Mongodb/ES" in r.content
    )


@pytest.mark.django_db
def test_full_memory_denies_cross_tenant(cape_db, mt_enabled, monkeypatch, client):
    """full_memory_dump_file routes via the analysis_number group (not task_id);
    the guard decorator must resolve that group and deny a cross-tenant viewer."""
    import analysis.views as av

    monkeypatch.setattr(av.db, "view_task", lambda *a, **k: ForeignTask())
    client.force_login(User.objects.create_user("fm", "fm@x.com", "x"))
    assert client.get("/full_memory/1/").status_code == 403


@pytest.mark.django_db
def test_non_numeric_task_id_denied_before_db(cape_db, mt_enabled, monkeypatch, client):
    """With MT ON, a non-numeric id on a \\w+ analysis route (full_memory) is
    coerced-and-denied (403) BEFORE db.view_task runs — so a bad id can't raise a
    DB DataError -> 500 (which would also leak a task-vs-no-task signal). This
    hardening only runs when MT is enabled; with MT off the decorator is a pure
    pass-through so the view keeps upstream's behavior (see
    test_require_visibility_mt_off_passthrough)."""
    import analysis.views as av

    def _boom(*a, **k):
        raise AssertionError("db.view_task must not be called for a non-numeric id")

    monkeypatch.setattr(av.db, "view_task", _boom)
    client.force_login(User.objects.create_user("nn", "nn@x.com", "x"))
    assert client.get("/full_memory/abc/").status_code == 403


@pytest.mark.django_db
def test_require_visibility_mt_off_passthrough(cape_db, mt_disabled, monkeypatch):
    """HARD INVARIANT: with MT OFF, require_task_visibility / require_task_manage
    are PURE pass-throughs — they must NOT coerce the id, call db.view_task, or
    return a 403. The wrapped view runs exactly as upstream (which then renders off
    disk/mongo, ~200)."""
    from django.test import RequestFactory
    import analysis.views as av

    def _boom(*a, **k):
        raise AssertionError("decorators must not touch the DB when MT is off")

    monkeypatch.setattr(av.db, "view_task", _boom)

    sentinel = object()

    @av.require_task_visibility
    def _vis_view(request, task_id):
        return sentinel

    @av.require_task_manage
    def _mng_view(request, task_id):
        return sentinel

    req = RequestFactory().get("/x/")
    req.user = User.objects.create_user("pt", "pt@x.com", "x")
    # even a non-numeric id passes straight through untouched when MT is off
    assert _vis_view(req, task_id="abc") is sentinel
    assert _mng_view(req, task_id="abc") is sentinel


@pytest.mark.django_db
def test_vtupload_denies_cross_tenant(cape_db, mt_enabled, monkeypatch, client):
    """vtupload reads + exfiltrates a sample to VirusTotal — require_task_manage."""
    import analysis.views as av

    monkeypatch.setattr(av.db, "view_task", lambda *a, **k: ForeignTask())
    client.force_login(User.objects.create_user("vt", "vt@x.com", "x"))
    assert client.get("/vtupload/CAPE/1/evil.bin/abc/").status_code == 403


@pytest.mark.django_db
def test_tag_tasks_skips_unmanageable_cross_tenant(cape_db, mt_enabled, client):
    """A tenant-less user must not be able to tag another tenant's private task."""
    import json as _json
    import analysis.views as av
    from lib.cuckoo.core.data.task import Task

    t = Task(target="x.exe")
    t.category = "file"
    t.user_id, t.tenant_id, t.visibility = 999, 10, "private"
    av.db.session.add(t)
    av.db.session.commit()
    tid = t.id

    client.force_login(User.objects.create_user("tg", "tg@x.com", "x"))  # tenant-less
    r = client.post(
        "/analysis/hunt/tag/",
        data=_json.dumps({"task_ids": [tid], "tag": "pwned"}),
        content_type="application/json",
    )
    assert r.status_code == 200
    av.db.session.expire_all()
    assert "pwned" not in (av.db.session.get(Task, tid).tags_tasks or "")


@pytest.mark.django_db
def test_file_search_all_files_drops_cross_tenant_paths(cape_db, mt_enabled, monkeypatch):
    """CRITICAL leak regression (capeyarazipall): _file_search_all_files must NOT
    return artifact paths belonging to analyses the requester can't read — else
    file() streams another tenant's dropped/payload/sample bytes. The gate now
    filters RECORDS by owning-task can_view_task BEFORE resolving paths, so it
    covers ALL path shapes — including content-addressed storage/binaries/<sha256>
    samples that have no /analyses/<id>/ segment (the shape the old regex missed)."""
    from django.test import RequestFactory
    from django.contrib.auth.models import User
    import analysis.views as av

    class OwnTask:      # task 2 — visible to the requester (public)
        id = 2
        user_id = 0
        tenant_id = 10
        visibility = "public"

    class ForeignTask:  # task 3 — another tenant's private analysis
        id = 3
        user_id = 999
        tenant_id = 20
        visibility = "private"

    monkeypatch.setattr(av, "perform_search", lambda *a, **k: [{"info": {"id": 2}}, {"info": {"id": 3}}])

    # Real yara_detected yields file paths for the records it is GIVEN; the gate
    # filters records before this call, so model that contract. The foreign task's
    # artifact is a content-addressed sample path (no /analyses/<id>/ segment).
    def _fake_yara(term, recs):
        ids = {r["info"]["id"] for r in recs}
        out = []
        if 2 in ids:
            out.append(("dropped", "/opt/CAPEv2/storage/analyses/2/files/own.bin", {}, {}))
        if 3 in ids:
            out.append(("target", "/opt/CAPEv2/storage/binaries/deadbeefdeadbeef", {}, {}))
        return out

    monkeypatch.setattr(av, "yara_detected", _fake_yara)
    monkeypatch.setattr(av, "path_exists", lambda p: True)
    # The gate batch-resolves visible tasks via list_tasks (one query, no N+1);
    # only task 2 (own/public) is visible, task 3 (foreign/private) is not.
    monkeypatch.setattr(av.db, "list_tasks", lambda *a, **k: [OwnTask()])

    req = RequestFactory().get("/file/capeyarazipall/2/Emotet/")
    req.user = User.objects.create_user("fs", "fs@x.com", "x")  # tenant-less, non-admin

    paths = av._file_search_all_files("capeyara", "Emotet", req)
    assert "/opt/CAPEv2/storage/analyses/2/files/own.bin" in paths            # readable kept
    assert "/opt/CAPEv2/storage/binaries/deadbeefdeadbeef" not in paths       # foreign content-addressed sample dropped


_STATS = {
    "total": 3,
    "average": 1,
    "tasks": {},
    "detections": {"Emotet": {"family": "Emotet", "total": 2}},
    "asns": [],
    "signatures": {},
    "processing": {},
    "reporting": {},
    "custom_statistics": {},
}


@pytest.mark.django_db
def test_statistics_mt_off_renders_upstream_markup(cape_db, mt_disabled, monkeypatch, client):
    """HARD INVARIANT: with MT OFF, entitled_scopes()->['global'] and the single
    panel must render BYTE-FOR-BYTE upstream markup — bare element ids (no
    '-global' suffix), a plain 'All Detections' modal title (no '— Global'), and
    no per-scope header."""
    import analysis.views as av
    import dashboard.views as dv

    monkeypatch.setattr(av, "statistics", lambda *a, **k: dict(_STATS))
    monkeypatch.setattr(dv, "entitled_scopes", lambda user: ["global"])
    client.force_login(User.objects.create_user("st", "st@x.com", "x"))

    r = client.get("/statistics/7/")
    assert r.status_code == 200
    body = r.content
    # bare upstream ids, no scope suffix
    assert b'id="tasksChart"' in body
    assert b'id="allDetectionsModal"' in body
    assert b'id="performanceTabs"' in body
    assert b'data-bs-target="#processing"' in body
    assert b"tasksChart-global" not in body
    assert b"allDetectionsModal-global" not in body
    # upstream modal title, no label suffix, and no per-scope header
    assert b"All Detections" in body
    assert b"All Detections \xe2\x80\x94" not in body  # no " — " suffix
    assert b"fa-layer-group" not in body


@pytest.mark.django_db
def test_statistics_mt_on_multiscope_suffixes_ids_and_labels(cape_db, mt_enabled, monkeypatch, client):
    """With MT ON and multiple entitled scopes, each panel's ids/targets are
    suffixed with '-<scope>' and the modal title carries the '— <label>' suffix
    plus a per-scope header, so the panels don't collide in the DOM."""
    import analysis.views as av
    import dashboard.views as dv

    monkeypatch.setattr(av, "statistics", lambda *a, **k: dict(_STATS))
    monkeypatch.setattr(dv, "entitled_scopes", lambda user: ["public", "mine"])
    client.force_login(User.objects.create_user("st2", "st2@x.com", "x"))

    r = client.get("/statistics/7/")
    assert r.status_code == 200
    body = r.content
    # per-scope suffixed ids for BOTH panels
    assert b'id="tasksChart-public"' in body
    assert b'id="tasksChart-mine"' in body
    assert b'id="allDetectionsModal-public"' in body
    # label-suffixed modal titles + per-scope headers
    assert b"All Detections \xe2\x80\x94 Public" in body
    assert b"All Detections \xe2\x80\x94 Mine" in body
    assert b"fa-layer-group" in body
    # the bare (unsuffixed) upstream ids must NOT appear in multi-panel mode
    assert b'id="tasksChart"' not in body


@pytest.mark.django_db
def test_perform_search_tags_scopes_prequery_by_viewer(cape_db, monkeypatch):
    """Codex: the tags_tasks/options SQL prequery must scope by visible_to BEFORE
    the search_limit — else other tenants' matches fill the limit and the tenant-
    scoped mongo query returns none of the viewer's own (older) visible matches."""
    import lib.cuckoo.common.web_utils as wu
    from lib.cuckoo.common.tenancy import Viewer

    captured = {}

    class _T:
        def __init__(self, i):
            self.id = i

    def _list_tasks(*a, **k):
        captured.update(k)
        return [_T(1), _T(2)]

    monkeypatch.setattr(wu.db, "list_tasks", _list_tasks)
    monkeypatch.setattr(wu, "mongo_find", lambda *a, **k: [], raising=False)
    monkeypatch.setattr(wu, "es_as_db", False, raising=False)

    v = Viewer(user_id=2, tenant_id=10)
    wu.perform_search("tags_tasks", "sometag", viewer=v)
    assert captured.get("visible_to") is v  # prequery scoped by the viewer before the limit
