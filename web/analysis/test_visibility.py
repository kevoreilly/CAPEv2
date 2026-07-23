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
def test_report_passes_viewer_scope_to_central_read(cape_db, mt_enabled, monkeypatch, client):
    """report() passes the viewer scope to the central read + staging like every sibling
    surface — it no longer special-cases scope. The owner-lockout fix lives in the shared
    resolvers (central_analysis_query / _job_id_for_task PREFER the RDS-authorized unique
    job_id and apply scope only on the non-bridged info.id fallback), tested separately."""
    import analysis.views as av
    import analysis.central_views as cv
    import analysis.central_scope as csc
    import lib.cuckoo.common.central_mode as cm
    import lib.cuckoo.common.artifact_storage as astor

    monkeypatch.setattr(cm, "central_mode_config", lambda: cm.CentralModeConfig(enabled=True))
    monkeypatch.setitem(av.enabledconf, "mongodb", True)
    SCOPE = {"info.tenant_id": 10}
    monkeypatch.setattr(csc, "viewer_scope", lambda user: SCOPE)

    class _OwnTask:
        id = 1
        user_id = 1
        tenant_id = 10
        visibility = "tenant"
    monkeypatch.setattr(av.db, "view_task", lambda *a, **k: _OwnTask())
    monkeypatch.setattr(av, "can_view_task", lambda *a, **k: True)
    staged = {}
    monkeypatch.setattr(astor, "ensure_local_analysis",
                        lambda tid, scope="__unset__": staged.update(scope=scope), raising=False)
    seen = {}

    class _Stop(Exception):
        pass

    def spy(task_id, scope=None):
        seen["scope"] = scope
        raise _Stop()
    monkeypatch.setattr(cv, "central_analysis_query", spy)

    u = User.objects.create_user("owner", "o@x.com", "x")
    client.force_login(u)
    try:
        client.get(_report_url())
    except _Stop:
        pass
    assert seen.get("scope") == SCOPE, (
        f"report() should pass the viewer scope to the central read; got {seen.get('scope')!r}")
    assert staged.get("scope") == SCOPE, (
        f"report() should pass the viewer scope to staging; got {staged.get('scope')!r}")


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
    """HARD INVARIANT: with MT OFF, require_task_visibility / require_task_manage /
    require_task_delete are PURE pass-throughs — they must NOT coerce the id, call
    db.view_task, or return a 403. The wrapped view runs exactly as upstream (which
    then renders off disk/mongo, ~200)."""
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

    @av.require_task_delete
    def _del_view(request, task_id):
        return sentinel

    req = RequestFactory().get("/x/")
    req.user = User.objects.create_user("pt", "pt@x.com", "x")
    # even a non-numeric id passes straight through untouched when MT is off
    assert _vis_view(req, task_id="abc") is sentinel
    assert _mng_view(req, task_id="abc") is sentinel
    assert _del_view(req, task_id="abc") is sentinel


@pytest.mark.django_db
def test_require_task_delete_gates_on_can_delete_not_can_manage(cape_db, mt_enabled, monkeypatch):
    """MT ON: require_task_delete authorizes via can_delete_task, NOT can_manage_task. A caller who may
    MANAGE a task (e.g. tenant-admin on a public job) but not DELETE it is refused -- and, because they
    can SEE it, with a DISTINGUISHABLE 'not permitted' (403) rather than the generic 'Not found'. RED
    against a revert of remove() to @require_task_manage (which would let the view run) or to the old
    undifferentiated 'Not found'."""
    from django.test import RequestFactory
    import analysis.views as av

    class _T:
        id = 5
    monkeypatch.setattr(av.db, "view_task", lambda tid: _T())
    monkeypatch.setattr(av, "can_view_task", lambda u, t: True, raising=False)
    monkeypatch.setattr(av, "can_manage_task", lambda u, t: True, raising=False)   # manage WOULD allow
    monkeypatch.setattr(av, "can_delete_task", lambda u, t: False, raising=False)  # delete denies

    sentinel = object()

    @av.require_task_delete
    def _del_view(request, task_id):
        return sentinel

    req = RequestFactory().get("/x/")
    req.user = User.objects.create_user("dg", "dg@x.com", "x")
    resp = _del_view(req, task_id="5")
    assert resp is not sentinel                          # gated by can_delete_task (deny), not can_manage
    assert resp.status_code == 403
    assert b"not permitted" in resp.content              # distinguishable (caller can SEE it), not "Not found"


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


@pytest.mark.django_db
def test_remove_oversized_id_is_not_found_not_500(cape_db, monkeypatch):
    """analysis.remove() must fail closed to not-found on an out-of-range / huge-digit id (the route
    captures raw \\d+), never a bodiless 500 from int()/view_task (22003 / ValueError). mongodb is
    forced ON so `viewed == []` is RED without the coerce guard: with mongodb on, an unguarded id WOULD
    reach db.view_task(int(task_id)) below -- so the empty capture proves the coerce ran FIRST, not that
    view_task is simply unreachable (it is, with mongodb off -> the assertion would be vacuous)."""
    from django.test import RequestFactory
    import analysis.views as av

    monkeypatch.setitem(av.enabledconf, "delete", True)   # skip the whiskey gate (delete enabled)
    monkeypatch.setitem(av.enabledconf, "mongodb", True)  # make the guarded view_task call REACHABLE
    viewed = []
    monkeypatch.setattr(av.db, "view_task", lambda tid: viewed.append(tid) or None, raising=False)
    monkeypatch.setattr(av.db, "delete_task", lambda tid: True, raising=False)
    rf = RequestFactory()
    for bad in ("99999999999999999999", "9" * 5000):  # in-range-int-overflow (22003) + >4300-digit (ValueError)
        resp = av.remove(rf.get("/x/"), bad)
        assert resp.status_code == 200                 # not-found render, not a 500
    assert viewed == []                                # coerced + failed closed BEFORE the reachable view_task


@pytest.mark.django_db
def test_remove_valid_id_mongodb_off_renders_message_not_500(cape_db, monkeypatch):
    """A valid id with mongodb OFF and ES off must render 200 with a message, NOT a bodiless 500: `message`
    is bound unconditionally so the final render can't hit UnboundLocalError when neither the mongodb nor the
    ES arm runs (both configs off -> the sole binding is the unconditional default)."""
    from django.test import RequestFactory
    import analysis.views as av

    monkeypatch.setitem(av.enabledconf, "delete", True)
    monkeypatch.setitem(av.enabledconf, "mongodb", False)  # neither delete-arm sets `message`
    monkeypatch.setattr(av, "es_as_db", False, raising=False)
    monkeypatch.setattr(av, "essearch", False, raising=False)
    deleted = []
    monkeypatch.setattr(av.db, "delete_task", lambda tid: deleted.append(tid) or True, raising=False)
    resp = av.remove(RequestFactory().get("/x/"), "7")

    assert resp.status_code == 200                     # not an UnboundLocalError 500
    assert deleted == ["7"]                            # SQL delete still happened (id coerced + normalized)


@pytest.mark.django_db
def test_can_delete_task_templatetag_gates_button(cape_db, monkeypatch):
    """The can_delete_task template tag gates the irreversible Delete button: True only when
    can_delete_task allows, and it fails CLOSED (False -> no button) if resolution raises. Accepts a
    Task-like object directly (no view_task hit when it already carries visibility/user_id)."""
    from analysis.templatetags import analysis_tags as tags
    import web.tenancy_optional as topt

    class _T:
        visibility = "public"
        user_id = 1

    u = User.objects.create_user("ttag", "ttag@x.com", "x")

    monkeypatch.setattr(topt, "can_delete_task", lambda user, task: False)
    assert tags.can_delete_task(u, _T()) is False        # denied -> button hidden
    monkeypatch.setattr(topt, "can_delete_task", lambda user, task: True)
    assert tags.can_delete_task(u, _T()) is True         # allowed -> button shown

    def _boom(user, task):
        raise RuntimeError("resolution error")
    monkeypatch.setattr(topt, "can_delete_task", _boom)
    assert tags.can_delete_task(u, _T()) is False         # fail closed on any error


@pytest.mark.django_db
def test_analysis_search_ids_bounded_not_500(cape_db, monkeypatch, client):
    """The analysis-side search 'ids' path bounds each token like apiv2's ext_tasks_search: an out-of-range
    (>2**31-1), huge-digit (>4300 chars), or zero token renders the generic 'Not all values are valid task
    ids' error (200) BEFORE any DB query -- never an unbounded int()->500. Only the apiv2 side had a bound
    test before this."""
    import analysis.views as av
    from django.urls import reverse

    def _boom(*a, **k):
        raise AssertionError("must not query the DB for an invalid id set")
    monkeypatch.setattr(av.db, "list_tasks", _boom, raising=False)
    client.force_login(User.objects.create_user("asids", "asids@x.com", "x"))
    try:
        url = reverse("search")
    except Exception:
        url = "/analysis/search/"
    for bad in ("2147483648", "9" * 4301, "0"):
        r = client.post(url, {"search": "ids:%s" % bad})
        assert r.status_code == 200
        assert b"Not all values are valid task ids" in r.content


@pytest.mark.django_db
def test_can_delete_task_templatetag_resolves_id(cape_db, monkeypatch):
    """The can_delete_task tag's id-path (mongo analysis.info.id, not a Task object): it resolves via
    Database().view_task -> False if the id is gone (hide the button), else delegates to can_delete_task.
    The object-path test never exercises this view_task branch."""
    from analysis.templatetags import analysis_tags as tags
    import web.tenancy_optional as topt

    u = User.objects.create_user("ttid", "ttid@x.com", "x")

    class _DB:
        def __init__(self, t):
            self._t = t

        def view_task(self, tid):
            return self._t

    # id resolves to None -> hide (False) without consulting can_delete_task
    monkeypatch.setattr("lib.cuckoo.core.database.Database", lambda: _DB(None))
    assert tags.can_delete_task(u, 5) is False

    # id resolves to a task -> delegate to can_delete_task
    class _T:
        visibility = "public"
        user_id = 1
    monkeypatch.setattr("lib.cuckoo.core.database.Database", lambda: _DB(_T()))
    monkeypatch.setattr(topt, "can_delete_task", lambda user, task: True)
    assert tags.can_delete_task(u, 5) is True


@pytest.mark.django_db
def test_require_task_delete_missing_or_unseeable_is_generic_not_found(cape_db, mt_enabled, monkeypatch):
    """require_task_delete returns the generic 'Not found' (no cross-tenant enumeration oracle) for a
    MISSING or NOT-VIEWABLE task -- distinct from the 'not permitted' 403 it returns for a seen-but-
    undeletable task (covered separately). Both anti-enumeration arms asserted here."""
    from django.test import RequestFactory
    import analysis.views as av

    sentinel = object()

    @av.require_task_delete
    def _view(request, task_id):
        return sentinel

    req = RequestFactory().get("/x/")
    req.user = User.objects.create_user("rnf", "rnf@x.com", "x")

    # (a) missing task -> generic Not found
    monkeypatch.setattr(av.db, "view_task", lambda tid: None)
    r = _view(req, task_id="5")
    assert r is not sentinel and r.status_code == 403
    assert b"Not found" in r.content and b"not permitted" not in r.content

    # (b) exists but not viewable -> SAME generic Not found (no existence signal)
    class _T:
        id = 5
    monkeypatch.setattr(av.db, "view_task", lambda tid: _T())
    monkeypatch.setattr(av, "can_view_task", lambda u, t: False, raising=False)
    r = _view(req, task_id="5")
    assert r.status_code == 403
    assert b"Not found" in r.content and b"not permitted" not in r.content


@pytest.mark.django_db
def test_pending_resolves_viewer_once(cape_db, mt_enabled, monkeypatch, client):
    """pending() must resolve viewer_for ONCE per request, not once per row -- else a break-glass-off
    superuser triggers an O(N) socialaccount_set.exists() fan-out. RED against per-row can_delete_task
    (which rebuilt viewer_for for each task -> 1 + N calls)."""
    from django.urls import reverse
    import analysis.views as av

    class _T:
        def __init__(self, i):
            self.id = i
            self.user_id, self.tenant_id, self.visibility = 1, None, "public"
            self.target, self.added_on, self.category, self.sample = "t%d" % i, None, "file", None

    monkeypatch.setattr(av.db, "list_tasks", lambda *a, **k: [_T(1), _T(2), _T(3), _T(4)])
    calls = {"n": 0}
    _real = av.viewer_for

    def _counting(u):
        calls["n"] += 1
        return _real(u)
    monkeypatch.setattr(av, "viewer_for", _counting)

    client.force_login(User.objects.create_user("pv", "pv@x.com", "x"))
    r = client.get(reverse("pending"))
    assert r.status_code == 200
    assert calls["n"] == 1, "viewer_for resolved %d times (expected 1 per request, not per-row)" % calls["n"]


# ---------------------------------------------------------------------------
# Template parse guard: Django forbids template vars/attrs beginning with '_'
# (TemplateSyntaxError at PARSE time). The MT/central per-task controls
# (visibility <select>, delete button) previously used '_'-prefixed loop/assign
# vars (_vis, _can_delete), which 500'd /analysis/<id>/ for a user who can
# actually toggle/delete (owner/tenant-admin) — the block only renders for them,
# so it slipped through. Compile each so a re-introduced '_'-var fails CI.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tpl", [
    "analysis/report.html",
    "analysis/failed_processing.html",
    "analysis/admin/index.html",
])
def test_analysis_template_has_no_underscore_leading_var(tpl):
    from django.template.loader import get_template
    get_template(tpl)  # raises TemplateSyntaxError if any var/attr begins with '_'
