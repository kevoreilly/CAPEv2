"""Central-mode task_id -> job_id resolution (lib.cuckoo.common.artifact_storage).

The staging/serving resolver must PREFER the RDS-authorized job_id (from the task's
custom field — collision-free and independent of the tenancy reconcile) so an authorized
OWNER isn't locked out of a fail-closed/unstamped doc, and only fall back to the scoped
mongo info.id lookup for non-bridged tasks (defence-in-depth against cross-store id
collision).
"""


def test_job_id_from_custom():
    from lib.cuckoo.common.artifact_storage import job_id_from_custom
    assert job_id_from_custom("job_id=ui-5,foo=bar") == "ui-5"   # job_id= in the FIRST position -> honoured
    assert job_id_from_custom("job_id=ui-9") == "ui-9"
    assert job_id_from_custom("local-3") == "local-3"            # bare NON-ui token (direct submission)
    assert job_id_from_custom("foo=bar") is None
    assert job_id_from_custom(None) is None
    assert job_id_from_custom("") is None
    # ANCHORED to the submit-bridge's prefix filter: a client custom that evades `custom LIKE 'job_id=%'`
    # must NOT resolve to a job_id here (else it could steer info.job_id / the S3 prefix / the scoped delete):
    assert job_id_from_custom("foo=bar,job_id=ui-999999") is None  # job_id= NOT in the first position
    assert job_id_from_custom("ui-999999") is None                 # bare 'ui-<N>' (bridge's reserved form)
    assert job_id_from_custom(" job_id=ui-999999") is None         # leading space -> raw prefix test fails
    assert job_id_from_custom("\tjob_id=ui-9") is None             # leading tab, same
    # PATH-SAFETY: the resolved job_id becomes the store container prefix ("<s3_prefix>/<job_id>/"), so a
    # path-unsafe custom must NOT resolve (else, on the local-mount backend, '..' escapes the results tree ->
    # arbitrary host-file read). Rejected as both a bare token AND a job_id= value.
    assert job_id_from_custom("../../../../etc") is None            # bare traversal token
    assert job_id_from_custom("job_id=../../etc") is None           # traversal as the job_id= value
    assert job_id_from_custom("..") is None
    assert job_id_from_custom("a..b") is None                       # any '..' run
    assert job_id_from_custom("a/b") is None                        # path separator (not in charset)
    assert job_id_from_custom(".hidden") is None                    # must start with an alnum


def test_job_id_from_custom_freetext_does_not_warn_but_probe_does(caplog):
    """`custom` is a documented free-text field, and this resolver runs on EVERY central artifact read, so a
    bare note with whitespace ('my sample run') must NOT emit a WARNING (that would spam the log per-read and
    bury real probes) -- it is logged at debug. A whitespace-free path-unsafe token ('../../etc') LOOKS like a
    job_id/path attempt and IS warned so a seam probe stays greppable. Both still resolve to None."""
    import logging
    import lib.cuckoo.common.artifact_storage as a

    with caplog.at_level(logging.WARNING, logger=a.log.name):
        assert a.job_id_from_custom("my sample run") is None       # free-text note (has whitespace)
    assert not caplog.records, [r.getMessage() for r in caplog.records]

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=a.log.name):
        assert a.job_id_from_custom("../../etc") is None           # probe-shaped ('..')
    assert any("path-unsafe bare job_id token" in r.getMessage() for r in caplog.records), \
        [r.getMessage() for r in caplog.records]

    # a traversal-shaped probe with INTERIOR whitespace must STILL warn (keyed on '..'/'/', not whitespace):
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=a.log.name):
        assert a.job_id_from_custom("../../etc x") is None
        assert a.job_id_from_custom("a/b c") is None
    assert len([r for r in caplog.records if "path-unsafe bare job_id token" in r.getMessage()]) == 2, \
        [r.getMessage() for r in caplog.records]


def test_is_safe_job_id_matches_centralstore():
    """The read-seam parser guard and the write-seam guard are ONE shared helper (no drift): centralstore
    imports _is_safe_job_id from artifact_storage."""
    import lib.cuckoo.common.artifact_storage as a
    import modules.reporting.centralstore as cs
    assert cs._is_safe_job_id is a._is_safe_job_id
    assert a._is_safe_job_id("ui-42") and a._is_safe_job_id("local-7")
    assert not a._is_safe_job_id("../x") and not a._is_safe_job_id("..") and not a._is_safe_job_id(".x")


def test_rds_job_id_nonnumeric_not_logged_as_rds_failure(monkeypatch, caplog):
    """A non-numeric task_id (the filereport/full_memory \\w+ routes) is bad INPUT, not an
    RDS error: _rds_job_id returns None silently and must NOT emit the ERROR-level
    "RDS lookup failed" traceback (which would flood logs + mask real pool-exhaustion)."""
    import logging
    import sys
    import types
    import lib.cuckoo.common.artifact_storage as a

    fake = types.ModuleType("lib.cuckoo.core.database")

    class _DB:
        def view_task(self, tid):
            return types.SimpleNamespace(custom="job_id=ui-1")
    fake.Database = _DB
    monkeypatch.setitem(sys.modules, "lib.cuckoo.core.database", fake)
    with caplog.at_level(logging.ERROR, logger=a.log.name):
        assert a._rds_job_id("abc") is None
    assert not [r for r in caplog.records if "RDS lookup failed" in r.getMessage()], \
        [r.getMessage() for r in caplog.records]


def test_job_id_for_task_rds_no_scope_skips_mongo(monkeypatch):
    """RDS job_id + no scope (see-all/break-glass): return it directly, no mongo verify."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-42")

    def boom(*x, **k):
        raise AssertionError("mongo consulted on the unscoped RDS path")
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", boom, raising=False)
    assert a._job_id_for_task(42, scope=None) == "ui-42"


def test_job_id_for_task_rds_scoped_authorizes(monkeypatch):
    """RDS job_id + scope: the resolved doc must pass a per-call authorization (in scope OR
    unstamped). job_id is from user custom, so it is NOT trusted blindly."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-42")
    seen = {}

    def find(coll, q, proj):
        seen["q"] = q
        return {"_id": 1}  # authorized: doc in scope-or-unstamped
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", find, raising=False)
    scope = {"info.tenant_id": 7}
    assert a._job_id_for_task(42, scope=scope) == "ui-42"
    # the unstamped OR-arm is constrained to THIS task (info.id == 42), not a bare tenant_id:null
    assert seen["q"] == {"$and": [{"info.job_id": "ui-42"},
                                  {"$or": [scope, {"$and": [{"info.tenant_id": None}, {"info.id": 42}]}]}]}


def _matches(doc, flt):
    """Minimal Mongo-filter evaluator ($and/$or/dotted equality, None=null) so the test can assert
    which doc the authorization query actually returns."""
    if "$and" in flt:
        return all(_matches(doc, s) for s in flt["$and"])
    if "$or" in flt:
        return any(_matches(doc, s) for s in flt["$or"])
    for key, want in flt.items():
        cur = doc
        for part in key.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur != want:
            return False
    return True


def test_job_id_for_task_forged_unstamped_cross_task_denied(monkeypatch):
    """Adversarial-review HIGH (artifact path): a forged custom job_id (ui-42) whose victim doc is
    UNSTAMPED but belongs to a DIFFERENT task (info.id=42) than the attacker's authorized task (999)
    must NOT authorize -> Http404. The owner's OWN unstamped doc (info.id == task_id) still resolves."""
    import lib.cuckoo.common.artifact_storage as a
    import pytest
    from django.http import Http404
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-42")

    victim = {"info": {"job_id": "ui-42", "id": 42, "tenant_id": None}}   # different task, unstamped

    def find(coll, q, proj):
        return {"_id": 1} if _matches(victim, q) else None
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", find, raising=False)

    # attacker's authorized task is 999 -> info.id==999 arm can't match the victim's info.id==42
    with pytest.raises(Http404):
        a._job_id_for_task(999, scope={"info.tenant_id": "A"})

    # the legit owner viewing their own task 42 (doc re-keyed to 42) still resolves
    a._JOB_ID_CACHE.clear()
    assert a._job_id_for_task(42, scope={"info.tenant_id": "A"}) == "ui-42"


def test_job_id_for_task_rds_forged_denied(monkeypatch):
    """A FORGED custom job_id pointing at another tenant's STAMPED doc fails the per-call
    authorization (the authq matches nothing) -> Http404, not a cross-tenant serve."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-victim")
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", lambda *x, **k: None, raising=False)
    import pytest
    from django.http import Http404
    with pytest.raises(Http404):
        a._job_id_for_task(9, scope={"info.tenant_id": 7})


def test_job_id_for_task_bridge_required_denies_nonbridged_scoped(monkeypatch):
    """Option A: bridge-required (central+MT) + a tenant scope + no RDS ui- job_id -> Http404. A non-bridged
    task has no tenant-safe artifact, so we must NOT fall through to the info.id lookup (whose scope arm could
    surface a foreign public collision). Break-glass (scope None) is unaffected -- covered separately."""
    import lib.cuckoo.common.artifact_storage as a
    import lib.cuckoo.common.central_mode as cm
    import pytest
    from django.http import Http404
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: None)          # non-bridged
    monkeypatch.setattr(cm, "central_bridge_required", lambda: True)

    def boom(*x, **k):
        raise AssertionError("mongo fallback consulted despite bridge-required")
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", boom, raising=False)
    with pytest.raises(Http404):
        a._job_id_for_task(9, scope={"info.tenant_id": 3})


def test_job_id_for_task_bridge_required_break_glass_still_falls_back(monkeypatch):
    """scope None (see-all / break-glass / MT-off) is NOT denied even when the bridge is required -- there is
    no tenant boundary to cross, so an admin can still resolve a non-bridged doc."""
    import lib.cuckoo.common.artifact_storage as a
    import lib.cuckoo.common.central_mode as cm
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: None)
    monkeypatch.setattr(cm, "central_bridge_required", lambda: True)
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one",
                        lambda coll, q, proj: {"info": {"job_id": "local-9"}}, raising=False)
    assert a._job_id_for_task(9, scope=None) == "local-9"


def test_job_id_for_task_fallback_scoped(monkeypatch):
    """Non-bridged (no RDS job_id): fall back to the mongo info.id lookup ANDed with the
    viewer scope (the cross-store id-collision defence)."""
    import lib.cuckoo.common.artifact_storage as a
    import lib.cuckoo.common.central_mode as cm
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: None)
    monkeypatch.setattr(cm, "central_bridge_required", lambda: False)  # pin: non-bridge fallback is allowed
    seen = {}

    def fake_find(coll, query, proj):
        seen["query"] = query
        return {"info": {"job_id": "wl-9"}}
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", fake_find, raising=False)
    scope = {"info.tenant_id": 3}
    assert a._job_id_for_task(9, scope=scope) == "wl-9"
    assert seen["query"] == {"$and": [{"info.id": 9}, scope]}, seen["query"]


def test_store_and_container_rejects_unsafe_fallback_jobid(monkeypatch):
    """Defence-in-depth: even if _job_id_for_task returns a path-unsafe job_id (a hostile info.job_id from a
    second/legacy writer of the shared collection, which the mongo-fallback path does NOT re-validate),
    _store_and_container must raise Http404 rather than build a container-escaping '<prefix>/../../etc'."""
    import lib.cuckoo.common.artifact_storage as a
    from django.http import Http404
    import pytest

    cfg = type("C", (), {"s3_prefix": "results"})()
    monkeypatch.setattr(a, "central_mode_config", lambda: cfg, raising=False)
    monkeypatch.setattr(a, "get_artifact_store", lambda c: (object(), True), raising=False)  # central store
    monkeypatch.setattr(a, "_job_id_for_task", lambda tid, scope=None: "../../../../etc", raising=False)
    with pytest.raises(Http404):
        a._store_and_container(42, scope=None)
    # a safe job_id still builds the expected container:
    monkeypatch.setattr(a, "_job_id_for_task", lambda tid, scope=None: "ui-42", raising=False)
    _store, container = a._store_and_container(42, scope=None)
    assert container == "results/ui-42"


def test_store_and_container_nonstring_fallback_jobid_is_http404(monkeypatch):
    """The mongo-fallback branch returns info.job_id straight from the shared collection with no type check, so
    a non-str value (e.g. an int written by a second/legacy writer -- the exact threat the guard cites) must
    yield a clean Http404, NOT a TypeError->500 (which the central_views except-Http404 handlers would miss)."""
    import lib.cuckoo.common.artifact_storage as a
    from django.http import Http404
    import pytest

    cfg = type("C", (), {"s3_prefix": "results"})()
    monkeypatch.setattr(a, "central_mode_config", lambda: cfg, raising=False)
    monkeypatch.setattr(a, "get_artifact_store", lambda c: (object(), True), raising=False)
    monkeypatch.setattr(a, "_job_id_for_task", lambda tid, scope=None: 12345, raising=False)  # non-str
    with pytest.raises(Http404):
        a._store_and_container(42, scope=None)


def test_is_safe_job_id_nonstring_is_false():
    """_is_safe_job_id must be type-safe (isinstance str), not raise, for a non-str input."""
    import lib.cuckoo.common.artifact_storage as a
    assert a._is_safe_job_id(12345) is False
    assert a._is_safe_job_id(None) is False
    assert a._is_safe_job_id(b"ui-1") is False
