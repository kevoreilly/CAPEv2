"""Worker-side report pipeline under multitenancy: a report renumbered to the main/central task id.

utils/process.py runs the report hooks, then modules/reporting/mongodb.py runs them again on a copy,
where info.id is already the other server's id: neither pass may use this worker's task_acl row with
that number (an unrelated task), nor its storage/analyses/<that id> directory.
"""
import copy
import types

import sqlalchemy as sa
from sqlalchemy.orm import Session


def _setup(monkeypatch, tmp_path):
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy import hooks as th
    from lib.tenancy.acl import ensure_acl_schema, set_task_acl
    from lib.tenancy.storage.config import ObjectStorageConfig

    engine = sa.create_engine(f"sqlite:///{tmp_path}/w.db")
    ensure_acl_schema(engine)
    with Session(engine) as s:
        # worker-local task 3: an unrelated public task of another user
        set_task_acl(s, 3, user_id=1, tenant_id=None, visibility="public")
        # worker-local task 9: the bridged task itself (submitted by the broker account)
        set_task_acl(s, 9, user_id=5, tenant_id=7, visibility="private")
        s.commit()
    monkeypatch.setattr("lib.cuckoo.core.database.Database", lambda: types.SimpleNamespace(session=Session(engine)))
    monkeypatch.setattr(th, "multitenancy_config", lambda: types.SimpleNamespace(enabled=True))
    cfg = ObjectStorageConfig(enabled=True, backend="local", local_root=str(tmp_path / "store"), prefix="results")
    monkeypatch.setattr("lib.tenancy.storage.config.object_storage_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.storage.reporting.object_storage_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.storage.reporting.object_storage_bridge_required", lambda: True)
    monkeypatch.setattr("lib.tenancy.storage.reporting.CUCKOO_ROOT", str(tmp_path))
    # the broker's stamp for central task 3's real owner
    monkeypatch.setenv("CAPE_TASK_VISIBILITY", "private")
    monkeypatch.setenv("CAPE_TASK_TENANT_ID", "2")
    monkeypatch.setenv("CAPE_TASK_USER_ID", "42")
    monkeypatch.delenv("CAPE_MAIN_TASK_ID", raising=False)
    analysis = tmp_path / "storage" / "analyses" / "9"
    (analysis / "reports").mkdir(parents=True)
    (analysis / "a.txt").write_text("x")
    core_hooks.clear_all_hooks()
    core_hooks.register_report_hook(th.default_report_stamp_hook)
    return core_hooks, analysis


def _mongo(monkeypatch, inserted):
    import modules.reporting.mongodb as m

    monkeypatch.setattr(m, "HAVE_MONGO", True)
    monkeypatch.setattr(m, "mongo_collection_names", lambda: ["cuckoo_schema"])
    monkeypatch.setattr(m, "mongo_find_one", lambda *a, **k: {"version": m.MongoDB.SCHEMA_VERSION})
    monkeypatch.setattr(m, "mongo_delete_data", lambda ids: None)
    monkeypatch.setattr(m, "insert_calls", lambda report, mongodb: [])
    monkeypatch.setattr(m, "ensure_valid_utf8", lambda report: None)
    monkeypatch.setattr(m, "mongo_insert_one", lambda collection, doc: inserted.append(copy.deepcopy(doc)))
    return m


def test_bridged_report_in_mongo_keeps_the_broker_stamp(monkeypatch, tmp_path):
    core_hooks, analysis = _setup(monkeypatch, tmp_path)
    try:
        results = {"info": {"id": 9, "custom": "job_id=ui-3"}, "behavior": {"processes": [], "processtree": [], "summary": {}}}
        # utils/process.py: run_report_hooks(results) before signatures/reporting
        core_hooks.run_report_hooks(results)
        pinfo = dict(results["info"])
        _ = ("process-level results['info']:", {k: pinfo.get(k) for k in ("id", "job_id", "user_id", "tenant_id", "visibility", "_renumbered_from")})
        # reporting phase: modules/reporting/mongodb.py
        inserted = []
        m = _mongo(monkeypatch, inserted)
        reporter = m.MongoDB()
        reporter.task = {"id": 9, "attributes": {}}
        reporter.set_path(str(analysis))
        reporter.run(results)
        minfo = inserted[-1]["info"]
        _ = ("mongo-stored info:", {k: minfo.get(k) for k in ("id", "job_id", "user_id", "tenant_id", "visibility", "visibility_seq")})
    finally:
        core_hooks.clear_all_hooks()
    assert (pinfo["user_id"], pinfo["tenant_id"], pinfo["visibility"]) == (42, 2, "private")
    assert (minfo["id"], minfo["user_id"], minfo["tenant_id"], minfo["visibility"]) == (3, 42, 2, "private"), minfo


def test_retried_bridged_upload_ships_the_unrelated_local_task_dir(monkeypatch, tmp_path):
    """Pre-existing, same root cause: after one transient put_file failure the mongodb.py hook pass
    re-runs the upload with info.id already renumbered to the central id, so it uploads the worker's
    unrelated storage/analyses/<central id> tree into the central job's container."""
    core_hooks, analysis = _setup(monkeypatch, tmp_path)
    other = tmp_path / "storage" / "analyses" / "3"  # worker-local task 3: another tenant's analysis
    (other / "reports").mkdir(parents=True)
    (other / "secret_of_other_tenant.txt").write_text("other tenant data")
    import lib.tenancy.storage.reporting as rep
    from lib.tenancy.storage.storage_backend import LocalFSStore

    real_store = LocalFSStore(str(tmp_path / "store"))
    calls = {"n": 0}

    class Flaky(LocalFSStore):
        def put_file(self, local_path, container, relpath):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("transient S3 error")
            return real_store.put_file(local_path, container, relpath)

    monkeypatch.setattr(rep, "get_artifact_store", lambda cfg: (Flaky(str(tmp_path / "store")), True))
    try:
        results = {"info": {"id": 9, "custom": "job_id=ui-3"}, "behavior": {"processes": [], "processtree": [], "summary": {}}}
        core_hooks.run_report_hooks(results)  # utils/process.py pass: one upload fails
        inserted = []
        m = _mongo(monkeypatch, inserted)
        reporter = m.MongoDB()
        reporter.task = {"id": 9, "attributes": {}}
        reporter.set_path(str(analysis))
        reporter.run(results)  # mongodb.py hook pass retries the upload
    finally:
        core_hooks.clear_all_hooks()
    import os
    shipped = sorted(os.listdir(tmp_path / "store" / "results" / "ui-3"))
    _ = ("central job ui-3 container:", shipped)
    assert "secret_of_other_tenant.txt" not in shipped


def test_reprocess_visibility_override_reaches_mongo_on_a_dist_worker(monkeypatch, tmp_path):
    # utils/process.py -r 9 --visibility public on a dist worker: the override wrote this worker's
    # task_acl row keyed by the MAIN id (another task) and, with the main's ACL applied last, never
    # reached Mongo. It now travels in the task_acl the reporters apply.
    import contextlib

    import utils.process as proc
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy import hooks as th
    from lib.tenancy.acl import ensure_acl_schema, resolve_task_scope, set_task_acl

    engine = sa.create_engine(f"sqlite:///{tmp_path}/w.db")
    ensure_acl_schema(engine)
    with Session(engine) as s:
        set_task_acl(s, 3, user_id=1, tenant_id=7, visibility="private")  # unrelated worker task 3
        s.commit()
    monkeypatch.setattr("lib.cuckoo.core.database.Database", lambda: types.SimpleNamespace(session=Session(engine)))
    monkeypatch.setattr(th, "multitenancy_config", lambda: types.SimpleNamespace(enabled=True))
    monkeypatch.setattr("lib.tenancy.storage.config.object_storage_config", lambda: types.SimpleNamespace(enabled=False))
    for k in ("CAPE_TASK_VISIBILITY", "CAPE_TASK_TENANT_ID", "CAPE_TASK_USER_ID"):
        monkeypatch.delenv(k, raising=False)

    class _Begin:
        def begin(self):
            return contextlib.nullcontext()

        def remove(self):
            pass

    monkeypatch.setattr(proc, "db", types.SimpleNamespace(session=_Begin(), engine=engine, set_status=lambda *a: None))
    monkeypatch.setattr(proc, "init_per_analysis_logging", lambda **kw: types.SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(proc, "set_formatter_fmt", lambda *a: None)

    class _Processing:
        def __init__(self, task, results):
            self.results = results

        def run(self):
            self.results["info"] = {"id": 9}
            self.results["behavior"] = {"processes": [], "processtree": [], "summary": {}}

    inserted = []
    m = _mongo(monkeypatch, inserted)

    class _Reporting:
        def __init__(self, task, results, reprocess):
            self.task, self.results = task, results

        def run(self):
            reporter = m.MongoDB()
            reporter.task = self.task
            reporter.analysis_path = str(tmp_path)
            reporter.run(self.results)
            return 0

    monkeypatch.setattr(proc, "RunProcessing", _Processing)
    monkeypatch.setattr(proc, "RunSignatures", lambda task, results: types.SimpleNamespace(run=lambda: None))
    monkeypatch.setattr(proc, "RunReporting", _Reporting)
    core_hooks.clear_all_hooks()
    core_hooks.register_report_hook(th.default_report_stamp_hook)
    task = {"id": 9, "options": "", "attributes": {"main_task_id": 3, "task_acl": {"user_id": 42, "tenant_id": 2, "visibility": "private", "visibility_seq": 4}}}
    try:
        proc.process(task=task, report=True, visibility="public")
    finally:
        core_hooks.clear_all_hooks()
    info = inserted[-1]["info"]
    assert (info["id"], info["user_id"], info["tenant_id"], info["visibility"]) == (3, 42, 2, "public"), info
    with Session(engine) as s:
        assert resolve_task_scope(s, 3).visibility == "private"  # the unrelated worker row is untouched


def test_partial_task_acl_still_takes_owner_from_the_unrelated_worker_row(monkeypatch, tmp_path):
    """dist.py's probe on the main yields {"visibility": "private", "visibility_seq": 0} when the main
    task has no task_acl row (or the probe's lookup raised, which the hook swallows): mongodb.py then
    keeps user_id/tenant_id from the worker's unrelated row with the main task id."""
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy import hooks as th
    from lib.tenancy.acl import ensure_acl_schema, set_task_acl

    # what the main's probe produces with no row: run the real hook on the main side
    main_engine = sa.create_engine(f"sqlite:///{tmp_path}/main.db")
    ensure_acl_schema(main_engine)
    monkeypatch.setattr("lib.cuckoo.core.database.Database", lambda: types.SimpleNamespace(session=Session(main_engine)))
    monkeypatch.setattr(th, "multitenancy_config", lambda: types.SimpleNamespace(enabled=True))
    monkeypatch.setattr("lib.tenancy.storage.config.object_storage_config", lambda: types.SimpleNamespace(enabled=False))
    for k in ("CAPE_TASK_VISIBILITY", "CAPE_TASK_TENANT_ID", "CAPE_TASK_USER_ID"):
        monkeypatch.delenv(k, raising=False)
    probe = {"info": {"id": 3}}
    th.default_report_stamp_hook(probe)
    task_acl = {k: v for k, v in probe["info"].items() if k in ("user_id", "tenant_id", "visibility", "visibility_seq")}
    _ = ("task_acl dist.py sends:", task_acl)

    # the worker
    w_engine = sa.create_engine(f"sqlite:///{tmp_path}/w.db")
    ensure_acl_schema(w_engine)
    with Session(w_engine) as s:
        set_task_acl(s, 3, user_id=1, tenant_id=7, visibility="public")  # unrelated worker task 3
        s.commit()
    monkeypatch.setattr("lib.cuckoo.core.database.Database", lambda: types.SimpleNamespace(session=Session(w_engine)))
    core_hooks.clear_all_hooks()
    core_hooks.register_report_hook(th.default_report_stamp_hook)
    try:
        inserted = []
        m = _mongo(monkeypatch, inserted)
        reporter = m.MongoDB()
        reporter.task = {"id": 9, "attributes": {"main_task_id": 3, "task_acl": task_acl}}
        reporter.analysis_path = str(tmp_path)
        reporter.run({"info": {"id": 9, "user_id": 5}, "behavior": {"processes": [], "processtree": [], "summary": {}}})
    finally:
        core_hooks.clear_all_hooks()
    info = inserted[-1]["info"]
    _ = ("mongo-stored:", {k: info.get(k) for k in ("id", "user_id", "tenant_id", "visibility")})
    assert (info["user_id"], info["tenant_id"]) == (None, None)
