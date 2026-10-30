"""utils/process.py end to end on a worker: both report-hook passes, then the mongodb reporter.

Operator overrides (process.py -r --visibility/--tenant-id) reach every store; a report filed under
another server's id never keeps this node's owner, tenant or task directory; plain single-node
reports are untouched.
"""
import contextlib
import copy
import json
import types

import sqlalchemy as sa
from sqlalchemy.orm import Session


def _mongo(monkeypatch, inserted, dump_iocs=False):
    import modules.reporting.mongodb as m

    monkeypatch.setattr(m, "HAVE_MONGO", True)
    monkeypatch.setattr(m, "mongo_collection_names", lambda: ["cuckoo_schema"])
    monkeypatch.setattr(m, "mongo_find_one", lambda *a, **k: {"version": m.MongoDB.SCHEMA_VERSION})
    monkeypatch.setattr(m, "mongo_delete_data", lambda ids: None)
    monkeypatch.setattr(m, "insert_calls", lambda report, mongodb: [])
    monkeypatch.setattr(m, "ensure_valid_utf8", lambda report: None)
    monkeypatch.setattr(m, "mongo_insert_one", lambda collection, doc: inserted.append(copy.deepcopy(doc)))
    monkeypatch.setattr(m, "reporting_conf", types.SimpleNamespace(mongodb=types.SimpleNamespace(dump_iocs=dump_iocs)))
    return m


def _proc_env(monkeypatch, tmp_path, object_storage=True, env=None):
    import utils.process as proc
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy import hooks as th
    from lib.tenancy.acl import ensure_acl_schema, set_task_acl
    from lib.tenancy.storage.config import ObjectStorageConfig

    engine = sa.create_engine(f"sqlite:///{tmp_path}/w.db")
    ensure_acl_schema(engine)
    with Session(engine) as s:
        set_task_acl(s, 3, user_id=1, tenant_id=None, visibility="public")  # unrelated local task 3
        set_task_acl(s, 9, user_id=5, tenant_id=7, visibility="private")  # the bridged task itself
        s.commit()
    monkeypatch.setattr("lib.cuckoo.core.database.Database", lambda: types.SimpleNamespace(session=Session(engine)))
    monkeypatch.setattr(th, "multitenancy_config", lambda: types.SimpleNamespace(enabled=True))
    if object_storage:
        cfg = ObjectStorageConfig(enabled=True, backend="local", local_root=str(tmp_path / "store"), prefix="results")
    else:
        cfg = types.SimpleNamespace(enabled=False)
    monkeypatch.setattr("lib.tenancy.storage.config.object_storage_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.storage.reporting.object_storage_config", lambda: cfg)
    monkeypatch.setattr("lib.tenancy.storage.reporting.object_storage_bridge_required", lambda: True)
    monkeypatch.setattr("lib.tenancy.storage.reporting.CUCKOO_ROOT", str(tmp_path))
    for k in ("CAPE_TASK_VISIBILITY", "CAPE_TASK_TENANT_ID", "CAPE_TASK_USER_ID", "CAPE_TASK_VISIBILITY_SEQ", "CAPE_MAIN_TASK_ID"):
        monkeypatch.delenv(k, raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    analysis = tmp_path / "storage" / "analyses" / "9"
    (analysis / "reports").mkdir(parents=True)
    (analysis / "a.txt").write_text("x")

    class _Begin:
        def begin(self):
            return contextlib.nullcontext()

        def remove(self):
            pass

    monkeypatch.setattr(proc, "db", types.SimpleNamespace(session=_Begin(), engine=engine, set_status=lambda *a: None))
    monkeypatch.setattr(proc, "init_per_analysis_logging", lambda **kw: types.SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(proc, "set_formatter_fmt", lambda *a: None)
    core_hooks.clear_all_hooks()
    core_hooks.register_report_hook(th.default_report_stamp_hook)
    return proc, core_hooks, analysis


def _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task, info, **kw):
    inserted, seen = [], {}
    m = _mongo(monkeypatch, inserted, dump_iocs=kw.pop("dump_iocs", False))

    class _Processing:
        def __init__(self, task, results):
            self.results = results

        def run(self):
            self.results["info"] = dict(info)
            self.results["behavior"] = {"processes": [], "processtree": [], "summary": {}}

    class _Reporting:
        def __init__(self, task, results, reprocess):
            self.task, self.results = task, results

        def run(self):
            seen.update(self.results["info"])  # what jsondump / ES / litereport store
            reporter = m.MongoDB()
            reporter.task = self.task
            reporter.set_path(str(analysis))
            reporter.run(self.results)
            return 0

    monkeypatch.setattr(proc, "RunProcessing", _Processing)
    monkeypatch.setattr(proc, "RunSignatures", lambda task, results: types.SimpleNamespace(run=lambda: None))
    monkeypatch.setattr(proc, "RunReporting", _Reporting)
    try:
        proc.process(task=task, report=True, **kw)
    finally:
        core_hooks.clear_all_hooks()
    return seen, inserted[-1]["info"]


def _pick(d):
    return {k: d.get(k) for k in ("id", "local_task_id", "job_id", "user_id", "tenant_id", "visibility", "visibility_seq")}


def test_bridged_reprocess_tenant_override_reaches_mongo(monkeypatch, tmp_path):
    """utils/process.py -r 9 --visibility tenant --tenant-id 5 on an object-storage bridged (non-dist) report."""
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path)
    task = {"id": 9, "options": "", "custom": "job_id=ui-3", "attributes": {}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task,
                       {"id": 9, "custom": "job_id=ui-3", "user_id": 5}, visibility="tenant", tenant_id=5)
    print("mongo info:", _pick(minfo))
    assert (seen["tenant_id"], seen["visibility"]) == (5, "tenant")
    assert (minfo["tenant_id"], minfo["visibility"]) == (5, "tenant"), _pick(minfo)


def test_bridged_reprocess_visibility_override_reaches_mongo(monkeypatch, tmp_path):
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path)
    task = {"id": 9, "options": "", "custom": "job_id=ui-3", "attributes": {}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task,
                       {"id": 9, "custom": "job_id=ui-3", "user_id": 5}, visibility="public")
    print("mongo info:", _pick(minfo))
    assert minfo["visibility"] == "public"


def test_plain_single_node_report_has_no_local_task_id(monkeypatch, tmp_path):
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path, object_storage=False)
    task = {"id": 9, "options": "", "custom": "", "attributes": {}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task, {"id": 9, "custom": "", "user_id": 5})
    print("mongo info:", _pick(minfo))
    assert "local_task_id" not in minfo and "local_task_id" not in seen
    assert (minfo["id"], minfo["user_id"], minfo["tenant_id"], minfo["visibility"]) == (9, 5, 7, "private")


def test_single_node_refused_upload_keeps_the_local_stamp(monkeypatch, tmp_path):
    """single node, object storage on, MT on, no bridge: refused upload; must keep local stamp, no local_task_id."""
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path, object_storage=True)
    task = {"id": 9, "options": "", "custom": "", "attributes": {}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task, {"id": 9, "custom": "", "user_id": 5})
    print("mongo info:", _pick(minfo))
    assert "local_task_id" not in minfo and "local_task_id" not in seen
    assert (minfo["id"], minfo["user_id"], minfo["tenant_id"], minfo["visibility"]) == (9, 5, 7, "private")


def test_dump_iocs_writes_this_tasks_directory(monkeypatch, tmp_path):
    """object-storage-renumbered report with dump_iocs on: iocs.json must land in analyses/9, never analyses/3."""
    import lib.cuckoo.common.iocs as iocs

    monkeypatch.setattr(iocs, "CUCKOO_ROOT", str(tmp_path))
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path)
    other = tmp_path / "storage" / "analyses" / "3" / "reports"
    other.mkdir(parents=True)
    (other / "iocs.json").write_text('{"owner": "other tenant"}')
    task = {"id": 9, "options": "", "custom": "job_id=ui-3", "attributes": {}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task,
                       {"id": 9, "custom": "job_id=ui-3", "user_id": 5}, dump_iocs=True)
    print("analyses/3 iocs:", (other / "iocs.json").read_text()[:60])
    assert json.loads((other / "iocs.json").read_text()) == {"owner": "other tenant"}
    assert (analysis / "reports" / "iocs.json").exists()


def test_dist_reprocess_tenant_override_reaches_mongo(monkeypatch, tmp_path):
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path, object_storage=False)
    task = {"id": 9, "options": "", "custom": "", "attributes": {"main_task_id": 3, "task_acl": {"user_id": 42, "tenant_id": 2, "visibility": "private", "visibility_seq": 4}}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task,
                       {"id": 9, "custom": "", "user_id": 5}, visibility="tenant", tenant_id=5)
    print("mongo info:", _pick(minfo))
    assert (minfo["tenant_id"], minfo["visibility"]) == (5, "tenant")


def test_partial_central_stamp_leaves_no_worker_owner(monkeypatch, tmp_path):
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path, env={"CAPE_TASK_VISIBILITY": "tenant", "CAPE_TASK_TENANT_ID": "2"})
    task = {"id": 9, "options": "", "custom": "job_id=ui-3", "attributes": {}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task, {"id": 9, "custom": "job_id=ui-3", "user_id": 5})
    print("mongo info:", _pick(minfo))
    assert minfo["user_id"] is None and seen["user_id"] is None


def test_dist_task_without_task_acl_has_no_worker_owner_or_tenant(monkeypatch, tmp_path):
    """dist task whose main sent no task_acl, no env: neither the worker row's owner nor tenant may reach the central doc."""
    proc, core_hooks, analysis = _proc_env(monkeypatch, tmp_path, object_storage=False)
    task = {"id": 9, "options": "", "custom": "", "attributes": {"main_task_id": 3}}
    seen, minfo = _run(monkeypatch, tmp_path, proc, core_hooks, analysis, task, {"id": 9, "custom": "", "user_id": 5})
    print("mongo info:", _pick(minfo))
    assert (minfo["user_id"], minfo["tenant_id"]) == (None, None)
