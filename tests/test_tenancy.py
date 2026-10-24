"""Unit tests for `lib.tenancy` (multi-tenancy, group sandbox policies, and cloud-agnostic object storage)."""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, create_engine
from sqlalchemy.orm import Session, sessionmaker

import lib.tenancy as cape_tenancy
from lib.tenancy import (
    PRIVATE,
    PUBLIC,
    TENANT,
    ObjectStorageConfig,
    ResourceScope,
    TenancyMiddleware,
    ViewerContext,
    VisibilityConflictError,
    can_delete,
    can_read,
    can_set_visibility,
    can_toggle,
    default_es_query_filter,
    default_report_stamp_hook,
    default_sql_task_acl_clause,
    ensure_acl_schema,
    get_current_viewer,
    install,
    resolve_task_scope,
    set_task_acl,
    sync_stamp_to_mongo,
    tenancy_exempt,
    toggle_task_visibility_cas,
    unscoped_context,
    viewer_scope_context,
    wrap_mongodb_module,
)
from lib.tenancy.policy import Job, Viewer, scope_match, viewer_scope_es_filter
from lib.tenancy.storage import (
    AzureBlobStore,
    GCSStore,
    LocalFSStore,
    ObjectStorage,
    S3Store,
    get_artifact_store,
)
from tests.tenancy_vectors import SCOPE_VECTORS, VECTORS


@pytest.mark.parametrize("label,viewer,job,want_read,want_toggle,want_delete", VECTORS, ids=[v[0] for v in VECTORS])
def test_predicate_matches_vectors(label, viewer, job, want_read, want_toggle, want_delete):
    v = Viewer(**viewer)
    j = Job(**job)
    assert can_read(v, j) is want_read, f"{label}: read"
    assert can_toggle(v, j) is want_toggle, f"{label}: toggle"
    assert can_delete(v, j) is want_delete, f"{label}: delete"


def test_can_delete_public_stricter_than_toggle():
    owner = Viewer(user_id=1, tenant_id=10)
    tadmin = Viewer(user_id=2, tenant_id=10, is_tenant_admin=True)
    boxadmin = Viewer(user_id=3, tenant_id=None, is_local_admin=True)
    other = Viewer(user_id=4, tenant_id=10)
    foreign_tadmin = Viewer(user_id=5, tenant_id=99, is_tenant_admin=True)
    pub = Job(owner_id=1, tenant_id=10, visibility="public")
    ten = Job(owner_id=1, tenant_id=10, visibility="tenant")
    priv = Job(owner_id=1, tenant_id=10, visibility="private")

    assert can_toggle(tadmin, pub) is True
    assert can_delete(tadmin, pub) is False
    assert can_delete(owner, pub) is True
    assert can_delete(boxadmin, pub) is True
    assert can_delete(other, pub) is False

    assert [can_delete(x, ten) for x in (owner, tadmin, boxadmin, other)] == [True, True, True, False]
    assert can_delete(foreign_tadmin, ten) is False

    assert [can_delete(x, priv) for x in (owner, tadmin, boxadmin, other)] == [True, True, True, False]
    assert can_delete(foreign_tadmin, priv) is False


def test_can_set_visibility_blocks_tenant_admin_public_downgrade():
    owner = Viewer(user_id=1, tenant_id=10)
    tadmin = Viewer(user_id=2, tenant_id=10, is_tenant_admin=True)
    boxadmin = Viewer(user_id=3, tenant_id=None, is_local_admin=True)
    other = Viewer(user_id=4, tenant_id=10)
    pub = Job(owner_id=1, tenant_id=10, visibility="public")
    ten = Job(owner_id=1, tenant_id=10, visibility="tenant")

    assert can_toggle(tadmin, pub) is True
    assert can_set_visibility(tadmin, pub, "tenant") is False
    assert can_set_visibility(tadmin, pub, "private") is False
    assert can_delete(tadmin, pub) is False
    assert can_set_visibility(tadmin, ten, "public") is True
    assert can_set_visibility(tadmin, pub, "public") is True
    assert can_set_visibility(owner, pub, "tenant") is True
    assert can_set_visibility(boxadmin, pub, "private") is True
    assert can_set_visibility(other, pub, "public") is False


def test_can_delete_orphan_owner_not_deletable_by_anon():
    anon = Viewer(user_id=None, tenant_id=None)
    assert can_delete(anon, Job(owner_id=None, tenant_id=None, visibility="private")) is False
    assert can_delete(anon, Job(owner_id=None, tenant_id=10, visibility="public")) is False
    assert can_delete(anon, Job(owner_id=None, tenant_id=10, visibility="tenant")) is False


def test_config_defaults_and_modes(monkeypatch):
    from lib.tenancy import policy as tenancy

    cfg = tenancy.multitenancy_config()
    assert cfg.enabled in (True, False)
    assert cfg.mode in ("shared", "locked")
    assert isinstance(cfg.local_admins_manage_all_tenants, bool)
    assert tenancy.default_visibility(cfg) in ("public", "tenant", "private")

    shared = tenancy.MTConfig(
        enabled=True, mode="shared", default_visibility="", local_admins_manage_all_tenants=True
    )
    locked = tenancy.MTConfig(
        enabled=True, mode="locked", default_visibility="", local_admins_manage_all_tenants=True
    )
    assert tenancy.default_visibility(shared) == "public"
    assert tenancy.default_visibility(locked) == "tenant"

    def _boom():
        raise RuntimeError("cuckoo.conf parse error")

    monkeypatch.setattr(tenancy, "_load_multitenancy_section", _boom)
    fc = tenancy.multitenancy_config()
    assert fc.enabled is True and fc.mode == "locked"
    assert fc.local_admins_manage_all_tenants is False
    assert tenancy.default_visibility(fc) == tenancy.PRIVATE


def test_scope_match_membership():
    def doc_matches(match, job):
        if match is None:
            return True
        for k, v in match.items():
            if k == "info.id":
                return False
            field = {
                "info.visibility": job.visibility,
                "info.tenant_id": job.tenant_id,
                "info.user_id": job.owner_id,
            }.get(k)
            if field != v:
                return False
        return True

    for viewer, job, scope, expected in SCOPE_VECTORS:
        assert doc_matches(scope_match(scope, viewer), job) is expected, (scope, viewer, job)

    assert scope_match("tenant", None) == {"info.id": -1}
    assert scope_match("mine", None) == {"info.id": -1}
    assert scope_match("public", None) == {"info.visibility": "public"}
    assert scope_match("global", None) is None


def test_policy_predicates():
    alice = ViewerContext(user_id=10, tenant_id=1, is_tenant_admin=False, is_local_admin=False, is_authenticated=True)
    bob_same_tenant = ViewerContext(
        user_id=11, tenant_id=1, is_tenant_admin=False, is_local_admin=False, is_authenticated=True
    )
    tenant_admin = ViewerContext(
        user_id=12, tenant_id=1, is_tenant_admin=True, is_local_admin=False, is_authenticated=True
    )
    charlie_other = ViewerContext(
        user_id=20, tenant_id=2, is_tenant_admin=False, is_local_admin=False, is_authenticated=True
    )

    private_scope = ResourceScope(owner_id=10, tenant_id=1, visibility=PRIVATE)
    tenant_scope = ResourceScope(owner_id=10, tenant_id=1, visibility=TENANT)
    public_scope = ResourceScope(owner_id=10, tenant_id=1, visibility=PUBLIC)

    assert can_read(alice, private_scope) is True
    assert can_read(bob_same_tenant, private_scope) is False
    assert can_read(tenant_admin, private_scope) is True
    assert can_read(charlie_other, private_scope) is False

    assert can_read(bob_same_tenant, tenant_scope) is True
    assert can_read(charlie_other, tenant_scope) is False
    assert can_read(charlie_other, public_scope) is True

    assert can_toggle(alice, private_scope) is True
    assert can_toggle(tenant_admin, private_scope) is True
    assert can_delete(tenant_admin, private_scope) is True
    assert can_toggle(tenant_admin, tenant_scope) is True
    assert can_delete(tenant_admin, tenant_scope) is True
    assert can_delete(bob_same_tenant, tenant_scope) is False


def test_task_acl_and_monotonic_visibility_cas():
    engine = create_engine("sqlite:///:memory:")
    ensure_acl_schema(engine)

    mongo_docs = {
        42: {"info": {"id": 42, "visibility": PRIVATE, "visibility_seq": 0}},
    }

    def fake_mongo_update_one(collection: str, flt: dict, update: dict):
        assert collection == "analysis"
        and_clauses = flt["$and"]
        task_id = and_clauses[0]["info.id"]
        doc = mongo_docs[task_id]
        max_seq = and_clauses[1]["$or"][0]["info.visibility_seq"]["$lte"]
        cur_seq = doc["info"].get("visibility_seq")
        if cur_seq is None or cur_seq <= max_seq:
            doc["info"].update(
                {
                    "user_id": update["$set"]["info.user_id"],
                    "tenant_id": update["$set"]["info.tenant_id"],
                    "visibility": update["$set"]["info.visibility"],
                    "visibility_seq": update["$set"]["info.visibility_seq"],
                }
            )
            return True
        return False

    with Session(engine) as session:
        acl = set_task_acl(session, 42, user_id=10, tenant_id=1, visibility=TENANT)
        session.commit()
        assert acl.visibility_seq == 1
        assert resolve_task_scope(session, 42) == ResourceScope(owner_id=10, tenant_id=1, visibility=TENANT)

        stamp_v2 = toggle_task_visibility_cas(
            session,
            42,
            PRIVATE,
            expected_prior=TENANT,
            mongo_update_one=fake_mongo_update_one,
        )
        assert stamp_v2.visibility_seq == 2
        assert mongo_docs[42]["info"]["visibility"] == PRIVATE
        assert mongo_docs[42]["info"]["visibility_seq"] == 2

        stale_stamp = cape_tenancy.VisibilityStamp(
            task_id=42,
            user_id=10,
            tenant_id=1,
            visibility=TENANT,
            visibility_seq=1,
        )
        updated = sync_stamp_to_mongo(stale_stamp, mongo_update_one=fake_mongo_update_one)
        assert updated is False
        assert mongo_docs[42]["info"]["visibility"] == PRIVATE
        assert mongo_docs[42]["info"]["visibility_seq"] == 2

        with pytest.raises(VisibilityConflictError):
            toggle_task_visibility_cas(session, 42, PUBLIC, expected_prior=TENANT)


def test_contextvar_and_mongodb_auto_scoping(monkeypatch):
    monkeypatch.setattr(
        "lib.tenancy.policy.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="shared", default_visibility="public", local_admins_manage_all_tenants=True
        ),
    )
    captured_queries = []

    fake_mongo = types.ModuleType("fake_dev_utils_mongodb")

    def mongo_find(collection, query, *args, **kwargs):
        captured_queries.append(("find", collection, query))
        return []

    def mongo_find_one(collection, query, *args, **kwargs):
        captured_queries.append(("find_one", collection, query))
        return None

    def mongo_aggregate(collection, pipeline, *args, **kwargs):
        captured_queries.append(("aggregate", collection, pipeline))
        return []

    fake_mongo.mongo_find = mongo_find
    fake_mongo.mongo_find_one = mongo_find_one
    fake_mongo.mongo_aggregate = mongo_aggregate

    wrap_mongodb_module(fake_mongo)

    viewer = ViewerContext(user_id=7, tenant_id=3, is_tenant_admin=False, is_local_admin=False, is_authenticated=True)

    with viewer_scope_context(viewer):
        assert get_current_viewer() == viewer
        fake_mongo.mongo_find_one("analysis", {"info.id": 99})
        fake_mongo.mongo_find("calls", {"_id": "abc"})
        fake_mongo.mongo_aggregate("analysis", [{"$project": {"info.id": 1}}])

        with unscoped_context():
            fake_mongo.mongo_find_one("analysis", {"info.id": 99})

    assert get_current_viewer() is None

    kind, coll, q1 = captured_queries[0]
    assert (kind, coll) == ("find_one", "analysis")
    assert "$and" in q1
    assert q1["$and"][0] == {"info.id": 99}
    assert {"info.visibility": PUBLIC} in q1["$and"][1]["$or"]
    assert {"info.user_id": 7} in q1["$and"][1]["$or"]
    assert {"info.tenant_id": 3, "info.visibility": TENANT} in q1["$and"][1]["$or"]

    assert captured_queries[1] == ("find", "calls", {"_id": "abc"})
    _, _, pipe = captured_queries[2]
    assert "$match" in pipe[0]
    assert captured_queries[3] == ("find_one", "analysis", {"info.id": 99})


def test_middleware_process_view_gates_tasks_and_samples():
    scopes = {
        100: ResourceScope(owner_id=10, tenant_id=1, visibility=PRIVATE),
        101: ResourceScope(owner_id=10, tenant_id=1, visibility=TENANT),
        102: ResourceScope(owner_id=10, tenant_id=1, visibility=PUBLIC),
    }

    viewer_bob = ViewerContext(
        user_id=11, tenant_id=1, is_tenant_admin=False, is_local_admin=False, is_authenticated=True
    )

    mw = TenancyMiddleware(
        lambda req: {"status_code": 200, "viewer": get_current_viewer()},
        viewer_resolver=lambda user: viewer_bob,
        task_scope_resolver=lambda tid: scopes.get(tid),
        sample_access_checker=lambda v, flt: flt.get("sha256") == "allowed_sha256",
        deny_response_factory=lambda req, msg: {"status_code": 404, "error_value": msg},
    )

    def report_view(request, task_id):
        return {"status_code": 200}

    def delete_task_view(request, task_id):
        return {"status_code": 200}

    @tenancy_exempt
    def public_health_view(request, task_id):
        return {"status_code": 200}

    req = types.SimpleNamespace(path="/analysis/100/", user=object())
    res_private = mw.process_view(req, report_view, (), {"task_id": 100})
    assert res_private == {"status_code": 404, "error_value": "Task not found"}

    req.path = "/analysis/101/"
    assert mw.process_view(req, report_view, (), {"task_id": 101}) is None

    req.path = "/apiv2/tasks/delete/101/"
    res_del = mw.process_view(req, delete_task_view, (), {"task_id": 101})
    assert res_del == {"status_code": 404, "error_value": "Task not found"}

    assert mw.process_view(req, public_health_view, (), {"task_id": 100}) is None

    req.path = "/apiv2/files/view/sha256/blocked_sha256/"
    res_sample = mw.process_view(req, report_view, (), {"sha256": "blocked_sha256"})
    assert res_sample == {"status_code": 404, "error_value": "Sample not found in database"}
    assert mw.process_view(req, report_view, (), {"sha256": "allowed_sha256"}) is None


def test_install_into_django_settings():
    settings_dict = {
        "INSTALLED_APPS": ["django.contrib.auth", "analysis"],
        "MIDDLEWARE": ["django.contrib.auth.middleware.AuthenticationMiddleware"],
        "TEMPLATES": [
            {"BACKEND": "django.template.backends.django.DjangoTemplates", "OPTIONS": {"context_processors": []}}
        ],
    }
    install(settings_dict, wrap_mongo=False)
    assert settings_dict["INSTALLED_APPS"][0] == "lib.tenancy.apps.CapeTenancyConfig"
    assert "lib.tenancy.middleware.TenancyMiddleware" in settings_dict["MIDDLEWARE"]
    assert (
        "lib.tenancy.context_processors.tenancy_context"
        in settings_dict["TEMPLATES"][0]["OPTIONS"]["context_processors"]
    )


def test_es_and_sql_filter_helpers(monkeypatch):
    monkeypatch.setattr(
        "lib.tenancy.policy.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="shared", default_visibility="public", local_admins_manage_all_tenants=True
        ),
    )
    viewer = ViewerContext(user_id=5, tenant_id=2, is_tenant_admin=False, is_local_admin=False, is_authenticated=True)
    with viewer_scope_context(viewer):
        es_body = default_es_query_filter({"query": {"term": {"target": "evil.exe"}}})
        assert "bool" in es_body["query"]
        assert es_body["query"]["bool"]["must"] == [{"term": {"target": "evil.exe"}}]
        assert len(es_body["query"]["bool"]["filter"]) == 1

        sql_clause = default_sql_task_acl_clause(Column("id", Integer), Column("user_id", Integer))
        assert sql_clause is not None


def test_local_storage_backend_roundtrip(tmp_path: Path):
    backend = LocalFSStore(str(tmp_path))
    src = tmp_path / "source.bin"
    src.write_bytes(b"MZ-test-payload")
    backend.put_file(str(src), "jobs/ui-10", "binary")
    assert backend.exists("jobs/ui-10", "binary") is True
    chunks, length = backend.stream("jobs/ui-10", "binary")
    assert b"".join(chunks) == b"MZ-test-payload"
    assert length == len(b"MZ-test-payload")


def test_cloud_agnostic_object_storage_config_and_backends(monkeypatch, tmp_path: Path):
    from lib.tenancy.storage.config import _parse

    # 1. New vendor-neutral [object_storage] keys
    cfg_gcs = _parse(
        {
            "enabled": "yes",
            "backend": "gcs",
            "bucket": "cape-artifacts-gcp",
            "prefix": "analyses",
            "gcp_project": "my-gcp-proj",
            "gcp_credentials_path": "/etc/cape/gcp.json",
        }
    )
    assert cfg_gcs.enabled is True
    assert cfg_gcs.backend == "gcs"
    assert cfg_gcs.storage_backend == "gcs"
    assert cfg_gcs.bucket == "cape-artifacts-gcp"
    assert cfg_gcs.s3_bucket == "cape-artifacts-gcp"
    assert cfg_gcs.prefix == "analyses"
    assert cfg_gcs.gcp_project == "my-gcp-proj"

    store_gcs, is_remote = get_artifact_store(cfg_gcs)
    assert is_remote is True
    assert isinstance(store_gcs, GCSStore)
    assert store_gcs.bucket_name == "cape-artifacts-gcp"
    assert store_gcs.project == "my-gcp-proj"

    # 2. Azure Blob Storage backend
    cfg_az = _parse(
        {
            "enabled": "yes",
            "backend": "azure",
            "bucket": "cape-container",
            "azure_connection_string": "DefaultEndpointsProtocol=https;AccountName=test;",
        }
    )
    store_az, is_remote_az = get_artifact_store(cfg_az)
    assert is_remote_az is True
    assert isinstance(store_az, AzureBlobStore)
    assert store_az.container_name == "cape-container"

    # 3. Legacy [central_mode] keys remain 100% compatible
    cfg_s3 = _parse(
        {
            "enabled": "yes",
            "storage_backend": "s3",
            "s3_bucket": "legacy-s3-bucket",
            "s3_prefix": "results",
            "s3_region": "eu-west-1",
            "s3_endpoint_url": "https://minio.internal:9000",
        }
    )
    store_s3, is_remote_s3 = get_artifact_store(cfg_s3)
    assert is_remote_s3 is True
    assert isinstance(store_s3, S3Store)
    assert store_s3.bucket == "legacy-s3-bucket"
    assert store_s3.region == "eu-west-1"
    assert store_s3.endpoint_url == "https://minio.internal:9000"

    # 4. ObjectStorage / CentralStore upload + dist.py CAPE_MAIN_TASK_ID + CAPE_TASK_* env stamping
    analysis_dir = tmp_path / "storage" / "analyses" / "7"
    analysis_dir.mkdir(parents=True)
    (analysis_dir / "dump.pcap").write_bytes(b"pcap-bytes")
    remote_root = tmp_path / "remote_store"
    remote_root.mkdir()

    monkeypatch.setattr(
        "lib.tenancy.storage.config.object_storage_config",
        lambda: ObjectStorageConfig(enabled=True, backend="local", local_root=str(remote_root), prefix="results"),
    )
    monkeypatch.setattr(
        "lib.tenancy.storage.reporting.object_storage_config",
        lambda: ObjectStorageConfig(enabled=True, backend="local", local_root=str(remote_root), prefix="results"),
    )
    monkeypatch.setattr(
        "lib.tenancy.policy.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )
    monkeypatch.setattr(
        "lib.tenancy.hooks.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )
    monkeypatch.setenv("CAPE_MAIN_TASK_ID", "42")
    monkeypatch.setenv("CAPE_TASK_TENANT_ID", "10")
    monkeypatch.setenv("CAPE_TASK_USER_ID", "5")
    monkeypatch.setenv("CAPE_TASK_VISIBILITY", "tenant")
    monkeypatch.setenv("CAPE_TASK_VISIBILITY_SEQ", "3")

    results = {"info": {"id": 7}}
    reporter = ObjectStorage()
    reporter.set_path(str(analysis_dir))
    reporter.run(results)

    assert results["info"]["job_id"] == "ui-42"
    assert results["info"]["id"] == 42
    assert (remote_root / "results" / "ui-42" / "dump.pcap").read_bytes() == b"pcap-bytes"
    done_meta = json.loads((remote_root / "results" / "ui-42" / ".centralstore.done").read_text())
    assert done_meta["job_id"] == "ui-42"

    default_report_stamp_hook(results)
    assert results["info"]["tenant_id"] == 10
    assert results["info"]["user_id"] == 5
    assert results["info"]["visibility"] == "tenant"
    assert results["info"]["visibility_seq"] == 3


def test_batched_mongo_backfill():
    from lib.tenancy.backfill import backfill_from_task_acl_batched, backfill_legacy_uniform

    calls = []

    def fake_update_many(collection, query, update):
        calls.append((collection, query, update))
        return 100

    res = backfill_legacy_uniform(fake_update_many, default_visibility=PUBLIC)
    assert res == 100
    assert len(calls) == 1
    assert calls[0][2]["$set"]["info.visibility"] == PUBLIC

    engine = create_engine("sqlite:///:memory:")
    ensure_acl_schema(engine)
    bulk_batches = []

    def fake_bulk_updater(ops):
        bulk_batches.append(ops)
        return len(ops)

    with Session(engine) as session:
        set_task_acl(session, 1, user_id=10, tenant_id=2, visibility=TENANT)
        set_task_acl(session, 2, user_id=11, tenant_id=2, visibility=PRIVATE)
        session.commit()

        count = backfill_from_task_acl_batched(
            session,
            [1, 2, 3],
            fake_bulk_updater,
            chunk_size=2,
            fallback_visibility=PUBLIC,
        )
        assert count == 3
        assert len(bulk_batches) == 2
        assert bulk_batches[0][0][1]["$set"]["info.visibility"] == TENANT
        assert bulk_batches[0][1][1]["$set"]["info.visibility"] == PRIVATE
        assert bulk_batches[1][0][1]["$set"]["info.visibility"] == PUBLIC


def test_tasks_set_visibility_endpoint(monkeypatch):
    from lib.tenancy.views import tasks_set_visibility

    engine = create_engine("sqlite:///:memory:")
    ensure_acl_schema(engine)
    with Session(engine) as s:
        set_task_acl(s, 42, user_id=10, tenant_id=2, visibility=PRIVATE)
        s.commit()

    def scope_loader(tid: int):
        sess = Session(engine)
        return sess, resolve_task_scope(sess, tid, fallback_user_id=10)

    mongo_calls = []

    def fake_mongo_update(col, flt, upd):
        mongo_calls.append((col, flt, upd))

    class FakeReq:
        def __init__(self, viewer, visibility, method="POST"):
            self.viewer = viewer
            self.data = {"visibility": visibility}
            self.method = method

    def _status(resp):
        return resp.status_code if hasattr(resp, "status_code") else resp["status_code"]

    def _body(resp):
        return json.loads(resp.content.decode("utf-8")) if hasattr(resp, "content") else resp

    monkeypatch.setattr(
        "lib.tenancy.views.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=False, mode="shared", default_visibility="", local_admins_manage_all_tenants=True
        ),
    )
    owner = ViewerContext(user_id=10, tenant_id=2)
    res_off = tasks_set_visibility(
        FakeReq(owner, TENANT), 42, scope_loader=scope_loader, mongo_update_one=fake_mongo_update
    )
    assert _status(res_off) == 400

    monkeypatch.setattr(
        "lib.tenancy.views.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="shared", default_visibility="", local_admins_manage_all_tenants=True
        ),
    )
    stranger = ViewerContext(user_id=99, tenant_id=3)
    res_404 = tasks_set_visibility(
        FakeReq(stranger, PUBLIC), 42, scope_loader=scope_loader, mongo_update_one=fake_mongo_update
    )
    assert _status(res_404) == 404

    res_ok = tasks_set_visibility(
        FakeReq(owner, TENANT), 42, scope_loader=scope_loader, mongo_update_one=fake_mongo_update
    )
    assert _status(res_ok) == 200
    assert _body(res_ok)["data"] == {"task_id": 42, "visibility": TENANT}
    assert len(mongo_calls) == 1

    peer = ViewerContext(user_id=11, tenant_id=2, is_tenant_admin=False)
    res_403 = tasks_set_visibility(
        FakeReq(peer, PUBLIC), 42, scope_loader=scope_loader, mongo_update_one=fake_mongo_update
    )
    assert _status(res_403) == 403


def test_dispatch_central_view_when_enabled(monkeypatch):
    from lib.tenancy.views import dispatch_central_view

    class DummyCfg:
        enabled = True

    monkeypatch.setattr("lib.tenancy.storage.config.central_mode_config", lambda: DummyCfg())
    monkeypatch.setattr(
        "lib.tenancy.storage.views.central_pcapstream",
        lambda req: {"central_dispatched": "pcapstream"},
    )

    def pcapstream(request, task_id, proto):
        return {"upstream": True}

    out = dispatch_central_view(object(), pcapstream, (), {"task_id": 1, "proto": "tcp"})
    assert out == {"central_dispatched": "pcapstream"}


def test_disabled_auth_enabled_enforces_ownership(monkeypatch):
    from lib.tenancy.middleware import default_viewer_resolver

    monkeypatch.setattr(
        "lib.tenancy.middleware.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=False, mode="shared", default_visibility="", local_admins_manage_all_tenants=True
        ),
    )
    monkeypatch.setattr(
        "lib.tenancy.policy.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=False, mode="shared", default_visibility="", local_admins_manage_all_tenants=True
        ),
    )
    monkeypatch.setattr("lib.tenancy.middleware._web_authentication_enabled", lambda: True)

    class DummyUser:
        def __init__(self, uid, *, is_staff=False, is_superuser=False):
            self.id = uid
            self.is_staff = is_staff
            self.is_superuser = is_superuser
            self.is_authenticated = True

    owner_v = default_viewer_resolver(DummyUser(10))
    nonowner_v = default_viewer_resolver(DummyUser(20))
    staff_v = default_viewer_resolver(DummyUser(30, is_staff=True))

    engine = create_engine("sqlite:///:memory:")
    ensure_acl_schema(engine)
    with Session(engine) as session:
        set_task_acl(session, 100, user_id=10, tenant_id=None, visibility=PRIVATE)
        set_task_acl(session, 200, user_id=None, tenant_id=None, visibility=PRIVATE)
        session.commit()

        owned_scope = resolve_task_scope(session, 100, fallback_user_id=10)
        legacy_scope = resolve_task_scope(session, 200, fallback_user_id=None)

    assert can_read(owner_v, owned_scope) is True
    assert can_toggle(owner_v, owned_scope) is True
    assert can_delete(owner_v, owned_scope) is True

    assert can_read(staff_v, owned_scope) is True
    assert can_toggle(staff_v, owned_scope) is True
    assert can_delete(staff_v, owned_scope) is True

    assert can_read(nonowner_v, owned_scope) is False
    assert can_toggle(nonowner_v, owned_scope) is False
    assert can_delete(nonowner_v, owned_scope) is False

    assert can_read(nonowner_v, legacy_scope) is True


def test_group_sandbox_policy_multi_group_union_and_glob_matching():
    from lib.tenancy.resources import merge_group_policies

    tier1_policy = types.SimpleNamespace(
        id=1,
        priority=10,
        active=True,
        allowed_machines=["win10_tier1_*", "win11_base"],
        allowed_tags=["win10", "x64", "office*"],
        allowed_routes=["none", "inetsim"],
        default_route="inetsim",
        forced_machine_tags=["pool_tier1"],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=180,
    )

    eu_routing_addon = types.SimpleNamespace(
        id=2,
        priority=20,
        active=True,
        allowed_machines=[],
        allowed_tags=["eu_region"],
        allowed_routes=["vpn:vpn_uk", "socks5:socks_*", "exit:exit_de"],
        default_route="vpn_uk",
        forced_machine_tags=[],
        allow_all_vms=False,
        allow_interactive=True,
        max_timeout=0,
    )

    ent = merge_group_policies([tier1_policy, eu_routing_addon])
    assert ent.unrestricted is False
    assert ent.can_use_machine("win10_tier1_01") is True
    assert ent.can_use_machine("win11_base") is True
    assert ent.can_use_machine("win10_tier2_01") is False
    assert ent.can_use_machine("all") is False
    assert ent.can_use_machine("") is True
    assert ent.forced_machine_tags == frozenset({"pool_tier1"})

    assert ent.can_use_tag("win10") is True
    assert ent.can_use_tag("office2021") is True
    assert ent.can_use_tag("eu_region") is True
    assert ent.can_use_tag("pool_tier1") is True
    assert ent.can_use_tag("kernel_debug") is False

    assert ent.can_use_route("none") is True
    assert ent.can_use_route("inetsim") is True
    assert ent.can_use_route("vpn_uk") is True
    assert ent.can_use_route("vpn:vpn_uk") is True
    assert ent.can_use_route("vpn_us", route_type="vpn") is False
    assert ent.can_use_route("socks_nl", route_type="socks5") is True
    assert ent.can_use_route("exit_de", route_type="exit") is True
    assert ent.can_use_route("internet") is False
    assert ent.can_use_route("tor") is False

    assert ent.default_route == "vpn_uk"
    assert ent.allow_interactive is True
    assert ent.max_timeout == 180


def test_filter_submission_form_context_and_web_utils_wrappers():
    from lib.tenancy.context import entitlements_scope_context
    from lib.tenancy.hooks import wrap_submission_and_web_utils
    from lib.tenancy.resources import filter_submission_form_context, merge_group_policies

    pol = types.SimpleNamespace(
        id=1,
        priority=10,
        active=True,
        allowed_machines=["win10_tier1_*"],
        allowed_tags=["win10", "x64"],
        allowed_routes=["inetsim", "vpn:vpn_uk", "socks5:socks_uk", "gw:gw_uk", "exit:exit_uk"],
        default_route="inetsim",
        forced_machine_tags=["pool_tier1"],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=120,
    )
    ent = merge_group_policies([pol])

    ctx = {
        "machines": [
            ("win10_tier1_a", "win10_tier1_a"),
            ("win10_tier2_b", "win10_tier2_b (x64, gpu)"),
        ],
        "tags": ["gpu", "win10", "x64", "secret_tag"],
        "vpns": [{"name": "vpn_uk", "description": "UK VPN"}, {"name": "vpn_us", "description": "US VPN"}],
        "socks5s": {"socks_uk": {"name": "socks_uk"}, "socks_us": {"name": "socks_us"}},
        "gateways": {"gw_uk": "10.0.0.1", "gw_us": "10.0.0.2"},
        "all_exitnodes": ["exit_uk", "exit_us"],
        "nexthop_enabled": True,
        "internet": True,
        "inetsim": True,
        "tor": True,
        "random_route": {"name": "random"},
        "route": "internet",
        "config": {"interactive_desktop": True, "timeout": 300},
    }

    filter_submission_form_context(ctx, ent)

    assert ctx["machines"] == [("win10_tier1_a", "win10_tier1_a")]
    assert ctx["tags"] == ["win10", "x64"]
    assert [v["name"] for v in ctx["vpns"]] == ["vpn_uk"]
    assert list(ctx["socks5s"].keys()) == ["socks_uk"]
    assert list(ctx["gateways"].keys()) == ["gw_uk"]
    assert ctx["all_exitnodes"] == ["exit_uk"]
    assert ctx["internet"] is False
    assert ctx["inetsim"] is True
    assert ctx["tor"] is False
    assert ctx["random_route"] is False
    assert ctx["route"] == "inetsim"
    assert ctx["allow_all_vms"] is False
    assert ctx["allow_route_none"] is False
    assert ctx["config"]["interactive_desktop"] is False
    assert ctx["config"]["timeout"] == 120

    class FakeMachinesMixIn:
        def list_machines(self, **kwargs):
            return [
                types.SimpleNamespace(name="win10_tier1_a", label="win10_tier1_a"),
                types.SimpleNamespace(name="win10_tier2_b", label="win10_tier2_b"),
            ]

    fake_web_utils = types.ModuleType("fake_web_utils")
    fake_web_utils._all_vms_tags = []
    fake_web_utils._all_nodes_exits = []

    def load_vms_tags():
        if not fake_web_utils._all_vms_tags:
            fake_web_utils._all_vms_tags.extend(["gpu", "win10", "x64", "secret_tag"])
        return list(fake_web_utils._all_vms_tags)

    def load_vms_exits():
        if not fake_web_utils._all_nodes_exits:
            fake_web_utils._all_nodes_exits.extend(["exit_uk", "exit_us"])
        return list(fake_web_utils._all_nodes_exits)

    fake_web_utils.load_vms_tags = load_vms_tags
    fake_web_utils.load_vms_exits = load_vms_exits

    wrap_submission_and_web_utils(machines_cls=FakeMachinesMixIn, web_utils_mod=fake_web_utils)
    db_inst = FakeMachinesMixIn()

    with entitlements_scope_context(ent):
        assert [m.name for m in db_inst.list_machines()] == ["win10_tier1_a"]
        assert fake_web_utils.load_vms_tags() == ["win10", "x64"]
        assert fake_web_utils.load_vms_exits() == ["exit_uk"]

    assert [m.name for m in db_inst.list_machines()] == ["win10_tier1_a", "win10_tier2_b"]
    assert fake_web_utils.load_vms_tags() == ["gpu", "secret_tag", "win10", "x64"]
    assert fake_web_utils.load_vms_exits() == ["exit_uk", "exit_us"]


def test_validate_and_normalize_submission_and_middleware_enforcement():
    from lib.tenancy.resources import merge_group_policies, validate_and_normalize_submission

    pol = types.SimpleNamespace(
        id=1,
        priority=10,
        active=True,
        allowed_machines=["win10_tier1_*"],
        allowed_tags=["win10", "x64"],
        allowed_routes=["inetsim", "vpn:vpn_uk"],
        default_route="inetsim",
        forced_machine_tags=["pool_tier1"],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=120,
    )
    ent = merge_group_policies([pol])

    ok, err, _ = validate_and_normalize_submission({"machine": "win10_secret_vm"}, ent)
    assert ok is False
    assert "win10_secret_vm" in err
    assert "Available:" not in err

    ok, err, _ = validate_and_normalize_submission({"machine": "all"}, ent)
    assert ok is False
    assert "all VMs" in err

    ok, err, _ = validate_and_normalize_submission({"machine": "win10_tier1_01", "route": "tor"}, ent)
    assert ok is False
    assert "Route 'tor'" in err

    ok, err, _ = validate_and_normalize_submission({"machine": "win10_tier1_01", "tags": "win10,gpu_secret"}, ent)
    assert ok is False
    assert "gpu_secret" in err
    assert "Supported tags" not in err

    ok, err, _ = validate_and_normalize_submission({"machine": "win10_tier1_01", "interactive": "1"}, ent)
    assert ok is False
    assert "Interactive" in err
    ok, err, _ = validate_and_normalize_submission(
        {"machine": "win10_tier1_01", "options": "procmemdump=1,interactive=1"}, ent
    )
    assert ok is False
    assert "Interactive" in err

    ok, err, norm = validate_and_normalize_submission({"machine": "", "tags": "win10", "timeout": "900"}, ent)
    assert ok is True
    assert err is None
    assert norm["route"] == "inetsim"
    assert norm["tags"] == "win10,pool_tier1"
    assert norm["timeout"] == "120"

    viewer = ViewerContext(user_id=15, tenant_id=1, is_tenant_admin=False, is_local_admin=False, is_authenticated=True)
    mw = TenancyMiddleware(
        lambda req: {"status_code": 200},
        viewer_resolver=lambda u: viewer,
        entitlements_resolver=lambda u: ent,
        deny_response_factory=lambda req, msg: {"status_code": 404, "error_value": msg},
        forbidden_response_factory=lambda req, msg: {"status_code": 403, "error_value": msg},
    )

    def machines_view(request, name):
        return {"status_code": 200}

    def tasks_create_file(request):
        return {"status_code": 200}

    req_vm_denied = types.SimpleNamespace(path="/apiv2/machines/view/win10_tier2_01/", method="GET", user=object())
    assert mw.process_view(req_vm_denied, machines_view, (), {"name": "win10_tier2_01"}) == {
        "status_code": 404,
        "error_value": "Machine not found",
    }

    req_vm_ok = types.SimpleNamespace(path="/apiv2/machines/view/win10_tier1_01/", method="GET", user=object())
    assert mw.process_view(req_vm_ok, machines_view, (), {"name": "win10_tier1_01"}) is None

    req_sub_denied = types.SimpleNamespace(
        path="/apiv2/tasks/create/file/",
        method="POST",
        user=object(),
        data={"machine": "win10_tier2_01", "route": "internet"},
    )
    res_403 = mw.process_view(req_sub_denied, tasks_create_file, (), {})
    assert res_403["status_code"] == 403

    req_sub_ok = types.SimpleNamespace(
        path="/apiv2/tasks/create/file/",
        method="POST",
        user=object(),
        data={"machine": "", "tags": "x64", "timeout": "600"},
    )
    assert mw.process_view(req_sub_ok, tasks_create_file, (), {}) is None
    assert req_sub_ok.data["route"] == "inetsim"
    assert req_sub_ok.data["tags"] == "x64,pool_tier1"
    assert req_sub_ok.data["timeout"] == "120"


def test_idp_multi_group_reconciliation_and_group_tenant_resolution(monkeypatch):
    from lib.tenancy.middleware import default_viewer_resolver
    from lib.tenancy.models import reconcile_idp_groups_to_django_groups
    from lib.tenancy.resources import resolve_user_entitlements

    monkeypatch.setattr(
        "lib.tenancy.middleware.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )

    grp_tier1 = types.SimpleNamespace(name="tier1-analysts")
    grp_eu = types.SimpleNamespace(name="eu-routing")
    grp_stale = types.SimpleNamespace(name="us-routing")
    grp_manual = types.SimpleNamespace(name="manual-special")

    pol_tier1 = types.SimpleNamespace(
        id=1,
        group=grp_tier1,
        tenant_id=7,
        is_tenant_admin_group=True,
        priority=10,
        active=True,
        idp_groups=["okta-soc-tier1"],
        allowed_machines=["win10_tier1_*"],
        allowed_tags=["win10"],
        allowed_routes=["inetsim"],
        default_route="inetsim",
        forced_machine_tags=["pool_tier1"],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=180,
    )
    pol_eu = types.SimpleNamespace(
        id=2,
        group=grp_eu,
        tenant_id=7,
        is_tenant_admin_group=False,
        priority=20,
        active=True,
        idp_groups=["okta-vpn-eu"],
        allowed_machines=[],
        allowed_tags=[],
        allowed_routes=["vpn:vpn_eu"],
        default_route="vpn_eu",
        forced_machine_tags=[],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=0,
    )
    pol_stale = types.SimpleNamespace(
        id=3,
        group=grp_stale,
        tenant_id=7,
        is_tenant_admin_group=False,
        priority=5,
        active=True,
        idp_groups=["okta-vpn-us"],
        allowed_machines=[],
        allowed_tags=[],
        allowed_routes=["vpn:vpn_us"],
        default_route="",
        forced_machine_tags=[],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=0,
    )
    pol_manual = types.SimpleNamespace(
        id=4,
        group=grp_manual,
        tenant_id=None,
        is_tenant_admin_group=False,
        priority=1,
        active=True,
        idp_groups=[],
        allowed_machines=["win11_manual"],
        allowed_tags=[],
        allowed_routes=[],
        default_route="",
        forced_machine_tags=[],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=0,
    )

    grp_tier1.sandbox_policy = pol_tier1
    grp_eu.sandbox_policy = pol_eu
    grp_stale.sandbox_policy = pol_stale
    grp_manual.sandbox_policy = pol_manual

    class FakeGroupManager:
        def __init__(self, initial):
            self._items = list(initial)

        def add(self, *grps):
            for g in grps:
                if g not in self._items:
                    self._items.append(g)

        def remove(self, *grps):
            for g in grps:
                if g in self._items:
                    self._items.remove(g)

        def all(self):
            return list(self._items)

    user = types.SimpleNamespace(
        id=42,
        is_authenticated=True,
        is_superuser=False,
        is_staff=False,
        groups=FakeGroupManager([grp_stale, grp_manual]),
    )

    matched = reconcile_idp_groups_to_django_groups(
        user,
        ["okta-soc-tier1", "okta-vpn-eu"],
        policies=[pol_tier1, pol_eu, pol_stale, pol_manual],
    )
    assert matched == [grp_tier1, grp_eu]
    assert user.groups.all() == [grp_manual, grp_tier1, grp_eu]

    viewer = default_viewer_resolver(user)
    assert viewer.tenant_id == 7
    assert viewer.is_tenant_admin is True

    ent = resolve_user_entitlements(user)
    assert ent.can_use_machine("win10_tier1_01") is True
    assert ent.can_use_machine("win11_manual") is True
    assert ent.can_use_route("vpn_eu") is True
    assert ent.can_use_route("vpn_us") is False


def test_group_native_tenancy_and_multi_group_sharing_and_role_groups(monkeypatch):
    from lib.tenancy.acl import TaskAcl
    from lib.tenancy.middleware import default_viewer_resolver

    monkeypatch.setattr(
        "lib.tenancy.middleware.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )
    monkeypatch.setattr(
        "lib.tenancy.policy.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )

    grp_alpha = types.SimpleNamespace(id=10, name="team-alpha")
    grp_alpha.sandbox_policy = types.SimpleNamespace(
        id=1,
        group_id=10,
        tenant_id=None,
        is_tenant_boundary=True,
        is_tenant_admin_group=True,
        priority=10,
        active=True,
    )

    grp_beta = types.SimpleNamespace(id=20, name="team-beta")
    grp_beta.sandbox_policy = types.SimpleNamespace(
        id=2,
        group_id=20,
        tenant_id=None,
        is_tenant_boundary=True,
        is_tenant_admin_group=False,
        priority=25,
        active=True,
    )

    grp_role_vpn = types.SimpleNamespace(id=99, name="role-vpn-access")
    grp_role_vpn.sandbox_policy = types.SimpleNamespace(
        id=3,
        group_id=99,
        tenant_id=None,
        is_tenant_boundary=False,
        is_tenant_admin_group=False,
        priority=100,
        active=True,
    )

    user = types.SimpleNamespace(
        id=77,
        is_authenticated=True,
        is_superuser=False,
        is_staff=False,
        groups=[grp_alpha, grp_beta, grp_role_vpn],
    )

    viewer = default_viewer_resolver(user)
    assert viewer.tenant_id == 20
    assert viewer.tenant_ids == (20, 10)
    assert viewer.admin_tenant_ids == (10,)
    assert viewer.is_tenant_admin is False

    job_alpha = Job(owner_id=500, tenant_id=10, visibility="tenant")
    job_beta = Job(owner_id=600, tenant_id=20, visibility="tenant")
    job_gamma = Job(owner_id=700, tenant_id=30, visibility="tenant")
    job_role_silo = Job(owner_id=800, tenant_id=99, visibility="tenant")

    assert can_read(viewer, job_alpha) is True
    assert can_read(viewer, job_beta) is True
    assert can_read(viewer, job_gamma) is False
    assert can_read(viewer, job_role_silo) is False

    assert can_toggle(viewer, job_alpha) is True
    assert can_delete(viewer, job_alpha) is True
    assert can_toggle(viewer, job_beta) is False
    assert can_delete(viewer, job_beta) is False

    assert scope_match("tenant", viewer) == {
        "$or": [
            {"info.tenant_id": 20, "info.visibility": "tenant"},
            {"info.tenant_id": 10, "info.visibility": {"$in": ["tenant", "private"]}},
        ]
    }

    es_f = viewer_scope_es_filter(viewer)
    assert {
        "bool": {"filter": [{"term": {"info.tenant_id": 20}}, {"term": {"info.visibility": "tenant"}}]}
    } in es_f["bool"]["should"]
    assert {
        "bool": {"filter": [{"term": {"info.tenant_id": 10}}, {"terms": {"info.visibility": ["tenant", "private"]}}]}
    } in es_f["bool"]["should"]

    clause = default_sql_task_acl_clause(TaskAcl.task_id, Column("user_id", Integer), viewer=viewer)
    compiled = str(clause.compile(compile_kwargs={"literal_binds": True}))
    assert "task_acl.tenant_id = 20" in compiled
    assert "task_acl.tenant_id = 10 AND task_acl.visibility IN ('tenant', 'private')" in compiled


def test_parent_group_hierarchy_one_way_task_visibility_and_resource_inheritance(monkeypatch):
    from lib.tenancy.middleware import default_viewer_resolver
    from lib.tenancy.resources import resolve_user_entitlements

    monkeypatch.setattr(
        "lib.tenancy.middleware.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )

    grp_company = types.SimpleNamespace(id=100, name="company-main")
    grp_company.sandbox_policy = types.SimpleNamespace(
        id=1,
        group_id=100,
        parent_group=None,
        inherit_parent_resources=True,
        inherit_parent_tasks=True,
        tenant_id=None,
        is_tenant_boundary=True,
        is_tenant_admin_group=False,
        priority=10,
        active=True,
        allowed_machines=["win10_company_*"],
        allowed_tags=["win10", "x64"],
        allowed_routes=["none", "inetsim"],
        default_route="inetsim",
        forced_machine_tags=["pool_company"],
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=120,
    )

    grp_team_a = types.SimpleNamespace(id=200, name="team-alpha")
    grp_team_a.sandbox_policy = types.SimpleNamespace(
        id=2,
        group_id=200,
        parent_group=grp_company,
        inherit_parent_resources=True,
        inherit_parent_tasks=True,
        tenant_id=None,
        is_tenant_boundary=True,
        is_tenant_admin_group=True,
        priority=20,
        active=True,
        allowed_machines=["win11_redteam_*"],
        allowed_tags=["redteam"],
        allowed_routes=["vpn:vpn_redteam"],
        default_route="vpn_redteam",
        forced_machine_tags=["pool_redteam"],
        allow_all_vms=False,
        allow_interactive=True,
        max_timeout=300,
    )

    user_in_team_a = types.SimpleNamespace(
        id=1,
        is_authenticated=True,
        is_superuser=False,
        is_staff=False,
        groups=[grp_team_a],
    )
    user_in_company_b = types.SimpleNamespace(
        id=2,
        is_authenticated=True,
        is_superuser=False,
        is_staff=False,
        groups=[grp_company],
    )

    viewer_a = default_viewer_resolver(user_in_team_a)
    viewer_b = default_viewer_resolver(user_in_company_b)

    assert viewer_a.tenant_id == 200
    assert viewer_a.tenant_ids == (200, 100)
    assert viewer_a.admin_tenant_ids == (200,)
    assert viewer_b.tenant_id == 100
    assert viewer_b.tenant_ids == (100,)

    job_from_company_b = Job(owner_id=900, tenant_id=100, visibility="tenant")
    job_from_team_a = Job(owner_id=901, tenant_id=200, visibility="tenant")

    assert can_read(viewer_a, job_from_company_b) is True
    assert can_read(viewer_a, job_from_team_a) is True
    assert can_read(viewer_b, job_from_company_b) is True
    assert can_read(viewer_b, job_from_team_a) is False

    assert can_delete(viewer_a, job_from_team_a) is True
    assert can_toggle(viewer_a, job_from_company_b) is False
    assert can_delete(viewer_a, job_from_company_b) is False

    ent_a = resolve_user_entitlements(user_in_team_a)
    assert ent_a.can_use_machine("win10_company_01") is True
    assert ent_a.can_use_machine("win11_redteam_01") is True
    assert ent_a.can_use_route("inetsim") is True
    assert ent_a.can_use_route("vpn_redteam") is True
    assert ent_a.default_route == "vpn_redteam"
    assert ent_a.forced_machine_tags == frozenset({"pool_redteam"})

    ent_b = resolve_user_entitlements(user_in_company_b)
    assert ent_b.can_use_machine("win10_company_01") is True
    assert ent_b.can_use_machine("win11_redteam_01") is False
    assert ent_b.can_use_route("inetsim") is True
    assert ent_b.can_use_route("vpn_redteam") is False


def test_private_task_submission_and_strict_owner_isolation(monkeypatch):
    from lib.tenancy.acl import get_task_acl
    from lib.tenancy.hooks import wrap_submission_and_web_utils
    from lib.tenancy.middleware import default_viewer_resolver
    from lib.tenancy.resources import resolve_user_entitlements

    monkeypatch.setattr(
        "lib.tenancy.middleware.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )
    monkeypatch.setattr(
        "lib.tenancy.hooks.multitenancy_config",
        lambda: cape_tenancy.MultitenancyConfig(
            enabled=True, mode="locked", default_visibility="tenant", local_admins_manage_all_tenants=True
        ),
    )

    engine = create_engine("sqlite:///:memory:", future=True)
    SessionLocal = sessionmaker(bind=engine, future=True)
    session = SessionLocal()

    class DummyTasking:
        def __init__(self, sess):
            self.session = sess

        def add(self, obj, user_id=0, **kwargs):
            return 555

    wrap_submission_and_web_utils(tasking_cls=DummyTasking)
    tasking = DummyTasking(session)

    grp_team_a = types.SimpleNamespace(id=200, name="team-alpha")
    grp_team_a.sandbox_policy = types.SimpleNamespace(
        id=2,
        group_id=200,
        parent_group=None,
        inherit_parent_resources=True,
        inherit_parent_tasks=True,
        tenant_id=None,
        is_tenant_boundary=True,
        is_tenant_admin_group=False,
        priority=20,
        active=True,
        allowed_machines=["win10_alpha_*"],
        allowed_tags=["win10"],
        allowed_routes=["inetsim"],
        default_route="inetsim",
        default_visibility="tenant",
        forced_machine_tags=[],
        allow_all_vms=False,
        allow_interactive=True,
        max_timeout=180,
    )

    alice = types.SimpleNamespace(id=10, is_authenticated=True, is_superuser=False, is_staff=False, groups=[grp_team_a])
    bob_teammate = types.SimpleNamespace(
        id=11, is_authenticated=True, is_superuser=False, is_staff=False, groups=[grp_team_a]
    )
    carol_group_admin = types.SimpleNamespace(
        id=12,
        is_authenticated=True,
        is_superuser=False,
        is_staff=False,
        groups=[
            types.SimpleNamespace(
                id=200,
                name="team-alpha",
                sandbox_policy=types.SimpleNamespace(
                    id=3,
                    group_id=200,
                    parent_group=None,
                    tenant_id=None,
                    is_tenant_boundary=True,
                    is_tenant_admin_group=True,
                    priority=20,
                    active=True,
                ),
            )
        ],
    )

    def tasks_create_file(req):
        tid = tasking.add("sample.exe", user_id=req.user.id)
        return {"status_code": 200, "task_id": tid}

    mw = TenancyMiddleware(
        lambda req: tasks_create_file(req),
        viewer_resolver=default_viewer_resolver,
        entitlements_resolver=resolve_user_entitlements,
    )

    req_private = types.SimpleNamespace(
        path="/apiv2/tasks/create/file/",
        method="POST",
        user=alice,
        data={"machine": "win10_alpha_01", "route": "inetsim", "visibility": "private"},
    )
    assert mw.process_view(req_private, tasks_create_file, (), {}) is None
    resp = mw(req_private)
    assert resp["task_id"] == 555

    acl_row = get_task_acl(session, 555)
    assert acl_row is not None
    assert acl_row.user_id == 10
    assert acl_row.tenant_id == 200
    assert acl_row.visibility == "private"

    scope = acl_row.to_scope()
    v_alice = default_viewer_resolver(alice)
    v_bob = default_viewer_resolver(bob_teammate)
    v_carol_admin = default_viewer_resolver(carol_group_admin)

    assert can_read(v_alice, scope) is True
    assert can_toggle(v_alice, scope) is True
    assert can_delete(v_alice, scope) is True

    assert can_read(v_bob, scope) is False
    assert can_toggle(v_bob, scope) is False
    assert can_delete(v_bob, scope) is False

    assert can_read(v_carol_admin, scope) is True
    assert can_toggle(v_carol_admin, scope) is True
    assert can_delete(v_carol_admin, scope) is True

    other_group_admin = ViewerContext(
        user_id=99,
        tenant_id=300,
        is_tenant_admin=True,
        tenant_ids=(300,),
        admin_tenant_ids=(300,),
    )
    assert can_read(other_group_admin, scope) is False
    assert can_toggle(other_group_admin, scope) is False
    assert can_delete(other_group_admin, scope) is False


def test_django_models_and_admin_when_configured():
    pytest.importorskip("django")
    import subprocess
    import sys

    script = """
import types
import django
from django.conf import settings
settings.configure(
    INSTALLED_APPS=[
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "lib.tenancy.apps.CapeTenancyConfig",
    ],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
)
django.setup()
from django.core.management import call_command
call_command("migrate", verbosity=0)

from django.contrib.auth.models import Group, User
from django.contrib.admin.sites import AdminSite
from lib.tenancy.models import GroupSandboxPolicy, Tenant
from lib.tenancy.admin import GroupSandboxPolicyAdmin
from lib.tenancy.resources import resolve_user_entitlements

tenant = Tenant.objects.create(slug="acme", name="ACME Corp")
grp1 = Group.objects.create(name="tier1-analysts")
grp2 = Group.objects.create(name="vpn-uk-users")
GroupSandboxPolicy.objects.create(
    group=grp1,
    tenant=tenant,
    priority=10,
    allowed_machines=["win10_tier1_*"],
    allowed_tags=["win10", "x64"],
    allowed_routes=["inetsim"],
    default_route="inetsim",
    forced_machine_tags=["pool_tier1"],
    allow_all_vms=False,
    allow_interactive=False,
    max_timeout=180,
)
GroupSandboxPolicy.objects.create(
    group=grp2,
    tenant=tenant,
    priority=20,
    allowed_machines=[],
    allowed_tags=["uk_tag"],
    allowed_routes=["vpn:vpn_uk"],
    default_route="vpn_uk",
)

user = User.objects.create_user(username="alice")
user.groups.add(grp1, grp2)

ent = resolve_user_entitlements(user)
assert ent.can_use_machine("win10_tier1_01") is True
assert ent.can_use_machine("win10_tier2_01") is False
assert ent.can_use_route("inetsim") is True
assert ent.can_use_route("vpn_uk") is True
assert ent.can_use_route("tor") is False
assert ent.can_use_tag("uk_tag") is True
assert ent.default_route == "vpn_uk"
assert ent.forced_machine_tags == frozenset({"pool_tier1"})
assert ent.max_timeout == 180

pol_admin = GroupSandboxPolicyAdmin(GroupSandboxPolicy, AdminSite())
staff_req = types.SimpleNamespace(user=types.SimpleNamespace(is_superuser=False))
super_req = types.SimpleNamespace(user=types.SimpleNamespace(is_superuser=True))
assert "allowed_machines" in pol_admin.get_readonly_fields(staff_req)
assert "allowed_machines" not in pol_admin.get_readonly_fields(super_req)

grp_direct = Group.objects.create(name="soc-team-alpha")
pol_direct = GroupSandboxPolicy.objects.create(
    group=grp_direct,
    is_tenant_boundary=True,
    allowed_machines=["win11_alpha_*"],
)
assert pol_direct.effective_tenant_id == grp_direct.id

grp_role = Group.objects.create(name="role-direct-internet")
pol_role = GroupSandboxPolicy.objects.create(
    group=grp_role,
    is_tenant_boundary=False,
    allowed_routes=["internet"],
)
assert pol_role.effective_tenant_id is None
"""
    import os
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
