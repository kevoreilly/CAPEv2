from lib.cuckoo.common.hooks import (
    apply_es_filter,
    apply_machine_filter,
    apply_mongo_filter,
    apply_route_filter,
    apply_sql_task_filter,
    apply_submission_context_filter,
    apply_tag_filter,
    clear_all_hooks,
    register_es_filter,
    register_machine_filter,
    register_mongo_filter,
    register_report_hook,
    register_route_filter,
    register_sql_task_filter,
    register_submission_context_filter,
    register_tag_filter,
    run_report_hooks,
)


def setup_function():
    # Other modules (tests/test_tenancy.py) register the real hooks at import/run time.
    clear_all_hooks()


def teardown_function():
    clear_all_hooks()


def test_hooks_noop_by_default():
    assert apply_mongo_filter("analysis", {"info.id": 1}) == {"info.id": 1}
    assert apply_sql_task_filter("SELECT 1") == "SELECT 1"
    assert apply_es_filter({"query": {"match_all": {}}}) == {"query": {"match_all": {}}}
    assert apply_machine_filter(["vm1", "vm2"]) == ["vm1", "vm2"]
    assert apply_tag_filter(["win10", "x64"]) == ["win10", "x64"]
    assert apply_route_filter(["inetsim", "tor"], "exit") == ["inetsim", "tor"]
    assert apply_submission_context_filter({"route": "none"}) == {"route": "none"}
    report = {"info": {"id": 1}}
    run_report_hooks(report)
    assert report == {"info": {"id": 1}}


def test_registered_hooks_transform_queries_and_reports():
    register_mongo_filter(lambda coll, q: {**q, "scoped": coll})
    register_sql_task_filter(lambda q: f"{q} WHERE visible=1")
    register_es_filter(lambda body: {**body, "filtered": True})
    register_report_hook(lambda r: r.setdefault("info", {}).update({"stamped": True}))
    register_machine_filter(lambda vms: [m for m in vms if m == "vm1"])
    register_tag_filter(lambda tags: [t for t in tags if t == "win10"])
    register_route_filter(lambda routes, rtype: [r for r in routes if r != "tor"])
    register_submission_context_filter(lambda ctx: {**ctx, "filtered_ctx": True})

    assert apply_mongo_filter("analysis", {"info.id": 5}) == {"info.id": 5, "scoped": "analysis"}
    assert apply_sql_task_filter("SELECT * FROM tasks") == "SELECT * FROM tasks WHERE visible=1"
    assert apply_es_filter({"query": {}}) == {"query": {}, "filtered": True}
    assert apply_machine_filter(["vm1", "vm2"]) == ["vm1"]
    assert apply_tag_filter(["win10", "x64"]) == ["win10"]
    assert apply_route_filter(["inetsim", "tor"], "vpn") == ["inetsim"]
    assert apply_submission_context_filter({"route": "inetsim"}) == {"route": "inetsim", "filtered_ctx": True}

    report = {"info": {"id": 5}}
    run_report_hooks(report)
    assert report["info"]["stamped"] is True


def test_legacy_single_arg_report_hook_runs_once_for_process_stage():
    calls = []
    register_report_hook(lambda r: calls.append("legacy_1arg"))
    for stg in ("process", "mongodb", "elasticsearchdb", "post_mongodb", "post_elasticsearchdb"):
        run_report_hooks({"info": {"id": 1}}, stage=stg)
    assert calls == ["legacy_1arg"]


def test_default_sample_exists_checker_does_not_conflict_with_sample_access_checker(db, temp_pe32, monkeypatch):
    from lib.tenancy.acl import ensure_acl_schema, set_task_acl
    from lib.tenancy.middleware import default_sample_access_checker, default_sample_exists_checker
    from lib.tenancy.policy import MultitenancyConfig, ViewerContext

    cfg = MultitenancyConfig(
        enabled=True, mode="shared", default_visibility="private", local_admins_manage_all_tenants=True
    )
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", lambda: cfg)
    ensure_acl_schema(db.engine)
    tid = db.add_path(str(temp_pe32), user_id=7)
    with db.session.begin():
        set_task_acl(db.session, tid, user_id=7, tenant_id=1, visibility="private")
    sha256 = db.view_task(tid).sample.sha256
    viewer = ViewerContext(
        user_id=7,
        tenant_id=1,
        is_superuser=False,
        is_tenant_admin=False,
        is_local_admin=False,
        is_authenticated=True,
        tenant_ids=(1,),
        admin_tenant_ids=(),
    )
    assert default_sample_exists_checker({"sha256": sha256}) is True
    assert default_sample_access_checker(viewer, {"sha256": sha256}) is True


