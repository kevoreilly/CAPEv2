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
