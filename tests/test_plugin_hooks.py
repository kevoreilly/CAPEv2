from lib.cuckoo.common.hooks import (
    apply_es_filter,
    apply_mongo_filter,
    apply_sql_task_filter,
    clear_all_hooks,
    register_es_filter,
    register_mongo_filter,
    register_report_hook,
    register_sql_task_filter,
    run_report_hooks,
)


def teardown_function():
    clear_all_hooks()


def test_hooks_noop_by_default():
    assert apply_mongo_filter("analysis", {"info.id": 1}) == {"info.id": 1}
    assert apply_sql_task_filter("SELECT 1") == "SELECT 1"
    assert apply_es_filter({"query": {"match_all": {}}}) == {"query": {"match_all": {}}}
    report = {"info": {"id": 1}}
    run_report_hooks(report)
    assert report == {"info": {"id": 1}}


def test_registered_hooks_transform_queries_and_reports():
    register_mongo_filter(lambda coll, q: {**q, "scoped": coll})
    register_sql_task_filter(lambda q: f"{q} WHERE visible=1")
    register_es_filter(lambda body: {**body, "filtered": True})
    register_report_hook(lambda r: r.setdefault("info", {}).update({"stamped": True}))

    assert apply_mongo_filter("analysis", {"info.id": 5}) == {"info.id": 5, "scoped": "analysis"}
    assert apply_sql_task_filter("SELECT * FROM tasks") == "SELECT * FROM tasks WHERE visible=1"
    assert apply_es_filter({"query": {}}) == {"query": {}, "filtered": True}

    report = {"info": {"id": 5}}
    run_report_hooks(report)
    assert report["info"]["stamped"] is True
