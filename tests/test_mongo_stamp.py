def test_stamp_tenant_context_into_info():
    from modules.reporting.mongodb import stamp_tenant_info

    class T:  # stand-in for a Task row
        user_id, tenant_id, visibility = 7, 10, "tenant"

    info = {"id": 42}
    stamp_tenant_info(info, T())
    assert info["tenant_id"] == 10 and info["user_id"] == 7 and info["visibility"] == "tenant"


def test_stamp_missing_task_defaults_public():
    from modules.reporting.mongodb import stamp_tenant_info
    info = {"id": 42}
    stamp_tenant_info(info, None)
    assert info["visibility"] == "public" and info["tenant_id"] is None and info["user_id"] is None

