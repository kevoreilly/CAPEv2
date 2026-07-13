def test_stamp_tenant_context_into_info():
    from modules.reporting.mongodb import stamp_tenant_info

    class T:  # stand-in for a Task row
        user_id, tenant_id, visibility = 7, 10, "tenant"

    info = {"id": 42}
    stamp_tenant_info(info, T())
    assert info["tenant_id"] == 10 and info["user_id"] == 7 and info["visibility"] == "tenant"


def test_stamp_missing_task_fails_closed_private():
    """Finding #1: an unresolved task (deleted/orphan, transient DB error, or the
    distributed main_task_id lookup miss on a worker) must NOT be stamped
    world-visible. Fail CLOSED to private with no owner/tenant so it matches no
    cross-tenant scope (public/tenant/mine) and stays invisible to everyone but
    break-glass. Previously defaulted to 'public' (fail-open leak)."""
    from modules.reporting.mongodb import stamp_tenant_info
    info = {"id": 42}
    stamp_tenant_info(info, None)
    assert info["visibility"] == "private"
    assert info["tenant_id"] is None and info["user_id"] is None



def test_stamp_report_distributed_fails_closed():
    """run()'s distributed branch (main_task_id set) fails closed to private — the
    worker-local task does not carry the submitter's tenancy (dist.py forwards none)."""
    from modules.reporting.mongodb import _stamp_report_for_task
    info = {"id": 5}
    _stamp_report_for_task(info, main_task_id=99, local_task_id=5)
    assert info["visibility"] == "private"
    assert info["tenant_id"] is None and info["user_id"] is None


def test_stamp_report_local_path_uses_local_task(monkeypatch):
    """Non-distributed (no main_task_id): stamp from the LOCAL task's tenancy."""
    from modules.reporting import mongodb as m

    class T:
        user_id, tenant_id, visibility = 7, 10, "tenant"

    monkeypatch.setattr(m, "_task_tenant_ctx", lambda tid: T() if tid == 5 else None)
    info = {"id": 5}
    m._stamp_report_for_task(info, main_task_id=None, local_task_id=5)
    assert info["visibility"] == "tenant" and info["tenant_id"] == 10 and info["user_id"] == 7
