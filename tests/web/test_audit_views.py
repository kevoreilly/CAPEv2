"""Regression tests for web.audit.views unqueue flows and DB persistence."""

from unittest.mock import patch

import pytest


@pytest.mark.usefixtures("db")
def test_inner_unqueue_test_resets_dangling_and_pending_runs_in_db(db):
    import audit.views as audit_views
    from lib.cuckoo.core.data.audit_data import (
        AvailableTest,
        TEST_QUEUED,
        TEST_UNQUEUED,
        TestRun,
        TestSession,
    )
    from lib.cuckoo.core.data.task import TASK_PENDING, TASK_RUNNING

    pending_task_id = db.add_url("https://example.invalid/audit-pending")
    running_task_id = db.add_url("https://example.invalid/audit-running")
    db.set_status(running_task_id, TASK_RUNNING)

    with db.session.begin():
        avail = AvailableTest(
            name="audit_unqueue_test",
            package="exe",
            payload_path="/tmp/fake.exe",
            module_path="/tmp/fake_audit_mod",
            task_config={},
        )
        sess = TestSession()
        run_dangling = TestRun(session=sess, test_definition=avail, cape_task_id=999999, status=TEST_QUEUED)
        run_pending = TestRun(session=sess, test_definition=avail, cape_task_id=pending_task_id, status=TEST_QUEUED)
        run_running = TestRun(session=sess, test_definition=avail, cape_task_id=running_task_id, status=TEST_QUEUED)
        db.session.add_all([avail, sess, run_dangling, run_pending, run_running])
        db.session.flush()
        session_id = sess.id
        dangling_id = run_dangling.id
        pending_run_id = run_pending.id
        running_run_id = run_running.id

    with patch.object(audit_views, "db", db):
        # 1. Single detached run with dangling cape_task_id (matches unqueue_test flow) resets & persists to DB.
        detached_dangling = db.get_audit_session_test(session_id, dangling_id)
        assert audit_views.inner_unqueue_test(detached_dangling) == 999999
        assert detached_dangling.status == TEST_UNQUEUED
        assert detached_dangling.cape_task_id is None

        reloaded_dangling = db.get_audit_session_test(session_id, dangling_id)
        assert reloaded_dangling.status == TEST_UNQUEUED
        assert reloaded_dangling.cape_task_id is None

        # 2. Session-level unqueue loop (matches unqueue_all_tests flow) deletes pending task,
        # persists TEST_UNQUEUED, and leaves running task untouched.
        assert db.view_task(pending_task_id).status == TASK_PENDING
        session_obj = db.get_test_session(session_id)
        unqueue_results = [tid for run in session_obj.runs if (tid := audit_views.inner_unqueue_test(run))]
        assert unqueue_results == [pending_task_id]
        assert db.view_task(pending_task_id) is None
        assert db.view_task(running_task_id) is not None

        reloaded_pending = db.get_audit_session_test(session_id, pending_run_id)
        assert reloaded_pending.status == TEST_UNQUEUED
        assert reloaded_pending.cape_task_id is None

        reloaded_running = db.get_audit_session_test(session_id, running_run_id)
        assert reloaded_running.status != TEST_UNQUEUED
        assert reloaded_running.cape_task_id == running_task_id
