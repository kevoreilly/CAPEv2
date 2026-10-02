"""guac resolves the live-VM job_id from the AUTHORIZED task_id, never the forgeable custom (HIGH).

The central submit-bridge assigns a deterministic job_id 'ui-<rds_task_id>'. central_guac._job_id_for_task
DERIVES that from the caller's own task_id, so a user who pre-set custom='job_id=ui-<victim>' (which the
bridge skips, leaving the forged value) cannot redirect the guac tunnel into another tenant's live VM.
"""


def test_job_id_derived_from_task_id():
    from lib.cuckoo.common.central_guac import _job_id_for_task
    assert _job_id_for_task(5) == "ui-5"
    assert _job_id_for_task("42") == "ui-42"   # str task id coerced
    assert _job_id_for_task(None) is None
    assert _job_id_for_task("abc") is None


def test_job_id_ignores_forged_custom(monkeypatch):
    """Regression guard: even if a task carries a FORGED custom pointing at another tenant's job, the
    resolver must return the caller's OWN ui-<task_id> -- not the forged value. (The impl no longer reads
    custom at all; this fails loudly if a future change re-introduces the custom-read.)"""
    import lib.cuckoo.common.central_guac as cg
    import lib.cuckoo.core.database as dbmod

    class _T:
        custom = "job_id=ui-999"  # victim's job, forged into the attacker's own task

    class _DB:
        def view_task(self, tid):
            return _T()

    monkeypatch.setattr(dbmod, "Database", lambda: _DB(), raising=False)
    assert cg._job_id_for_task(5) == "ui-5"  # caller's own task, NOT the forged ui-999
