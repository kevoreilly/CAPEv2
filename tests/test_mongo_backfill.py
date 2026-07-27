def test_backfill_stamps_from_task():
    from utils.db_migration.mongo_backfill_tenant import backfill_doc

    class T:
        user_id, tenant_id, visibility = 5, 10, "tenant"
    doc = {"info": {"id": 1}}
    update = backfill_doc(doc, lambda tid: T())
    assert update == {"info.tenant_id": 10, "info.user_id": 5, "info.visibility": "tenant"}


def test_backfill_orphan_fails_closed_private():
    """Finding #8: an orphaned doc (Postgres task pruned, mongo doc retained) must
    NOT be backfilled world-visible. Fail closed to private so it stays invisible
    to every tenant — previously defaulted 'public', flipping previously-invisible
    orphans to globally cross-tenant-readable when MT was first enabled."""
    from utils.db_migration.mongo_backfill_tenant import backfill_doc
    doc = {"info": {"id": 9}}
    update = backfill_doc(doc, lambda tid: None)
    assert update == {"info.tenant_id": None, "info.user_id": None, "info.visibility": "private"}


def test_backfill_corrupt_id_fails_closed_private():
    """Copilot: a doc with a missing or non-numeric info.id (corrupt/partial data)
    must fail CLOSED to private rather than raise and abort the whole backfill run.
    A non-numeric id must be rejected BEFORE view_task (which would raise on bind)."""
    from utils.db_migration.mongo_backfill_tenant import backfill_doc

    private = {"info.tenant_id": None, "info.user_id": None, "info.visibility": "private"}

    # non-numeric id -> int() raises -> orphan WITHOUT ever calling view_task
    def _boom(tid):
        raise AssertionError("view_task must not be called for a non-numeric id")

    assert backfill_doc({"info": {"id": "abc"}}, _boom) == private
    assert backfill_doc({"info": {"id": None}}, _boom) == private

    # missing id defaults to 0 -> view_task(0) -> None (pruned) -> orphan
    assert backfill_doc({"info": {}}, lambda t: None) == private
    assert backfill_doc({}, lambda t: None) == private


def test_is_central_id_discriminates_id_space():
    from utils.db_migration.mongo_backfill_tenant import _is_central_id
    assert _is_central_id("ui-42") is True
    assert _is_central_id("ui-999") is True
    assert _is_central_id("local-42") is False   # direct submit -> worker-local id space
    assert _is_central_id("") is False
    assert _is_central_id(None) is False
    assert _is_central_id("ui-x") is False


def test_backfill_filter_excludes_stamped_public_docs():
    """The orphan arm must match ONLY the exact fail-closed shape (private + null owner
    AND tenant), so a stamped anonymous/public doc (whose SQL task may later be pruned) is
    never selected and silently downgraded on a rerun (idempotency)."""
    from utils.db_migration.mongo_backfill_tenant import _needs_backfill_filter
    arms = _needs_backfill_filter()["$or"]
    assert {"info.visibility": {"$exists": False}} in arms                 # un-stamped
    assert {"info.user_id": None, "info.tenant_id": None, "info.visibility": "private"} in arms  # exact orphan
    assert {"info.user_id": None} not in arms                             # NOT the over-matching bare arm
