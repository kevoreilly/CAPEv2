def test_backfill_stamps_from_task():
    from utils.db_migration.mongo_backfill_tenant import backfill_doc

    class T:
        user_id, tenant_id, visibility = 5, 10, "tenant"
    doc = {"info": {"id": 1}}
    update = backfill_doc(doc, lambda tid: T())
    assert update == {"info.tenant_id": 10, "info.user_id": 5, "info.visibility": "tenant"}


def test_backfill_orphan_defaults_public():
    from utils.db_migration.mongo_backfill_tenant import backfill_doc
    doc = {"info": {"id": 9}}
    update = backfill_doc(doc, lambda tid: None)
    assert update == {"info.tenant_id": None, "info.user_id": None, "info.visibility": "public"}
