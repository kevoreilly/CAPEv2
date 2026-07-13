"""One-shot backfill: stamp tenant_id/user_id/visibility into existing mongo analysis
docs from their Postgres task. Run once when enabling multitenancy on a populated DB."""
import os
import sys


def backfill_doc(doc, view_task) -> dict:
    task = view_task(int(doc.get("info", {}).get("id", 0)))
    if task is None:
        # Orphan: the Postgres task was pruned but the mongo doc remains. Fail
        # CLOSED to private (no owner/tenant) so it matches no cross-tenant scope
        # and stays invisible to everyone but break-glass — never world-visible.
        return {"info.tenant_id": None, "info.user_id": None, "info.visibility": "private"}
    return {
        "info.tenant_id": getattr(task, "tenant_id", None),
        "info.user_id": getattr(task, "user_id", None),
        "info.visibility": getattr(task, "visibility", "private") or "private",
    }


def main():
    # Resolve the repo root from this file's location (utils/db_migration/),
    # not a hardcoded /opt/CAPEv2, so dev/custom installs work too.
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    from dev_utils.mongodb import mongo_create_index, mongo_find, mongo_update_one
    from lib.cuckoo.core.database import Database, init_database
    try:
        init_database()
    except Exception:
        pass
    db = Database()
    # Ensure the tenant-scope index exists — on an existing install the
    # reporting module only creates it at first-schema-init, so a backfilled
    # collection would otherwise scan unindexed on every scoped aggregation.
    try:
        mongo_create_index(
            "analysis",
            [("info.tenant_id", 1), ("info.visibility", 1), ("info.user_id", 1)],
            background=True,
            name="tenant_scope_idx",
        )
    except Exception as idx_err:
        print(f"warning: could not create tenant_scope_idx: {idx_err}")
    n = 0
    for doc in mongo_find("analysis", {"info.visibility": {"$exists": False}}, {"info.id": 1}):
        mongo_update_one("analysis", {"_id": doc["_id"]}, {"$set": backfill_doc(doc, db.view_task)})
        n += 1
    print(f"backfilled {n} docs")


if __name__ == "__main__":
    main()
