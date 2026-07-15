"""One-shot backfill: stamp tenant_id/user_id/visibility into existing mongo analysis
docs from their Postgres task. Run once (quiesced) when enabling multitenancy on a
populated DB. In a central deployment run it on the CENTRAL node — it only touches docs
whose id space matches the node it runs on (see _is_central_id / the id-space guard)."""
import os
import re
import sys


def _is_central_id(job_id) -> bool:
    """A doc whose broker job_id is 'ui-<N>' has had info.id rewritten to the CENTRAL
    task id (central RDS id space); anything else keeps a WORKER-LOCAL info.id. Used to
    only restamp docs whose id space matches the DB this script talks to."""
    return bool(job_id) and re.match(r"^ui-(\d+)$", str(job_id)) is not None


def _needs_backfill_filter() -> dict:
    """Mongo selector for docs to (re)stamp: un-stamped (no info.visibility, first-enable)
    OR the EXACT reporter fail-closed crash-orphan shape (private + null owner AND tenant).
    Deliberately NOT a bare {info.user_id: null} arm — that also matches every stamped
    anonymous/CLI doc (nullable owner; Mongo null matches missing too), so a rerun could
    silently downgrade a legitimately-public doc whose task was later pruned."""
    return {"$or": [
        {"info.visibility": {"$exists": False}},
        {"info.user_id": None, "info.tenant_id": None, "info.visibility": "private"},
    ]}


def backfill_doc(doc, view_task) -> dict:
    # Orphan / corrupt: the Postgres task was pruned (or the doc has a missing or
    # non-numeric info.id) — fail CLOSED to private (no owner/tenant) so it matches
    # no cross-tenant scope and stays invisible to everyone but break-glass, never
    # world-visible. A bad id must NOT abort the whole one-shot backfill run.
    _orphan = {"info.tenant_id": None, "info.user_id": None, "info.visibility": "private"}
    try:
        _rid = int(doc.get("info", {}).get("id", 0))
    except (TypeError, ValueError):
        return _orphan
    task = view_task(_rid)
    if task is None:
        return _orphan
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
    skipped = 0
    # Repair BOTH un-stamped docs (no info.visibility — first-enable) AND crash-orphaned
    # docs. Match the EXACT reporter fail-closed shape (private + null owner AND tenant),
    # NOT just user_id:null: Task.user_id is nullable (CLI/anon submits), and Mongo null
    # matches missing too, so a bare user_id:null arm would re-touch every anonymous doc
    # on each run and could silently downgrade a legitimately-public doc whose task was
    # later pruned. The narrow shape keeps the tool idempotent + off live permissive docs.
    _needs_backfill = _needs_backfill_filter()
    _central = False
    try:
        from lib.cuckoo.common.central_mode import central_mode_config

        _central = central_mode_config().enabled
    except Exception:
        _central = False
    for doc in mongo_find("analysis", _needs_backfill, {"info.id": 1, "info.job_id": 1}):
        # Id-space guard: backfill_doc resolves info.id via view_task against THIS node's
        # DB. A ui-* doc's info.id is a CENTRAL id (central RDS); a non-ui-* doc's is a
        # worker-LOCAL id. Only restamp docs whose id space matches the node running the
        # script — resolving a foreign id against the wrong DB would hit a colliding row
        # and mis-stamp another tenant's scope onto the doc.
        _jid = (doc.get("info") or {}).get("job_id")
        if _is_central_id(_jid) != _central:
            skipped += 1
            continue
        mongo_update_one("analysis", {"_id": doc["_id"]}, {"$set": backfill_doc(doc, db.view_task)})
        n += 1
    print(f"backfilled {n} docs ({skipped} skipped: info.id id-space != this node)")


if __name__ == "__main__":
    main()
