# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gc
import logging
from contextlib import suppress
from lib.cuckoo.common.iocs import dump_iocs
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from modules.reporting.report_doc import ensure_valid_utf8, get_json_document, insert_calls
from lib.cuckoo.common.config import Config

try:
    from pymongo.errors import InvalidDocument, OperationFailure

    from dev_utils.mongodb import mongo_collection_names, mongo_create_index, mongo_delete_data, mongo_find_one, mongo_insert_one, mongo_update_one

    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

MONGOSIZELIMIT = 0x1000000
MEGABYTE = 0x100000

log = logging.getLogger(__name__)
reporting_conf = Config("reporting")


def stamp_tenant_info(info: dict, task) -> None:
    """Write tenant_id/user_id/visibility into the report's info subdict so mongo
    aggregations can be scoped. An unresolved task (deleted/orphan, transient DB
    error, or a distributed main_task_id lookup miss) fails CLOSED to private with
    no owner/tenant, so the doc matches no cross-tenant scope (public/tenant/mine)
    and stays invisible to everyone but break-glass — never world-visible."""
    if task is None:
        info["tenant_id"] = None
        info["user_id"] = None
        info["visibility"] = "private"
        return
    info["tenant_id"] = getattr(task, "tenant_id", None)
    info["user_id"] = getattr(task, "user_id", None)
    # Fail closed on a null/blank visibility too (shouldn't happen — the column
    # has a private server_default — but never default a real task to public).
    info["visibility"] = getattr(task, "visibility", "private") or "private"


def _task_tenant_ctx(task_id):
    """Load a task's tenant context on an INDEPENDENT session (its own pooled
    connection), so this never touches the processor's shared scoped session.
    Using Database().session here left an implicit transaction open and broke
    processing with 'A transaction is already begun on this Session'. Returns a
    detached holder with tenant_id/user_id/visibility, or None if not found."""
    from sqlalchemy.orm import Session

    from lib.cuckoo.core.database import Database
    from lib.cuckoo.core.data.task import Task

    with Session(Database().engine) as s:
        t = s.get(Task, task_id)
        if t is None:
            return None
        return type("_TaskCtx", (), {
            "tenant_id": t.tenant_id, "user_id": t.user_id, "visibility": t.visibility,
        })()


_CENTRAL_ENGINE = None
_CENTRAL_ENGINE_URL = None
_CENTRAL_LOCK_WARNED = False


def _central_engine():
    """Lazily build + cache a read-only SQLAlchemy engine to the CENTRAL control-plane
    RDS ([central_mode] central_database_url). Returns None when unset (worker can't
    resolve central tenancy -> stamp fail-closed). Rebuilds if the config URL changes."""
    global _CENTRAL_ENGINE, _CENTRAL_ENGINE_URL
    from lib.cuckoo.common.central_mode import central_mode_config

    url = central_mode_config().central_database_url
    if not url:
        return None
    if _CENTRAL_ENGINE is not None and url == _CENTRAL_ENGINE_URL:
        return _CENTRAL_ENGINE
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    # NullPool (like Database.lock_engine): the reconcile holds an advisory-lock
    # connection across the read while opening a SECOND connection for that read, so a
    # bounded shared pool would deadlock/exhaust under concurrent reconciles (fail
    # closed = doc invisible). Bounded connect too: this runs in run()'s finally under
    # the lock; a black-holed central RDS would otherwise stall reporting ~2 min on TCP
    # SYN retries -> fail closed in seconds via the caller's except path instead.
    _CENTRAL_ENGINE = create_engine(url, poolclass=NullPool, connect_args={"connect_timeout": 5})
    _CENTRAL_ENGINE_URL = url
    return _CENTRAL_ENGINE


def _warn_central_lock_once(reason):
    global _CENTRAL_LOCK_WARNED
    if not _CENTRAL_LOCK_WARNED:
        _CENTRAL_LOCK_WARNED = True
        log.warning(
            "central-mode report-visibility reconcile cannot take a validated writer-primary lock (%s): "
            "central (ui-*) analyses will NOT be visibility-upgraded and stay fail-closed private until "
            "central_database_url points at the WRITER/PRIMARY endpoint.", reason,
        )


def _central_lock_engine():
    """The central engine to take the reconcile's advisory lock on — but ONLY if it is a
    validated WRITER PRIMARY. pg_advisory_lock on a hot standby acquires locally and
    excludes nothing on the primary (where set_task_visibility locks), so it would look
    serialized while the TOCTOU quietly reopens.

    Probe pg_is_in_recovery() FRESH on every call — NO cache: a transient probe failure
    must re-probe on the next reconcile (not disable serialization for the process
    lifetime), and an in-place RDS failover (same URL, endpoint now a standby) must be
    detected (not keep locking a demoted server). NullPool means the extra round-trip has
    no warm-pool cost. Returns None on unset URL / standby / probe failure — the caller
    must then NOT upgrade the doc (leave the fail-closed private stamp), and we warn once."""
    eng = _central_engine()
    if eng is None:
        _warn_central_lock_once("central_database_url is unset")
        return None
    try:
        from sqlalchemy import text

        with eng.connect() as c:
            in_recovery = bool(c.execute(text("SELECT pg_is_in_recovery()")).scalar())
    except Exception as _e:
        _warn_central_lock_once(f"writer-primary probe failed ({_e})")
        return None
    if in_recovery:
        _warn_central_lock_once("central_database_url is a read replica/standby")
        return None
    return eng


def _task_tenant_ctx_central(central_task_id, conn=None):
    """Resolve a CENTRAL task's authoritative tenancy from the central control-plane
    RDS. In central mode the worker's LOCAL task DB is a different (per-worker) id
    space and centralstore rewrote info.id to the CENTRAL id, so the stamp MUST be
    resolved here, not against Database() (the worker-local DB). Returns a detached
    holder with tenant_id/user_id/visibility, or None (fail-closed) when the central
    DB URL is unset or the task isn't found.

    When ``conn`` is given (the pinned advisory-lock connection), read on THAT
    connection so the writer-primary verdict, the lock, and this read all share one
    backend and cannot disagree under an in-place failover / multi-host URL; otherwise
    open a fresh central connection."""
    from sqlalchemy.orm import Session

    from lib.cuckoo.core.data.task import Task

    if conn is not None:
        session_ctx = Session(bind=conn)
    else:
        eng = _central_engine()
        if eng is None:
            return None
        session_ctx = Session(eng)
    with session_ctx as s:
        t = s.get(Task, int(central_task_id))
        if t is None:
            return None
        return type("_TaskCtx", (), {
            "tenant_id": t.tenant_id, "user_id": t.user_id, "visibility": t.visibility,
        })()


def _connection_in_recovery(conn) -> bool:
    """True if ``conn`` — the pinned advisory-lock connection — talks to a server in
    recovery (a hot standby), so the reconcile must NOT upgrade (a lagging standby row
    would re-widen the committed private doc). None-safe: returns False when there is no
    lock connection (non-Postgres / sqlite path), where recovery status is irrelevant. A
    probe error is treated as unsafe (returns True, fail closed) — we cannot confirm the
    lock landed on the primary, so leave the doc fail-closed private."""
    if conn is None:
        return False
    from sqlalchemy import text

    try:
        return bool(conn.execute(text("SELECT pg_is_in_recovery()")).scalar())
    except Exception as _e:
        _warn_central_lock_once(f"in-lock writer-primary re-check failed ({_e})")
        return True


def _warn_central_reconcile_skipped(task_id, reason) -> None:
    """Per-task diagnostic when the central reconcile skips the visibility upgrade (leaving
    the doc fail-closed private). The mongo-write-failure path logs the same way for the
    same 'sole corrector no-op'd' situation; operators enumerate stranded central tasks from
    these lines instead of scanning mongo for info.tenant_id:null."""
    log.warning(
        "visibility reconcile SKIPPED for central task %s (%s); doc stays fail-closed "
        "private until reprocess", task_id, reason,
    )


def _is_central_rewritten_id(job_id) -> bool:
    """centralstore rewrites info.id to the CENTRAL task id ONLY for broker jobs whose
    job_id matches 'ui-<N>' (centralstore.py). Direct submissions (job_id 'local-<id>')
    and bare-token jobs keep the WORKER-LOCAL info.id — a DIFFERENT id space. This is the
    discriminator: only a rewritten (ui-*) id may be resolved against the central RDS;
    everything else resolves against the worker-local DB (or fails closed)."""
    import re

    return bool(job_id) and re.match(r"^ui-(\d+)$", str(job_id)) is not None


def _stamp_report_for_task(report_info: dict, main_task_id, local_task_id, central_conn=None) -> None:
    """Stamp tenant context onto a report's info subdict (called only when MT is on).

    On the legacy distributed worker path (``main_task_id`` set — only utils/dist.py
    sets it, never the broker/central path) the worker-local task does NOT carry the
    submitter's tenancy, so fail CLOSED to private/invisible rather than leak.

    In CENTRAL mode, info.id is rewritten to the CENTRAL task id ONLY for broker ui-*
    jobs; for those, resolve the submitter's tenancy from the central RDS. For a central
    DIRECT submission (job_id not ui-*), info.id is still the WORKER-LOCAL id, so resolve
    it against the worker-local DB — resolving it against the central RDS would hit a
    COLLIDING central-id-space row (cross-tenant leak). Single-node also uses the local
    DB. Any lookup error fails closed to private."""
    if main_task_id:
        stamp_tenant_info(report_info, None)
        return
    try:
        from lib.cuckoo.common.central_mode import central_mode_config

        if central_mode_config().enabled and _is_central_rewritten_id(report_info.get("job_id")):
            # info.id was rewritten to the CENTRAL id (ui-<N>): resolve from the central
            # RDS (fail-closed if the URL is unset or the task is missing). NOT the
            # worker-local DB (wrong id space) and NOT the user-influenceable custom
            # envelope (spoofable).
            stamp_tenant_info(report_info, _task_tenant_ctx_central(local_task_id, conn=central_conn))
            return
        # Single-node OR central direct-submit: info.id is a WORKER-LOCAL id -> local DB.
        stamp_tenant_info(report_info, _task_tenant_ctx(local_task_id))
    except Exception as _db_err:
        log.warning("Failed to look up task for tenant stamping (task %s): %s", local_task_id, _db_err)
        stamp_tenant_info(report_info, None)


_warned_no_lock_engine = False


def _warn_no_lock_engine_once():
    global _warned_no_lock_engine
    if not _warned_no_lock_engine:
        _warned_no_lock_engine = True
        log.warning(
            "multitenancy enabled but no Postgres advisory-lock engine (non-postgres backend): the "
            "report-visibility reconcile runs UNSERIALIZED against visibility toggles; the fail-closed "
            "insert keeps this window safe (doc is private until upgraded) but a narrow re-widen remains."
        )


def _reconcile_report_visibility(main_task_id, local_task_id, ids_to_delete, job_id=None) -> None:
    """Raise the just-written mongo analysis doc's tenancy to the AUTHORITATIVE SQL value
    under the per-task advisory lock set_task_visibility holds, closing the stamp-vs-toggle
    TOCTOU. run() inserts the doc FAIL-CLOSED (private), so it is never permissive before
    this upgrade; if the upgrade can't complete the doc stays private (safe), never
    stale-permissive.

    The lock must be on the SAME Postgres as the authoritative toggle: for a rewritten
    central id (ui-*) that is the CENTRAL RDS (set_task_visibility runs on the central
    node), so lock the central engine there; otherwise the worker-local engine. A
    worker-local lock would NOT mutually exclude a central-node toggle (locks on different
    servers don't serialize).

    No-op when MT is disabled, on the legacy distributed path (main_task_id set — that doc
    stays fail-closed private, and its lock/id domain differs from the central toggle's, so
    serializing here is neither possible nor needed), or when mongo is unavailable. NEVER
    raises: it runs from run()'s finally, where an escape would flip a fully-stored report
    to failed_reporting or mask the storage block's own exception."""
    try:
        from lib.cuckoo.common.tenancy import multitenancy_config

        if main_task_id or not multitenancy_config().enabled or mongo_update_one is None:
            return
        from lib.cuckoo.core.database import Database
        from lib.cuckoo.core.data.tasking import task_visibility_lock

        # Serialize with the AUTHORITATIVE toggle. In central mode a rewritten (ui-*) id's
        # toggle runs on the central node against the central RDS, so lock the central
        # engine (same DB + key); else the worker-local engine.
        _central_id = False
        try:
            from lib.cuckoo.common.central_mode import central_mode_config

            _central_id = central_mode_config().enabled and _is_central_rewritten_id(job_id)
        except Exception:
            _central_id = False
        if _central_id:
            # The central upgrade REQUIRES a validated writer-primary lock. Without it
            # (unset URL / standby / probe failure) reading tenancy from a lagging standby
            # and $set-ing it verbatim could re-widen the doc (a stale 'public' over a
            # committed private). So skip the upgrade entirely and leave run()'s fail-closed
            # private stamp — genuinely fail-closed (invisible-until-fixed), matching every
            # other central failure mode. _central_lock_engine() already warned once; add a
            # per-task line so operators can enumerate the stranded docs from logs.
            lock_engine = _central_lock_engine()
            if lock_engine is None:
                _warn_central_reconcile_skipped(local_task_id, "no validated writer-primary lock")
                return
        else:
            # Single-node: the local DB is authoritative; a missing lock_engine (sqlite,
            # single-writer) is safe to proceed unserialized.
            lock_engine = getattr(Database(), "lock_engine", None)
            if lock_engine is None:
                _warn_no_lock_engine_once()
        # Seed job_id so _stamp_report_for_task can tell a rewritten central id (ui-*,
        # resolve from the central RDS) from a worker-local id (resolve locally) — it is
        # otherwise blind to the id space here.
        info = {"job_id": job_id}
        with task_visibility_lock(lock_engine, local_task_id) as lock_conn:
            if _central_id:
                # Bind the writer-primary verdict AND the tenancy re-read to the SAME
                # connection that holds the advisory lock. _central_lock_engine()'s probe
                # ran on a throwaway NullPool connection; an in-place failover landing
                # between that probe and the lock — or a multi-host central_database_url
                # (NullPool re-resolves on every connect) — could acquire the lock on a
                # demoted standby whose replication-lag-stale row would re-widen the
                # committed private doc. Re-validate + read on the pinned connection so
                # probe, lock, and read cannot disagree.
                if _connection_in_recovery(lock_conn):
                    _warn_central_reconcile_skipped(
                        local_task_id, "lock connection is a standby / in-lock primary re-check failed")
                    return
                _stamp_report_for_task(info, None, local_task_id, central_conn=lock_conn)
            else:
                # Re-read the current SQL tenancy under the lock (authoritative; a toggle
                # can't commit + sync mongo while we hold it).
                _stamp_report_for_task(info, None, local_task_id)
            try:
                ids = [int(x) for x in ids_to_delete]
            except (TypeError, ValueError):
                ids = [local_task_id]
            res = mongo_update_one(
                "analysis",
                {"info.id": {"$in": ids}},
                {"$set": {
                    "info.tenant_id": info.get("tenant_id"),
                    "info.user_id": info.get("user_id"),
                    "info.visibility": info.get("visibility", "private"),
                }},
            )
            # graceful_auto_reconnect returns None after exhausting AutoReconnect retries
            # (no raise): the upgrade silently no-op'd. The doc is still fail-closed
            # private (safe), but surface it loudly — this is the sole corrector.
            if res is None:
                log.error(
                    "visibility reconcile mongo write FAILED for task %s (mongo unreachable, "
                    "graceful_auto_reconnect exhausted); doc stays fail-closed private until reprocess",
                    local_task_id,
                )
    except Exception:
        # Contain: the fail-closed insert means a failed upgrade is safe (doc stays
        # private). Never propagate out of run()'s finally.
        log.exception("visibility reconcile failed for task %s (doc remains fail-closed private)", local_task_id)


class MongoDB(Report):
    """Stores report in MongoDB."""

    order = 9999

    # Mongo schema version, used for data migration.
    SCHEMA_VERSION = "1"

    def debug_dict_size(self, dct):
        if isinstance(dct, list):
            dct = dct[0]

        totals = dict((k, 0) for k in dct)

        def walk(root, key, val):
            if isinstance(val, dict):
                for k, v in val.items():
                    walk(root, k, v)

            elif isinstance(val, (list, tuple, set)):
                for el in val:
                    walk(root, None, el)

            elif isinstance(val, str):
                totals[root] += len(val)

        for key, val in dct.items():
            walk(key, key, val)

        return sorted(list(totals.items()), key=lambda item: item[1], reverse=True)

    # use this function to hunt down non string key
    def fix_int2str(self, dictionary, current_key_tree=""):
        for k, v in dictionary.iteritems():
            if not isinstance(k, str):
                log.error("BAD KEY: %s", ".".join([current_key_tree, str(k)]))
                dictionary[str(k)] = dictionary.pop(k)
            elif isinstance(v, dict):
                self.fix_int2str(v, ".".join([current_key_tree, k]))
            elif isinstance(v, list):
                for d in v:
                    if isinstance(d, dict):
                        self.fix_int2str(d, ".".join([current_key_tree, k]))

    def loop_saver(self, report):
        keys = list(report.keys())
        if "info" not in keys:
            log.error("Missing 'info' key: %s", keys)
            return
        if "_id" in keys:
            keys.remove("_id")

        # We insert the info section first to get an _id
        obj_id = mongo_insert_one("analysis", {"info": report["info"]}).inserted_id
        keys.remove("info")

        for key in keys:
            try:
                # We include info here so that mongo hooks (like normalize_files) can get the task_id
                mongo_update_one("analysis", {"_id": obj_id}, {"$set": {key: report[key], "info": report["info"]}}, bypass_document_validation=True)
            except InvalidDocument:
                log.warning("Investigate your key: %s", key)
            except Exception as e:
                log.error("Failed to update key %s in loop_saver: %s", key, e)

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to MongoDB.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_MONGO:
            raise CuckooDependencyError("Unable to import pymongo (install with `pip3 install pymongo`)")

        # move to startup
        # Set mongo schema version.
        # TODO: This is not optimal because it run each analysis. Need to run only one time at startup.
        if "cuckoo_schema" in mongo_collection_names():
            if mongo_find_one("cuckoo_schema", {}, {"version": 1})["version"] != self.SCHEMA_VERSION:
                CuckooReportError("Mongo schema version not expected, check data migration tool")
        else:
            mongo_insert_one("cuckoo_schema", {"version": self.SCHEMA_VERSION})
            # Best-effort compound index for tenant-scoped aggregations — only
            # when multitenancy is enabled (a disabled install stays exactly
            # upstream; the index backs the scope_match queries that only run
            # in locked mode).
            from lib.cuckoo.common.tenancy import multitenancy_config

            if multitenancy_config().enabled:
                try:
                    mongo_create_index(
                        "analysis",
                        [("info.tenant_id", 1), ("info.visibility", 1), ("info.user_id", 1)],
                        background=True,
                        name="tenant_scope_idx",
                    )
                except Exception as idx_err:
                    log.warning("Could not create tenant_scope_idx on analysis collection: %s", idx_err)

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = get_json_document(results, self.analysis_path)
        if not report or "info" not in report:
            log.error("Failed to get JSON document or 'info' key is missing for Task")
            return

        local_task_id = int(report["info"].get("id", 0))
        if not local_task_id:
            log.error("Task ID is missing in report['info']")
            return

        # trick for distributed api
        main_task_id = results.get("info", {}).get("options", {}).get("main_task_id")
        if main_task_id:
            with suppress(ValueError, TypeError):
                report["info"]["id"] = int(main_task_id)

        if "network" not in report:
            report["network"] = {}

        if "behavior" not in report or not isinstance(report["behavior"], dict):
            report["behavior"] = {"processes": [], "processtree": [], "summary": {}}

        # Stamp tenant context so mongo aggregations can be scoped. Use an
        # INDEPENDENT session (not the processor's shared scoped session) so we
        # don't leave a transaction open and break processing. Gated on
        # multitenancy being enabled so a disabled/public install writes EXACTLY
        # the upstream report shape (no info.tenant_id/user_id/visibility keys);
        # the migration backfill stamps existing docs when MT is first enabled.
        from lib.cuckoo.common.tenancy import multitenancy_config

        if multitenancy_config().enabled:
            # Insert FAIL-CLOSED: stamp private (no owner/tenant) so the doc is never
            # world/tenant-visible before _reconcile_report_visibility (run()'s finally)
            # raises it to the authoritative value UNDER the advisory lock. A failed or
            # late reconcile then leaves the doc private (safe), never stale-permissive,
            # and partially-built loop_saver docs stay private during the per-key loop.
            # (The legacy distributed path — main_task_id set — has no submitter tenancy
            # and stays private; the reconcile is a no-op there.)
            stamp_tenant_info(report["info"], None)

        # Delete old data just before inserting new one to avoid "missing report" window
        # or data loss if insertion fails during preparation (e.g. OOM)
        ids_to_delete = {local_task_id, int(report["info"]["id"])}
        log.debug("Deleting previous MongoDB data for Task IDs: %s", ids_to_delete)
        mongo_delete_data(list(ids_to_delete))

        new_processes = insert_calls(report, mongodb=True)
        # Store the results in the report.
        report["behavior"]["processes"] = new_processes

        # Store iocs as file
        if reporting_conf.mongodb.dump_iocs:
            dump_iocs(report, local_task_id)

        ensure_valid_utf8(report)
        gc.collect()

        # Store the report and retrieve its object id.
        try:
            log.debug("Inserting new MongoDB report for Task %s", report["info"]["id"])
            mongo_insert_one("analysis", report)

        except OperationFailure as e:
            # Check for error codes indicating the BSON object was too large
            # (10334 BSONObjectTooLarge) or the maximum nested object depth was
            # exceeded (15 Overflow).
            if e.code in (10334, 15):
                log.error("Got MongoDB OperationFailure, code %d", e.code)
                # ToDo rewrite how children are stored
                log.warning("Deleting behavior process tree children from results.")
                del report["behavior"]["processtree"][0]["children"]
                try:
                    mongo_insert_one("analysis", report)
                except Exception as e:
                    log.error("Deleting behavior process tree parent from results: %s", str(e))
                    del report["behavior"]["processtree"][0]
                    mongo_insert_one("analysis", report)
        except InvalidDocument as e:
            if str(e).startswith("cannot encode object") or "must not contain" in str(e):
                self.loop_saver(report)
                return
            parent_key, psize = self.debug_dict_size(report)[0]
            log.warning("Largest parent key: %s (%d MB)", parent_key, int(psize) // MEGABYTE)
            if self.options.get("fix_large_docs"):
                # Delete the problem keys and check for more
                error_saved = True
                size_filter = MONGOSIZELIMIT
                while error_saved:
                    if isinstance(report, list):
                        report = report[0]
                    try:
                        if isinstance(report[parent_key], list):
                            if parent_key == "strings":
                                del report["strings"]
                                parent_key, psize = self.debug_dict_size(report)[0]
                                continue
                            else:
                                for j, parent_dict in enumerate(report[parent_key]):
                                    child_key, csize = self.debug_dict_size(parent_dict)[0]
                                    if csize > size_filter:
                                        log.warning("results['%s']['%s'] deleted due to size: %s", parent_key, child_key, csize)
                                        del report[parent_key][j][child_key]
                        else:
                            child_key, csize = self.debug_dict_size(report[parent_key])[0]
                            if csize > size_filter:
                                log.warning("results['%s']['%s'] deleted due to size: %s", parent_key, child_key, csize)
                                del report[parent_key][child_key]
                        try:
                            mongo_insert_one("analysis", report)
                            error_saved = False
                        except InvalidDocument as e:
                            if str(e).startswith("documents must have only string keys"):
                                log.error("Search bug in your modifications - you got an dictionary key as int, should be string")
                                log.error(str(e))
                                return
                            else:
                                parent_key, psize = self.debug_dict_size(report)[0]
                                log.error(str(e))
                                log.warning("Largest parent key: %s (%d MB)", parent_key, int(psize) // MEGABYTE)
                                size_filter -= MEGABYTE
                    except Exception as e:
                        log.error("Failed to delete child key: %s", e)
                        error_saved = False

                if error_saved:
                    log.error("Failed to insert report into MongoDB even after attempting to fix large documents for Task %s", report["info"]["id"])
        except Exception as e:
            log.exception("Failed to store report in MongoDB for Task %s: %s", report["info"]["id"], e)
        finally:
            # Raise the fail-closed-private doc to the authoritative visibility under
            # set_task_visibility's advisory lock, so a toggle that raced this report
            # can't leave mongo more permissive than SQL. Runs on every exit path (incl.
            # the loop_saver / fix_large_docs returns) and NEVER raises. MT-off and the
            # legacy-dist path are no-ops; on non-postgres the mongo write still runs but
            # unserialized (the fail-closed insert keeps that window safe).
            _reconcile_report_visibility(main_task_id, local_task_id, ids_to_delete, report["info"].get("job_id"))
