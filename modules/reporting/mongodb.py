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


def _stamp_report_for_task(report_info: dict, main_task_id, local_task_id) -> None:
    """Stamp tenant context onto a report's info subdict (called only when MT is on).

    On the legacy distributed worker path (``main_task_id`` set — only utils/dist.py
    sets it, never the broker/central path) the worker-local task does NOT carry the
    submitter's tenancy, so fail CLOSED to private/invisible rather than leak.
    Otherwise stamp from the LOCAL task (report["info"]["id"] may have been rewritten
    to a main id), failing closed to private if that lookup errors."""
    if main_task_id:
        stamp_tenant_info(report_info, None)
        return
    try:
        stamp_tenant_info(report_info, _task_tenant_ctx(local_task_id))
    except Exception as _db_err:
        log.warning("Failed to look up task for tenant stamping (task %s): %s", local_task_id, _db_err)
        stamp_tenant_info(report_info, None)


def _reconcile_report_visibility(main_task_id, local_task_id, ids_to_delete) -> None:
    """Close the stamp-vs-toggle TOCTOU. run() stamps info.visibility from SQL at the
    TOP, then does slow work before writing the mongo doc; a concurrent
    set_task_visibility toggle in that window would leave the doc with a stale (more
    permissive) visibility than SQL — a cross-tenant leak, since the aggregate/search/
    stats surfaces scope on info.visibility. Re-stamp the written doc from the
    AUTHORITATIVE SQL row under the SAME per-task advisory lock the toggle holds, so
    the two can't interleave and mongo ends == SQL. No-op when MT is disabled."""
    from lib.cuckoo.common.tenancy import multitenancy_config

    if not multitenancy_config().enabled or mongo_update_one is None:
        return
    from lib.cuckoo.core.database import Database
    from lib.cuckoo.core.data.tasking import task_visibility_lock

    info = {}
    with task_visibility_lock(getattr(Database(), "lock_engine", None), local_task_id):
        # Re-read the current SQL tenancy (same fail-closed rules as the initial stamp).
        _stamp_report_for_task(info, main_task_id, local_task_id)
        try:
            ids = [int(x) for x in ids_to_delete]
        except (TypeError, ValueError):
            ids = [local_task_id]
        mongo_update_one(
            "analysis",
            {"info.id": {"$in": ids}},
            {"$set": {
                "info.tenant_id": info.get("tenant_id"),
                "info.user_id": info.get("user_id"),
                "info.visibility": info.get("visibility", "private"),
            }},
        )


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
            # Fail-closed on the legacy distributed worker path (main_task_id set),
            # else stamp from the LOCAL task. MT is supported on the mongo store +
            # the broker/central path; legacy dist.py is a documented not-yet-
            # supported mode (see docs/MULTITENANCY-SUPPORT.md). See _stamp_report_for_task.
            _stamp_report_for_task(report["info"], main_task_id, local_task_id)

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
            # Serialize the visibility (re)stamp with set_task_visibility so a toggle
            # that raced this report run can't leave mongo more permissive than SQL.
            # Runs on every exit path (incl. the loop_saver / fix_large_docs returns).
            # No-op when MT is off / non-postgres.
            _reconcile_report_visibility(main_task_id, local_task_id, ids_to_delete)
