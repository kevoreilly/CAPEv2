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

    from dev_utils.mongodb import mongo_collection_names, mongo_delete_data, mongo_find_one, mongo_insert_one, mongo_update_one

    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

MONGOSIZELIMIT = 0x1000000
MEGABYTE = 0x100000

log = logging.getLogger(__name__)
reporting_conf = Config("reporting")


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
