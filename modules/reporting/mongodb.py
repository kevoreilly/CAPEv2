# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gc
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from modules.reporting.report_doc import ensure_valid_utf8, get_json_document, insert_calls

try:
    from pymongo.errors import InvalidDocument, OperationFailure

    from dev_utils.mongodb import mongo_collection_names, mongo_delete_data, mongo_find_one, mongo_insert_one, mongo_update_one

    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

MONGOSIZELIMIT = 0x1000000
MEGABYTE = 0x100000

log = logging.getLogger(__name__)


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

        obj_id = mongo_insert_one("analysis", {"info": report["info"]}).inserted_id
        keys.remove("info")

        for key in keys:
            try:
                mongo_update_one("analysis", {"_id": obj_id}, {"$set": {key: report[key]}}, bypass_document_validation=True)
            except InvalidDocument:
                log.warning("Investigate your key: %s", key)

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

        if "network" not in report:
            report["network"] = {}

        new_processes = insert_calls(report, mongodb=True)
        # Store the results in the report.
        report["behavior"] = dict(report["behavior"])
        report["behavior"]["processes"] = new_processes

        # trick for distributed api
        if results.get("info", {}).get("options", {}).get("main_task_id", ""):
            report["info"]["id"] = int(results["info"]["options"]["main_task_id"])

        mongo_delete_data(int(report["info"]["id"]))
        log.debug("Deleted previous MongoDB data for Task %s", report["info"]["id"])

        ensure_valid_utf8(report)
        gc.collect()

        # Store the report and retrieve its object id.
        try:
            mongo_insert_one("analysis", report)
        except OperationFailure as e:
            # ToDo rewrite how children are stored
            if str(e).startswith("BSONObj exceeds maximum nested object"):
                log.debug("Deleting behavior process tree children from results.")
                del report["behavior"]["processtree"][0]["children"]
                try:
                    mongo_insert_one("analysis", report)
                except Exception as e:
                    log.error("Deleting behavior process tree parent from results: %s", str(e))
                    del report["behavior"]["processtree"][0]
                    mongo_insert_one("analysis", report)
        except InvalidDocument as e:
            if str(e).startswith("cannot encode object") or str(e).endswith("must not contain '.'"):
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
                                        log.warn("results['%s']['%s'] deleted due to size: %s", parent_key, child_key, csize)
                                        del report[parent_key][j][child_key]
                        else:
                            child_key, csize = self.debug_dict_size(report[parent_key])[0]
                            if csize > size_filter:
                                log.warn("results['%s']['%s'] deleted due to size: %s", parent_key, child_key, csize)
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
