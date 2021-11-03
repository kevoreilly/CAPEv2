# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import gc
import logging
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from six.moves import zip

MONGOSIZELIMIT = 0x1000000
MEGABYTE = 0x100000

try:
    from pymongo import MongoClient, TEXT
    from bson.objectid import ObjectId
    from pymongo.errors import ConnectionFailure, InvalidDocument

    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

log = logging.getLogger(__name__)


class MongoDB(Report):
    """Stores report in MongoDB."""

    order = 9999

    # Mongo schema version, used for data migration.
    SCHEMA_VERSION = "1"

    def connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        try:
            self.conn = MongoClient(
                self.options.get("host", "127.0.0.1"),
                port=self.options.get("port", 27017),
                username=self.options.get("username", None),
                password=self.options.get("password", None),
                authSource=self.options.get("authsource", "cuckoo"),
            )
            self.db = self.conn[self.options.get("db", "cuckoo")]
        except TypeError:
            raise CuckooReportError("Mongo connection port must be integer")
        except ConnectionFailure:
            raise CuckooReportError("Cannot connect to MongoDB")

    def debug_dict_size(self, dct):
        if type(dct) == list:
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

    @classmethod
    def ensure_valid_utf8(cls, obj):
        """Ensures that all strings are valid UTF-8 encoded, which is
        required by MongoDB to be able to store the JSON documents.
        @param obj: analysis results dictionary.
        """
        if not obj:
            return

        items = []
        if isinstance(obj, dict):
            items = obj.items()
        elif isinstance(obj, list):
            items = enumerate(obj)

        for k, v in items:
            # This type check is intentionally not done using isinstance(),
            # because bson.binary.Binary *is* a subclass of bytes/str, and
            # we do not want to convert that.
            if type(v) is str:
                try:
                    v.encode("utf-8")
                except UnicodeEncodeError:
                    obj[k] = "".join(str(ord(_)) for _ in v).encode("utf-8")
            else:
                cls.ensure_valid_utf8(v)

    # use this function to hunt down non string key
    def fix_int2str(self, dictionary, current_key_tree=""):
        for k, v in dictionary.iteritems():
            if not isinstance(k, str):
                log.error("BAD KEY: {}".format(".".join([current_key_tree, str(k)])))
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
            log.error("Missing 'info' key: %r", keys)
            return
        if "_id" in keys:
            keys.remove("_id")

        obj_id = self.db.analysis.insert_one({"info": report["info"]})
        keys.remove("info")

        for key in keys:
            try:
                self.db.analysis.update_one(
                    {"_id": obj_id.inserted_id}, {"$set": {key: report[key]}}, bypass_document_validation=True
                )
            except InvalidDocument as e:
                log.warning("Investigate your key: %r", key)

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to MongoDB.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_MONGO:
            raise CuckooDependencyError("Unable to import pymongo " "(install with `pip3 install pymongo`)")

        self.connect()

        # Set mongo schema version.
        # TODO: This is not optimal because it run each analysis. Need to run only one time at startup.
        if "cuckoo_schema" in self.db.collection_names():
            if self.db.cuckoo_schema.find_one()["version"] != self.SCHEMA_VERSION:
                CuckooReportError("Mongo schema version not expected, check data migration tool")
        else:
            self.db.cuckoo_schema.insert_one({"version": self.SCHEMA_VERSION})

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = dict(results)

        if "network" not in report:
            report["network"] = {}

        # Add screenshot paths
        report["shots"] = []
        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            shots = [shot for shot in os.listdir(shots_path) if shot.endswith(".jpg")]
            for shot_file in sorted(shots):
                shot_path = os.path.join(self.analysis_path, "shots", shot_file)
                screenshot = File(shot_path)
                if screenshot.valid():
                    # Strip the extension as it's added later
                    # in the Django view
                    report["shots"].append(shot_file.replace(".jpg", ""))

        # Store chunks of API calls in a different collection and reference
        # those chunks back in the report. In this way we should defeat the
        # issue with the oversized reports exceeding MongoDB's boundaries.
        # Also allows paging of the reports.
        new_processes = []

        for process in report.get("behavior", {}).get("processes", []) or []:
            new_process = dict(process)
            chunk = []
            chunks_ids = []
            # Loop on each process call.
            for _, call in enumerate(process["calls"]):
                # If the chunk size is 100 or if the loop is completed then
                # store the chunk in MongoDB.
                if len(chunk) == 100:
                    to_insert = {"pid": process["process_id"], "calls": chunk}
                    chunk_id = self.db.calls.insert(to_insert)
                    chunks_ids.append(chunk_id)
                    # Reset the chunk.
                    chunk = []
                # Append call to the chunk.
                chunk.append(call)
            # Store leftovers.
            if chunk:
                to_insert = {"pid": process["process_id"], "calls": chunk}
                chunk_id = self.db.calls.insert(to_insert)
                chunks_ids.append(chunk_id)
            # Add list of chunks.
            new_process["calls"] = chunks_ids
            new_processes.append(new_process)
        # Store the results in the report.
        report["behavior"] = dict(report["behavior"])
        report["behavior"]["processes"] = new_processes
        # Calculate the mlist_cnt for display if present to reduce db load
        if "signatures" in results:
            for entry in results["signatures"]:
                if entry["name"] == "ie_martian_children":
                    report["mlist_cnt"] = len(entry["data"])
                if entry["name"] == "office_martian_children":
                    report["f_mlist_cnt"] = len(entry["data"])

        # Other info we want quick access to from the web UI
        if results.get("virustotal", {}).get("positive") and results.get("virustotal", {}).get("total"):
            report["virustotal_summary"] = "%s/%s" % (results["virustotal"]["positive"], results["virustotal"]["total"])
        if results.get("suricata", False):

            keywords = ("tls", "alerts", "files", "http", "ssh", "dns")
            keywords_dict = ("suri_tls_cnt", "suri_alert_cnt", "suri_file_cnt", "suri_http_cnt", "suri_ssh_cnt", "suri_dns_cnt")
            for keyword, keyword_value in zip(keywords, keywords_dict):
                if results["suricata"].get(keyword, 0):
                    report[keyword_value] = len(results["suricata"][keyword])

        # Create an index based on the info.id dict key. Increases overall scalability
        # with large amounts of data.
        # Note: Silently ignores the creation if the index already exists.
        self.db.analysis.create_index("info.id", background=True)

        # We performs a lot of SHA256 hash lookup so we need this index
        self.db.analysis.create_index(
            [("target.file.sha256", TEXT), ("dropped.sha256", TEXT), ("procdump.sha256", TEXT), ("CAPE.payloads.sha256", TEXT)],
            name="ALL_SHA256",
            background=True,
        )

        # trick for distributed api
        if results.get("info", {}).get("options", {}).get("main_task_id", ""):
            report["info"]["id"] = int(results["info"]["options"]["main_task_id"])

        analyses = self.db.analysis.find({"info.id": int(report["info"]["id"])})
        if analyses:
            log.debug("Deleting analysis data for Task %s" % report["info"]["id"])
            for analysis in analyses:
                for process in analysis["behavior"].get("processes", []) or []:
                    for call in process["calls"]:
                        self.db.calls.remove({"_id": ObjectId(call)})
                self.db.analysis.remove({"_id": ObjectId(analysis["_id"])})
            log.debug("Deleted previous MongoDB data for Task %s" % report["info"]["id"])

        self.ensure_valid_utf8(report)
        gc.collect()

        # Store the report and retrieve its object id.
        try:
            self.db.analysis.insert_one(report)
        except InvalidDocument as e:
            if str(e).startswith("cannot encode object") or str(e).endswith("must not contain '.'"):
                self.loop_saver(report)
                return
            parent_key, psize = self.debug_dict_size(report)[0]
            if not self.options.get("fix_large_docs", False):
                # Just log the error and problem keys
                # log.error(str(e))
                log.warning("Largest parent key: %s (%d MB)" % (parent_key, int(psize) / MEGABYTE))
            else:
                # Delete the problem keys and check for more
                error_saved = True
                size_filter = MONGOSIZELIMIT
                while error_saved:
                    if type(report) == list:
                        report = report[0]
                    try:
                        if type(report[parent_key]) == list:
                            for j, parent_dict in enumerate(report[parent_key]):
                                child_key, csize = self.debug_dict_size(parent_dict)[0]
                                if csize > size_filter:
                                    log.warn("results['%s']['%s'] deleted due to size: %s" % (parent_key, child_key, csize))
                                    del report[parent_key][j][child_key]
                        else:
                            child_key, csize = self.debug_dict_size(report[parent_key])[0]
                            if csize > size_filter:
                                log.warn("results['%s']['%s'] deleted due to size: %s" % (parent_key, child_key, csize))
                                del report[parent_key][child_key]
                        try:
                            self.db.analysis.insert_one(report)
                            error_saved = False
                        except InvalidDocument as e:
                            if str(e).startswith("documents must have only string keys"):
                                log.error("Search bug in your modifications - you got an dictionary key as int, should be string")
                                log.error(str(e))
                                return
                            else:
                                parent_key, psize = self.debug_dict_size(report)[0]
                                log.error(str(e))
                                log.warning("Largest parent key: %s (%d MB)" % (parent_key, int(psize) / MEGABYTE))
                                size_filter = size_filter - MEGABYTE
                    except Exception as e:
                        log.error("Failed to delete child key: %s" % str(e))
                        error_saved = False

        self.conn.close()
