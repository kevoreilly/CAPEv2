# Copyright (C) 2010-2015 Jose Palanco (jose.palanco@drainware.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File

try:
    from elasticsearch import Elasticsearch

    HAVE_ELASTICSEARCH = True
except ImportError:
    HAVE_ELASTICSEARCH = False

logging.getLogger("elasticsearch").setLevel(logging.WARNING)


class ElasticsearchDB(Report):
    """Stores report in Elastic Search."""

    order = 9997

    def connect(self):
        """Connects to Elasticsearch database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        self.es = Elasticsearch(
            hosts=[
                {
                    "host": self.options.get("host", "127.0.0.1"),
                    "port": self.options.get("port", 9200),
                }
            ],
            timeout=60,
        )

    def run(self, results: dict):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to Elasticsearch.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_ELASTICSEARCH:
            raise CuckooDependencyError("Unable to import elasticsearch " "(install with `pip3 install elasticsearch`)")

        self.connect()
        index_prefix = self.options.get("index", "cuckoo")
        search_only = self.options.get("searchonly", False)

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = dict(results)

        idxdate = report["info"]["started"].split(" ")[0]
        self.index_name = "{0}-{1}".format(index_prefix, idxdate)

        if not search_only:
            if "network" not in report:
                report["network"] = {}

            # Store API calls in chunks for pagination in Django
            if "processes" in report.get("behavior", {}):
                new_processes = []
                for process in report["behavior"]["processes"]:
                    new_process = dict(process)
                    chunk = []
                    chunks_ids = []
                    # Loop on each process call.
                    for call in process["calls"]:
                        # If the chunk size is 100 or if the loop is completed then
                        # store the chunk in Elastcisearch.
                        if len(chunk) == 100:
                            to_insert = {"pid": process["process_id"], "calls": chunk}
                            pchunk = self.es.index(index=self.index_name, doc_type="calls", body=to_insert)
                            chunk_id = pchunk["_id"]
                            chunks_ids.append(chunk_id)
                            # Reset the chunk.
                            chunk = []

                        # Append call to the chunk.
                        chunk.append(call)

                    # Store leftovers.
                    if chunk:
                        to_insert = {"pid": process["process_id"], "calls": chunk}
                        pchunk = self.es.index(index=self.index_name, doc_type="calls", body=to_insert)
                        chunk_id = pchunk["_id"]
                        chunks_ids.append(chunk_id)

                    # Add list of chunks.
                    new_process["calls"] = chunks_ids
                    new_processes.append(new_process)

                # Store the results in the report.
                report["behavior"] = dict(report["behavior"])
                report["behavior"]["processes"] = new_processes

            # Add screenshot paths
            report["shots"] = []
            shots_path = os.path.join(self.analysis_path, "shots")
            if os.path.exists(shots_path):
                shots = [shot for shot in os.listdir(shots_path) if shot.endswith(".jpg")]
                for shot_file in sorted(shots):
                    shot_path = os.path.join(self.analysis_path, "shots", shot_file)
                    screenshot = File(shot_path)
                    if screenshot.valid():
                        # Strip the extension as it's added later in the Django view
                        report["shots"].append(shot_file.replace(".jpg", ""))

            # Other info we want Quick access to from the web UI
            if "positives" in results.get("virustotal", {}) and "total" in results.get("virustotal", {}):
                report["virustotal_summary"] = f'{results["virustotal"]["positives"]}/{results["virustotal"]["total"]}'

            if results.get("suricata", {}):
                if len(results["suricata"].get("tls", [])) > 0:
                    report["suri_tls_cnt"] = len(results["suricata"]["tls"])
                if len(results["suricata"].get("alerts", [])) > 0:
                    report["suri_alert_cnt"] = len(results["suricata"]["alerts"])
                if len(results["suricata"].get("files", [])) > 0:
                    report["suri_file_cnt"] = len(results["suricata"]["files"])
                if len(results["suricata"].get("http", [])) > 0:
                    report["suri_http_cnt"] = len(results["suricata"]["http"])
        else:
            report = {
                "task_id": results["info"]["id"],
                "info": results.get("info"),
                "target": results.get("target"),
                "summary": results.get("behavior", {}).get("summary"),
                "network": results.get("network"),
                "virustotal": results.get("virustotal"),
                "virustotal_summary": f'{results["virustotal"]["positives"]}/{results["virustotal"]["total"]}',
            }

        # Store the report and retrieve its object id.
        self.es.index(index=self.index_name, doc_type="analysis", id=results["info"]["id"], body=report)
