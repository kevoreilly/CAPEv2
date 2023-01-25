# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gc
import json
import logging
from contextlib import suppress
from datetime import datetime

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from modules.reporting.report_doc import ensure_valid_utf8, get_json_document, insert_calls

repconf = Config("reporting")
if repconf.elasticsearchdb.enabled:
    try:
        from elasticsearch.exceptions import AuthorizationException, ConnectionError, RequestError

        from dev_utils.elasticsearchdb import (
            ANALYSIS_INDEX_MAPPING_SETTINGS,
            daily_analysis_index_exists,
            daily_calls_index_exists,
            delete_analysis_and_related_calls,
            elastic_handler,
            get_daily_analysis_index,
            get_daily_calls_index,
        )

        HAVE_ELASTICSEARCH = True
    except ImportError:
        HAVE_ELASTICSEARCH = False

log = logging.getLogger(__name__)
logging.getLogger("elasticsearch").setLevel("ERROR")


class ElasticSearchDB(Report):
    """Stores report in ElasticSearchDB."""

    def __init__(self):
        self.es = None

    def connect(self):
        """Connects to Elasticsearch database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        try:
            self.es = elastic_handler
        except TypeError:
            raise CuckooReportError("Elasticsearch connection port must be integer")
        except ConnectionError:
            raise CuckooReportError("Cannot connect to ElasticsearchDB")

    def index_report(self, report):
        self.es.index(index=get_daily_analysis_index(), body=report)

    def check_analysis_index(self):
        try:
            log.debug("Check if the index exists")
            if not daily_analysis_index_exists():
                self.es.indices.create(
                    index=get_daily_analysis_index(),
                    body=ANALYSIS_INDEX_MAPPING_SETTINGS,
                )
        except (RequestError, AuthorizationException) as e:
            raise CuckooDependencyError(f"Unable to create Elasticsearch index {e}")

    def check_calls_index(self):
        try:
            log.debug("Check if the index exists")
            if not daily_calls_index_exists():
                self.es.indices.create(index=get_daily_calls_index())
        except (RequestError, AuthorizationException) as e:
            raise CuckooDependencyError(f"Unable to create Elasticsearch index {e}")

    def format_dates(self, report):
        info = report["info"]

        report["info"]["started"] = (
            datetime.strptime(info["started"], "%Y-%m-%d %H:%M:%S") if isinstance(info["started"], str) else info["started"]
        )
        report["info"]["ended"] = (
            datetime.strptime(info["ended"], "%Y-%m-%d %H:%M:%S") if isinstance(info["ended"], str) else info["ended"]
        )
        report["info"]["machine"]["started_on"] = (
            datetime.strptime(info["machine"]["started_on"], "%Y-%m-%d %H:%M:%S")
            if isinstance(info["machine"]["started_on"], str)
            else info["machine"]["started_on"]
        )
        report["info"]["machine"]["shutdown_on"] = (
            datetime.strptime(info["machine"]["shutdown_on"], "%Y-%m-%d %H:%M:%S")
            if isinstance(info["machine"]["shutdown_on"], str)
            else info["machine"]["shutdown_on"]
        )

        for dropped in report["dropped"]:
            if "pe" in dropped:
                dropped["pe"]["timestamp"] = datetime.strptime(dropped["pe"]["timestamp"], "%Y-%m-%d %H:%M:%S")

    # Fix signatures from string to list in order to have a common mapping
    def fix_signature_results(self, report):
        for s in report["signatures"]:
            for f in s["data"]:
                for k, val in f.items():
                    if isinstance(val, (str, bool)):
                        f[k] = {"name": str(val)}
                    if k == "file" and isinstance(val, list):
                        for index, file in enumerate(val):
                            val[index] = {"name": file}

    def fix_suricata_http_status(self, report):
        if "http" in report["suricata"]:
            for http in report["suricata"]["http"]:
                if http["status"] == "None":
                    http["status"] = None

    def fix_cape_payloads(self, report):
        if "CAPE" in report:
            for p in report["CAPE"]["payloads"]:
                if p["tlsh"] is False:
                    p["tlsh"] = None

    def convert_procdump_strings_to_str(self, report):
        if "procdump" in report and report["procdump"]:
            for item in report["procdump"]:
                for k, val in item.items():
                    if k == "strings":
                        for index, string in enumerate(val):
                            val[index] = str(string)

    def fix_fields(self, report):
        self.fix_suricata_http_status(report)
        self.fix_signature_results(report)
        self.fix_cape_payloads(report)
        self.convert_procdump_strings_to_str(report)

    def date_hook(self, json_dict):
        for (key, value) in json_dict.items():
            with suppress(Exception):
                json_dict[key] = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        return json_dict

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to Elasticsearch DB.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_ELASTICSEARCH:
            raise CuckooDependencyError("Unable to import elasticsearch (install with `pip3 install elasticsearch`)")

        self.connect()

        # Check if the daily index exists.
        self.check_analysis_index()
        self.check_calls_index()

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = get_json_document(results, self.analysis_path)
        self.fix_fields(report)
        report = json.loads(json.dumps(report, default=str), object_hook=self.date_hook)
        new_processes = insert_calls(report, elastic_db=elastic_handler)

        # Store the results in the report.
        report["behavior"] = dict(report["behavior"])
        report["behavior"]["processes"] = new_processes

        delete_analysis_and_related_calls(report["info"]["id"])
        self.format_dates(report)
        ensure_valid_utf8(report)
        gc.collect()

        # Store the report and retrieve its object id.
        try:
            self.index_report(report)
        except Exception as e:
            log.error(e)
            return
