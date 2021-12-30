# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import gc
import logging
from datetime import datetime

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooDependencyError, CuckooReportError
from modules.reporting.report_doc import ensure_valid_utf8, get_json_document, insert_calls

repconf = Config("reporting")
if repconf.elasticsearchdb.enabled:
    try:
        from elasticsearch.exceptions import AuthorizationException, ConnectionError, RequestError

        from dev_utils.elasticsearchdb import (daily_analysis_index_exists, daily_calls_index_exists,
                                               delete_analysis_and_related_calls, elastic_handler, get_analysis_index_mapping,
                                               get_daily_analysis_index, get_daily_calls_index)

        HAVE_ELASTICSEARCH = True
    except ImportError:
        HAVE_ELASTICSEARCH = False

log = logging.getLogger(__name__)


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
            raise CuckooReportError(
                "Elasticsearch connection port must be integer")
        except ConnectionError:
            raise CuckooReportError("Cannot connect to ElasticsearchDB")

    def index_report(self, report):
        self.es.index(index=get_daily_analysis_index(), body=report)

    def check_analysis_index(self):
        try:
            log.info('Check if the index exists')
            if not daily_analysis_index_exists():
                self.es.indices.create(index=get_daily_analysis_index(),
                                       body=get_analysis_index_mapping())
        except (RequestError, AuthorizationException) as e:
            raise CuckooDependencyError(
                f"Unable to create Elasticsearch index {e}"
            )

    def check_calls_index(self):
        try:
            log.info('Check if the index exists')
            if not daily_calls_index_exists():
                self.es.indices.create(index=get_daily_calls_index())
        except (RequestError, AuthorizationException) as e:
            raise CuckooDependencyError(
                f"Unable to create Elasticsearch index {e}"
            )

    def format_dates(self, report):
        report['info']['started'] = datetime.strptime(report['info']['started'],
                                                      "%Y-%m-%d %H:%M:%S")
        report['info']['ended'] = datetime.strptime(report['info']['ended'],
                                                    "%Y-%m-%d %H:%M:%S")
        report['info']['machine']['started_on'] = datetime.strptime(
            report['info']['machine']['started_on'], "%Y-%m-%d %H:%M:%S")
        report['info']['machine']['shutdown_on'] = datetime.strptime(
            report['info']['machine']['shutdown_on'], "%Y-%m-%d %H:%M:%S")

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to Elasticsearch DB.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_ELASTICSEARCH:
            raise CuckooDependencyError(
                "Unable to import elasticsearch " "(install with `pip3 install elasticsearch`)")

        self.connect()

        # Check if the daily index exists.
        self.check_analysis_index()
        self.check_calls_index()

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = get_json_document(results, self.analysis_path)
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
