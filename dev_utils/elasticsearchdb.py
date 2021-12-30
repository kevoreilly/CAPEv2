# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging

from lib.cuckoo.common.config import Config

repconf = Config("reporting")
if repconf.elasticsearchdb.enabled:
    from elasticsearch import Elasticsearch

    elastic_handler = Elasticsearch(
        hosts=[repconf.elasticsearchdb.host],
        port=repconf.elasticsearchdb.get("port", 9200),
        http_auth=(repconf.elasticsearchdb.get("username", None), repconf.elasticsearchdb.get("password", None)),
        use_ssl=repconf.elasticsearchdb.get("use_ssl", False),
        verify_certs=repconf.elasticsearchdb.get("verify_certs", False),
        timeout=60,
    )

    ANALYSIS_INDEX_PREFIX = f"{repconf.elasticsearchdb.index}-analysis-"
    CALLS_INDEX_PREFIX = f"{repconf.elasticsearchdb.index}-calls-"
    SCROLL_SIZE = 5000
    SCROLL_TIME = "5m"

log = logging.getLogger(__name__)


def get_daily_analysis_index():
    return f"{ANALYSIS_INDEX_PREFIX}{datetime.datetime.now().strftime('%Y.%m.%d')}"


def daily_analysis_index_exists():
    return elastic_handler.indices.exists(index=get_daily_analysis_index())


def get_daily_calls_index():
    return f"{CALLS_INDEX_PREFIX}{datetime.datetime.now().strftime('%Y.%m.%d')}"


def daily_calls_index_exists():
    return elastic_handler.indices.exists(index=get_daily_calls_index())


def get_query_by_info_id(task_id):
    return {"query": {"match": {"info.id": task_id}}}


def get_analysis_index():
    return f"{ANALYSIS_INDEX_PREFIX}*"


def get_analysis_index_mapping():
    return {
        "mappings": {
            "properties": {
                "info": {
                    "properties": {
                        "started": {"type": "date"},
                        "machine": {"properties": {"started_on": {"type": "date"}, "shutdown_on": {"type": "date"}}},
                    }
                },
                "network": {"properties": {"dead_hosts": {"type": "keyword"}}},
            }
        }
    }


def get_calls_index():
    return f"{CALLS_INDEX_PREFIX}*"


def delete_analysis_and_related_calls(task_id):
    analyses = elastic_handler.search(index=get_analysis_index(), body=get_query_by_info_id(task_id))["hits"]["hits"]
    if analyses:
        log.debug("Deleting analysis data for Task %s" % task_id)
        for analysis in analyses:
            analysis = analysis["_source"]
            for process in analysis["behavior"].get("processes", []) or []:
                for call in process["calls"]:
                    elastic_handler.delete_by_query(index=get_calls_index(), body={"query": {"match": {"_id": call}}})

            elastic_handler.delete_by_query(index=get_analysis_index(), body=get_query_by_info_id(task_id))
        log.debug("Deleted previous ElasticsearchDB data for Task %s" % task_id)


def scroll(scroll_id):
    return elastic_handler.scroll(scroll_id=scroll_id, scroll=SCROLL_TIME)


def scroll_docs(index, query, timeout=600, _source=()):
    return elastic_handler.search(
        index=index, body=query, scroll=SCROLL_TIME, size=SCROLL_SIZE, request_timeout=timeout, _source=_source
    )


def all_docs(index, query, _source=()):
    # Scroll documents
    result_scroll = scroll_docs(index=index, query=query, _source=_source)
    hits = result_scroll["hits"]["hits"]

    while result_scroll["hits"]["hits"]:
        result_scroll = scroll(result_scroll["_scroll_id"])
        # Process current batch of hits
        hits.extend(result_scroll["hits"]["hits"])

    elastic_handler.clear_scroll(scroll_id=result_scroll["_scroll_id"])

    return hits
