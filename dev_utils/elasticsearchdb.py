# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# ToDo upgrade
# Deprecation warnings in 7.15.0 pre-releases
# https://github.com/elastic/elasticsearch-py/issues/1698

import datetime
import logging
from typing import Iterable, List

from lib.cuckoo.common.config import Config

repconf = Config("reporting")
if repconf.elasticsearchdb.enabled:
    from elasticsearch import Elasticsearch

    elastic_handler = Elasticsearch(
        hosts=[repconf.elasticsearchdb.host],
        port=repconf.elasticsearchdb.get("port", 9200),
        http_auth=(repconf.elasticsearchdb.get("username"), repconf.elasticsearchdb.get("password")),
        use_ssl=repconf.elasticsearchdb.get("use_ssl", False),
        verify_certs=repconf.elasticsearchdb.get("verify_certs", False),
        timeout=120,
    )

    ANALYSIS_INDEX_PREFIX = f"{repconf.elasticsearchdb.index}-analysis-"
    CALLS_INDEX_PREFIX = f"{repconf.elasticsearchdb.index}-calls-"
    SCROLL_SIZE = 5000
    SCROLL_TIME = "5m"

log = logging.getLogger(__name__)

ANALYSIS_INDEX_MAPPING_SETTINGS = {
    "mappings": {
        "properties": {
            "info": {
                "properties": {
                    "started": {"type": "date"},
                    "machine": {"properties": {"started_on": {"type": "date"}, "shutdown_on": {"type": "date"}}},
                }
            },
            "network": {"properties": {"dead_hosts": {"type": "keyword"}}},
            "target": {"properties": {"file": {"properties": {"tlsh": {"type": "keyword"}}}}},
            "dropped": {"properties": {"tlsh": {"type": "keyword"}}},
            "CAPE": {"properties": {"payloads": {"properties": {"tlsh": {"type": "keyword"}}}}},
        }
    },
    "settings": {
        "index.blocks.read_only_allow_delete": "false",
        "index.priority": "1",
        "index.query.default_field": ["*"],
        "index.refresh_interval": "1s",
        "index.write.wait_for_active_shards": "1",
        "index.routing.allocation.include._tier_preference": "data_content",
        "index.number_of_replicas": "1",
        "index.mapping.total_fields.limit": 20000,
        "index.mapping.depth.limit": 1000,
    },
}


def get_daily_analysis_index() -> str:
    return f"{ANALYSIS_INDEX_PREFIX}{datetime.datetime.now().strftime('%Y.%m.%d')}"


def daily_analysis_index_exists() -> bool:
    return elastic_handler.indices.exists(index=get_daily_analysis_index())


def get_daily_calls_index() -> str:
    return f"{CALLS_INDEX_PREFIX}{datetime.datetime.now().strftime('%Y.%m.%d')}"


def daily_calls_index_exists() -> bool:
    return elastic_handler.indices.exists(index=get_daily_calls_index())


def get_query_by_info_id(task_id: str) -> dict:
    return {"match": {"info.id": task_id}}


def get_analysis_index() -> str:
    return f"{ANALYSIS_INDEX_PREFIX}*"


def get_calls_index():
    return f"{CALLS_INDEX_PREFIX}*"


def delete_analysis_and_related_calls(task_id: str):
    analyses = elastic_handler.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"]
    if analyses:
        log.debug("Deleting analysis data for Task %s", task_id)
        for analysis in analyses:
            analysis = analysis["_source"]
            for process in analysis["behavior"].get("processes", []):
                for call in process["calls"]:
                    elastic_handler.delete_by_query(index=get_calls_index(), body={"query": {"match": {"_id": call}}})

            elastic_handler.delete_by_query(index=get_analysis_index(), body={"query": get_query_by_info_id(task_id)})
        log.debug("Deleted previous ElasticsearchDB data for Task %s", task_id)


def scroll(scroll_id: str) -> dict:
    return elastic_handler.scroll(scroll_id=scroll_id, scroll=SCROLL_TIME)


def scroll_docs(index: str, query: dict, timeout: int = 600, _source: Iterable[str] = ()) -> dict:
    return elastic_handler.search(
        index=index, body=query, scroll=SCROLL_TIME, size=SCROLL_SIZE, request_timeout=timeout, _source=_source
    )


def all_docs(index: str, query: dict, _source: Iterable[str] = ()) -> List[dict]:
    # Scroll documents
    result_scroll = scroll_docs(index=index, query=query, _source=_source)
    hits = result_scroll["hits"]["hits"]

    if "_scroll_id" not in result_scroll:
        return []

    while len(result_scroll["hits"]["hits"]) > 0:
        # Process current batch of hits
        hits.extend(result_scroll["hits"]["hits"])

        result_scroll = scroll(result_scroll["_scroll_id"])

    elastic_handler.clear_scroll(scroll_id=result_scroll["_scroll_id"])

    return hits
