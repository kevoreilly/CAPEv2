# Configuration for MCP server search filters
# You can modify this dictionary to include or exclude specific fields in the lean report
# Injested by Agents to give a quick overview

lean_search_filters = {
    "info": 1,
    "virustotal_summary": 1,
    "detections.family": 1,
    "malfamily": 1,
    "malfamily_tag": 1,
    "malscore": 1,
    "network.pcap_sha256": 1,
    "network.domains.domain": 1,
    "network.http.uri": 1,
    "signatures.name": 1,
    "signatures.description": 1,
    "signatures.severity": 1,
    "CAPE": 1,
    "behavior.summary.mutexes": 1,
    "behavior.summary.executed_commands": 1,
    "mlist_cnt": 1,
    "f_mlist_cnt": 1,
    "target.file.clamav": 1,
    "target.file.sha256": 1,
    "suri_tls_cnt": 1,
    "suri_alert_cnt": 1,
    "suri_http_cnt": 1,
    "suri_file_cnt": 1,
    "trid": 1,
    "_id": 0,
}
