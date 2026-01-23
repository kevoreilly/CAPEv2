import json
import logging
import os

import requests

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.objects import File

processing_conf = Config("processing")

log = logging.getLogger(__name__)


def reversing_labs_lookup(target: str, is_hash: bool = False):
    _headers = {
        "User-Agent": "CAPE Sandbox",
        "Content-Type": "application/json",
        "Authorization": f"Token {processing_conf.reversinglabs.key}",
    }

    report_fields = [
        "id",
        "sha1",
        "sha256",
        "sha512",
        "md5",
        "category",
        "file_type",
        "file_subtype",
        "identification_name",
        "identification_version",
        "file_size",
        "extracted_file_count",
        "local_first_seen",
        "local_last_seen",
        "classification_origin",
        "classification_reason",
        "classification_source",
        "classification",
        "riskscore",
        "classification_result",
        "ticore",
        "tags",
        "summary",
        "discussion",
        "ticloud",
        "aliases",
    ]
    if not is_hash:
        sha256 = target if len(target) == 64 else File(target).get_sha256()
    else:
        sha256 = target
    full_report_lookup = {"hash_values": [sha256], "report_fields": report_fields}
    try:
        r = requests.post(
            url=processing_conf.reversinglabs.url + "/api/samples/v2/list/details/",
            headers=_headers,
            data=json.dumps(full_report_lookup),
        )
    except requests.exceptions.RequestException as e:
        return {
            "error": True,
            "msg": f"Unable to complete connection to Reversing Labs: {e}",
        }

    reversing_labs_response = r.json()
    if r.status_code != 200:
        return {
            "error": True,
            "msg": f"Unable to complete lookup to Reversing Labs: {r.json().get('message')}",
        }
    if not reversing_labs_response.get("results"):
        return {"error": True, "msg": "No results found."}
    results = reversing_labs_response["results"][0]
    # most_recent_scan_engines = results["av_scanners"][-1]

    scanner_summary = results["av_scanners_summary"]
    sample_summary = results["sample_summary"]
    ticloud = results["ticloud"]
    ticore = results["ticore"]

    scanner_total = scanner_summary["scanner_count"]
    scanner_evil = scanner_summary["scanner_match"]
    classification = sample_summary["classification"]
    classification_result = sample_summary["classification_result"]
    file = ticore["info"]["file"]
    malicious = classification in ("malicious", "suspicious") and sample_summary["goodware_override"] is False
    md5 = sample_summary["md5"]
    sha1 = sample_summary["sha1"]
    sha256 = sample_summary["sha256"]
    riskscore = ticloud["riskscore"]
    name = file["proposed_filename"]
    # entropy = file["entropy"]
    story = ticore["story"]

    reversing_labs = {
        "name": name,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "malicious": malicious,
        "classification": classification,
        "classification_result": classification_result,
        "riskscore": riskscore,
        "detected": scanner_evil,
        "total": scanner_total,
        "story": story,
        "permalink": os.path.join(processing_conf.reversinglabs.url, sha256),
    }

    return reversing_labs


class ReversingLabs(Processing):
    def run(self):
        self.key = "reversinglabs"

        if not processing_conf.reversinglabs.key:
            raise CuckooProcessingError("ReversingLabs API key not configured, skipping")
        if self.task["category"] not in ("file", "static"):
            return {}

        target = self.task["target"]
        log.debug("Looking up: %s", target)
        reversing_labs_response = reversing_labs_lookup(target)
        if "error" in reversing_labs_response:
            raise CuckooProcessingError(reversing_labs_response["msg"])
        return reversing_labs_response
