import os
import json

import requests
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

processing_conf = Config("processing")

KEY = processing_conf.reversinglabs.key
URL = processing_conf.reversinglabs.url

REVERSING_LABS_DETAILED_ANALYSIS_ENDPOINT = "/api/samples/v2/list/details/"


def reversing_labs_lookup(target: str):
    _headers = {
        "User-Agent": "Cuckoo Sandbox",
        "Content-Type": "application/json",
        "Authorization": "Token {token}".format(token=KEY),
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

    sha256 = target if len(target) == 64 else File(target).get_sha256()
    full_report_lookup = {"hash_values": [target], "report_fields": report_fields}
    try:
        r = requests.post(
            url=URL + REVERSING_LABS_DETAILED_ANALYSIS_ENDPOINT,
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
    most_recent_scan_engines = results["av_scanners"][-1]

    scanner_summary = results["av_scanners_summary"]
    sample_summary = results["sample_summary"]
    ticloud = results["ticloud"]
    ticore = results["ticore"]

    scanner_total = scanner_summary["scanner_count"]
    scanner_evil = scanner_summary["scanner_match"]
    classification = sample_summary["classification"]
    file = ticore["info"]["file"]
    malicious = (
        classification in ["malicious", "suspicious"]
        and sample_summary["goodware_override"] is False
    )
    md5 = sample_summary["md5"]
    sha1 = sample_summary["sha1"]
    sha256 = sample_summary["sha256"]
    riskscore = ticloud["riskscore"]
    name = file["proposed_filename"]
    entropy = file["entropy"]
    story = ticore["story"]

    reversing_labs = {
        "name": name,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "malicious": malicious,
        "classification": classification,
        "riskscore": riskscore,
        "detected": scanner_evil,
        "total": scanner_total,
        "story": story,
        "permalink": os.path.join(URL, sha256),
    }

    return reversing_labs


class ReversingLabs(Processing):
    def run(self):
        self.key = "reversinglabs"

        if not KEY:
            raise CuckooProcessingError("VirusTotal API key not configured, skipping")
        if self.task["category"] != "file":
            return {}

        target = self.task["target"]
        reversing_labs_response = reversing_labs_lookup(target)
        if "error" in reversing_labs_response:
            raise CuckooProcessingError(reversing_labs_response["msg"])
        return reversing_labs_response
