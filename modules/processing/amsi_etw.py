import datetime
import json
import logging
import os

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)


class AMSI_ETW(Processing):
    key = "amsi_etw"

    def run(self):
        jsonl_file = os.path.join(self.aux_path, "amsi_etw", "amsi.jsonl")
        if not os.path.exists(jsonl_file) or os.stat(jsonl_file).st_size == 0:
            return None

        result = []
        with open(jsonl_file, "r") as fil:
            idx = 0
            for idx, line in enumerate(fil, 1):
                try:
                    decoded = self.decode_event(json.loads(line))
                except Exception:
                    log.exception("Failed to process line %d of %s.", idx, jsonl_file)
                    break
                result.append(decoded)
            log.info("Processed %d AMSI event{'s' if idx != 1 else ''}.", idx)

        return result

    @classmethod
    def decode_event(cls, event):
        header = event["EventHeader"]
        return {
            # From https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea
            # The timestamp is stored as "100-nanosecond intervals since midnight, January 1, 1601"
            "timestamp": (
                datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
                + datetime.timedelta(seconds=header["TimeStamp"] / 10_000_000)
            ).isoformat(),
            "thread_id": header["ThreadId"],
            "process_id": header["ProcessId"],
            "provider_id": header["ProviderId"],
            "kernel_time": header["KernelTime"],
            "user_time": header["UserTime"],
            "activity_id": header["ActivityId"],
            "scan_result": cls.scan_result_to_str(int(event["scanResult"])),
            "app_name": event["appname"],
            "content_name": event["contentname"],
            "content_filtered": event["contentFiltered"],
            "content_size": int(event["contentsize"]),
            "dump_path": event.get("dump_path", ""),
            "hash": event["hash"][2:].lower(),
        }

    @staticmethod
    def scan_result_to_str(val: int) -> str:
        # Based off of https://redcanary.com/blog/amsi/
        if val == 0:
            return "clean"
        elif val == 1:
            return "not_detected"
        elif val == 0x8000:
            return "detected"
        elif val & 0x4000:
            return "blocked_by_admin"
        else:
            return "unknown"
