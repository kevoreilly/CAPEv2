import json
import logging
import os
import pprint

from lib.common.results import upload_to_host
from lib.common.rand import random_string
from lib.common.etw_utils import (
    ETWAuxiliaryWrapper,
    ETWProviderWrapper,
    HAVE_ETW,
    ProviderInfo,
    GUID,
    et,
    encode,
)

log = logging.getLogger(__name__)

SAFELIST = []

__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"


if HAVE_ETW:

    class DNSETWProvider(ETWProviderWrapper):
        def __init__(
            self,
            level=et.TRACE_LEVEL_INFORMATION,
            logfile=None,
            no_conout=False,
            any_keywords=None,
            all_keywords=None,
        ):
            providers = [
                ProviderInfo(
                    "Microsoft-Windows-DNS-Client",
                    GUID("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"),
                    level,
                    any_keywords,
                    all_keywords,
                )
            ]
            super().__init__(
                session_name="ETW_DNS",
                providers=providers,
                event_id_filters=[3010, 3020, 60101],
                logfile=logfile,
                no_conout=no_conout,
            )

        def on_event(self, event_tufo):
            # We override on_event because of the specific filtering and SAFELIST check
            event_id, event = event_tufo

            if event_id not in self.event_id_filters:
                return

            if not self.no_conout:
                log.info(
                    "%d (%s)\n%s\n",
                    event_id,
                    event.get("Task Name", ""),
                    pprint.pformat(encode(event)),
                )

            if event.get("QueryName") in SAFELIST:
                return

            if self.logfile:
                self.write_to_log(self.logfile, event_id, event)

        def write_to_log(self, file_handle, event_id, event):
            if event_id == 3010:
                printed_events = {
                    "QueryType": "Query",
                    "ProcessId": event["EventHeader"]["ProcessId"],
                    "ThreadId": event["EventHeader"]["ThreadId"],
                    "QueryName": event["QueryName"],
                    "DNS Server": event["DnsServerIpAddress"],
                }
                json.dump(printed_events, file_handle)
                file_handle.write("\n")
            elif event_id == 3020:
                printed_events = {
                    "QueryType": "Response",
                    "ProcessId": event["EventHeader"]["ProcessId"],
                    "ThreadId": event["EventHeader"]["ThreadId"],
                    "QueryName": event["QueryName"],
                }
                json.dump(printed_events, file_handle)
                file_handle.write("\n")
            else:
                json.dump(event, file_handle)
                file_handle.write("\n")


class DNS_ETW(ETWAuxiliaryWrapper):
    """ETW logging"""

    def __init__(self, options, config):
        super().__init__(options, config, "dns_etw")

        self.output_dir = os.path.join("C:\\", random_string(5, 10))
        try:
            os.mkdir(self.output_dir)
        except FileExistsError:
            pass

        log_file_path = os.path.join(self.output_dir, f"{random_string(5, 10)}.log")
        self.log_file = None

        if HAVE_ETW and self.enabled:
            try:
                self.log_file = open(log_file_path, "w", encoding="utf-8")
                self.capture = DNSETWProvider(
                    logfile=self.log_file, level=255, no_conout=True
                )
            except Exception as e:
                log.error("Failed to open DNS ETW log file: %s", e)

    def upload_results(self):
        if self.log_file:
            try:
                self.log_file.close()
            except Exception as e:
                log.error("Failed to close DNS ETW log file: %s", e)
            self.log_file = None

        files_to_upload = set()
        if os.path.exists(self.output_dir):
            for d in os.listdir(self.output_dir):
                path = os.path.join(self.output_dir, d)
                if os.path.isfile(path):
                    files_to_upload.add(path)
                    continue
                for f in os.listdir(path):
                    file_path = os.path.join(path, f)
                    files_to_upload.add(file_path)

        log.debug(files_to_upload)
        for f in files_to_upload:
            dumppath = os.path.join("aux", "dns_etw.json")
            log.debug("DNS_ETW Aux Module is uploading %s", f)
            upload_to_host(f, dumppath)
