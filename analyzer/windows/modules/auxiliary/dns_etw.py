import json
import logging
import os
import pprint
from collections.abc import Iterable, Mapping

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host
from lib.core.config import Config

log = logging.getLogger(__name__)

SAFELIST = []

ETW = False
HAVE_ETW = False
try:
    from etw import ETW, ProviderInfo
    from etw import evntrace as et
    from etw.GUID import GUID

    HAVE_ETW = True
except ImportError as e:
    log.debug(
        "Could not load auxiliary module DNS_ETW due to '%s'\nIn order to use DNS_ETW functionality, it "
        "is required to have pywintrace setup in python", str(e)
    )

__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"


def encode(data, encoding="utf-8"):
    if isinstance(data, str):
        return data.encode(encoding, "ignore")
    elif isinstance(data, Mapping):
        return dict(map(encode, data.items()))
    elif isinstance(data, Iterable):
        return type(data)(map(encode, data))
    else:
        return data


if HAVE_ETW:

    class ETW_provider(ETW):
        def __init__(
            self,
            ring_buf_size=1024,
            max_str_len=1024,
            min_buffers=0,
            max_buffers=0,
            level=et.TRACE_LEVEL_INFORMATION,
            any_keywords=None,
            all_keywords=None,
            filters=None,
            event_callback=None,
            logfile=None,
            no_conout=False,
        ):
            """
            Initializes an instance of DNS_ETW. The default parameters represent a very typical use case and should not be
            overridden unless the user knows what they are doing.

            :param ring_buf_size: The size of the ring buffer used for capturing events.
            :param max_str_len: The maximum length of the strings the proceed the structure.
                                Unless you know what you are doing, do not modify this value.
            :param min_buffers: The minimum number of buffers for an event tracing session.
                                Unless you know what you are doing, do not modify this value.
            :param max_buffers: The maximum number of buffers for an event tracing session.
                                Unless you know what you are doing, do not modify this value.
            :param level: Logging level
            :param any_keywords: List of keywords to match
            :param all_keywords: List of keywords that all must match
            :param filters: List of filters to apply to capture.
            :param event_callback: Callback for processing events
            :param logfile: Path to logfile.
            :param no_conout: If true does not output live capture to console.
            """

            self.logfile = logfile
            self.no_conout = no_conout
            if event_callback:
                self.event_callback = event_callback
            else:
                self.event_callback = self.on_event

            providers = [
                ProviderInfo(
                    "Microsoft-Windows-DNS-Client",
                    GUID("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"),
                    level,
                    any_keywords,
                    all_keywords,
                )
            ]
            self.event_id_filters = [3010, 3020, 60101]
            super().__init__(
                session_name="ETW_DNS",
                ring_buf_size=ring_buf_size,
                max_str_len=max_str_len,
                min_buffers=min_buffers,
                max_buffers=max_buffers,
                event_callback=self.event_callback,
                task_name_filters=filters,
                providers=providers,
                event_id_filters=self.event_id_filters,
            )

        def on_event(self, event_tufo):
            """
            Starts the capture using ETW.
            :param event_tufo: tufo containing event information
            :param logfile: Path to logfile.
            :param no_conout: If true does not output live capture to console.
            :return: Does not return anything.
            """
            event_id, event = event_tufo
            # We can filter events based on whatever criteria here in event_tufo/event/event_id
            if event_id not in self.event_id_filters:
                return
            if self.no_conout is False:
                log.info("%d (%s)\n%s\n", event_id, event["Task Name"], pprint.pformat(encode(event)))
            if event["QueryName"] in SAFELIST:
                return
            # Event 3010 query
            # Pid --> event["EventHeader"]["ProcessId"]
            # threadid --> event["EventHeader"]["ThreadId"]
            # queryname --> event["QueryName"]
            # dnsserveraddress --> event["DnsServerIpAddress"]
            # Event 3020 response
            # Pid --> event["EventHeader"]["ProcessId"]
            # threadid --> event["EventHeader"]["ThreadId"]
            # queryname --> event["QueryName"]
            if self.logfile is not None:
                with open(self.logfile, "a") as file:
                    if event_id == 3010:
                        printed_events = {
                            "QueryType": "Query",
                            "ProcessId": event["EventHeader"]["ProcessId"],
                            "ThreadId": event["EventHeader"]["ThreadId"],
                            "QueryName": event["QueryName"],
                            "DNS Server": event["DnsServerIpAddress"],
                        }
                        json.dump(printed_events, file)
                        file.write("\n")
                    elif event_id == 3020:
                        printed_events = {
                            "QueryType": "Response",
                            "ProcessId": event["EventHeader"]["ProcessId"],
                            "ThreadId": event["EventHeader"]["ThreadId"],
                            "QueryName": event["QueryName"],
                        }
                        json.dump(printed_events, file)
                        file.write("\n")
                    else:
                        json.dump(event, file)
                        file.write("\n")

        def start(self):
            # do pre-capture setup
            self.do_capture_setup()
            super().start()

        def stop(self):
            super().stop()
            # do post-capture teardown
            self.do_capture_teardown()

        def do_capture_setup(self):
            # do whatever setup for capture here
            pass

        def do_capture_teardown(self):
            # do whatever for capture teardown here
            pass

    class DNS_ETW(Auxiliary):
        """ETW logging"""

        def __init__(self, options, config):
            Auxiliary.__init__(self, options, config)
            self.config = Config(cfg="analysis.conf")
            self.enabled = self.config.dns_etw
            self.do_run = self.enabled

            self.output_dir = "C:\\etw_dns\\"
            try:
                os.mkdir(self.output_dir)
            except FileExistsError:
                pass

            self.log_file = os.path.join(self.output_dir, "dns_provider.log")
            if HAVE_ETW:
                self.capture = ETW_provider(logfile=self.log_file, level=255, no_conout=True)

        def start(self):
            if not self.enabled or not HAVE_ETW:
                return False
            try:
                log.debug("Starting DNS ETW")
                # Start DNS_ETW_provider in the background
                self.capture.start()
            except Exception as e:
                print(e)
                import traceback

                log.exception(traceback.format_exc())
            return True

        def stop(self):
            if not HAVE_ETW:
                return
            log.debug("Stopping DNS_ETW...")
            self.capture.stop()
            files_to_upload = set()

            for d in os.listdir(self.output_dir):
                path = os.path.join(self.output_dir, d)
                if os.path.isfile(path):
                    files_to_upload.add(path)
                    continue
                for f in os.listdir(path):
                    file_path = os.path.join(path, f)
                    files_to_upload.add(file_path)
                continue

            # Upload the ETW log files to the host.
            log.debug(files_to_upload)
            for f in files_to_upload:
                # Prepend file name with etw to indicate DNS_ETW
                # file_path_list = f.split("\\")
                # file_name = file_path_list[-1]
                # process = file_path_list[-2]
                dumppath = os.path.join("DNS_ETW", "etw_dns.json")
                log.debug("DNS_ETW Aux Module is uploading %s", f)
                upload_to_host(f, dumppath)
