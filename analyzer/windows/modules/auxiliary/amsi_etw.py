"""
This module captures AMSI events via ETW, uploading script contents (powershell, WMI, macros, etc)
to aux/amsi_etw and saving trace details to be reported by the amsi_etw processing module.

It is a reimplementation of the SecureWorks amsi_collector and amsi modules, adapted to
use the CCCS event tracing module format.

Installation of the pywintrace python library on the guest is mandatory.
Setting the option 'amsi_etw_assemblies=1' during tasking will cause full CLR assemblies
to be collected as well.
"""
import json
import logging
import os
import tempfile
import binascii

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_buffer_to_host, upload_to_host
from lib.core.config import Config

log = logging.getLogger(__name__)

ETW = False
HAVE_ETW = False
try:
    from etw import ETW, ProviderInfo
    from etw.GUID import GUID

    HAVE_ETW = True
except ImportError as e:
    log.debug(
        "Could not load auxiliary module AMSI_ETW due to '%s'\nIn order to use AMSI_ETW functionality, it "
        "is required to have pywintrace setup in python", str(e)
    )

if HAVE_ETW:

    class ETW_provider(ETW):
        def __init__(
            self,
            ring_buf_size=1024,
            max_str_len=1024,
            min_buffers=0,
            max_buffers=0,
            filters=None,
            event_callback=None,
            logfile=None,
            upload_prefix="aux/amsi_etw",
            upload_assemblies=False
        ):
            """
            Initializes an instance of AMSI_ETW. The default parameters represent a very typical use case and should not be
            overridden unless the user knows what they are doing.

            :param ring_buf_size: The size of the ring buffer used for capturing events.
            :param max_str_len: The maximum length of the strings the proceed the structure.
                                Unless you know what you are doing, do not modify this value.
            :param min_buffers: The minimum number of buffers for an event tracing session.
                                Unless you know what you are doing, do not modify this value.
            :param max_buffers: The maximum number of buffers for an event tracing session.
                                Unless you know what you are doing, do not modify this value.
            :param filters: List of filters to apply to capture.
            :param logfile: Path to logfile.
            :param upload_prefix: Path to upload results to. Must be approved in resultserver.py.
            :param upload_assemblies: Whether to also upload the content of dotnet assemblies.
            """
            self.upload_prefix = upload_prefix
            self.log_file = logfile
            self.event_callback = self.on_event
            self.upload_assemblies = upload_assemblies

            providers = [
                ProviderInfo(
                    "AMSI",
                    GUID("{2A576B87-09A7-520E-C21A-4942F0271D67}"),
                    level=255,
                    any_keywords=None,
                    all_keywords=None,
                )
            ]
            self.event_id_filters = [1101]
            super().__init__(
                session_name="ETW_AMSI",
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
            :return: Does not return anything.
            """
            event_id, event = event_tufo
            content = event.pop("content", None)
            if content:
                dump_path = f"{self.upload_prefix}/{event['hash'][2:].lower()}"
                decoded_content = binascii.unhexlify(content[2:])
                if event.get("appname", "") in ("DotNet", "coreclr"):
                    # The content is the full in-memory .NET assembly PE.
                    if self.upload_assemblies:
                        event['dump_path'] =  dump_path+".bin"
                        upload_buffer_to_host(decoded_content, event['dump_path'])
                    else:
                        log.debug("Skipping upload of %d byte CLR assembly - amsi_etw_assemblies option was not set", len(decoded_content))
                else:
                    # The content is UTF-16 encoded text. We'll store it as utf-8, just like all other text files.
                    decoded_content = decoded_content.decode("utf-16", errors="replace").encode("utf-8")
                    event['dump_path'] =  dump_path+".txt"
                    upload_buffer_to_host(decoded_content, event['dump_path'])

            if self.log_file:
                # Write the event metadata as a line in the jsonl log file.
                json.dump(event, self.log_file)
                self.log_file.write("\n")

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

    class AMSI_ETW(Auxiliary):
        """ETW logging"""

        def __init__(self, options, config):
            Auxiliary.__init__(self, options, config)

            self.config = Config(cfg="analysis.conf")
            self.enabled = self.config.amsi_etw
            self.do_run = self.enabled
            self.upload_prefix = "aux/amsi_etw"
            self.upload_assemblies = options.get("amsi_etw_assemblies", False)
            if self.upload_assemblies:
                log.debug("Will upload Dotnet assembly content")
            else:
                log.debug("Will discard Dotnet assembly content")

            if HAVE_ETW:
                self.log_file = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
                self.capture = ETW_provider(logfile=self.log_file, upload_prefix=self.upload_prefix,
                    upload_assemblies=self.upload_assemblies)

        def start(self):
            if not self.enabled or not HAVE_ETW:
                return False
            try:
                log.debug("Starting AMSI ETW")
                # Start AMSI_ETW_provider in the background
                self.capture.start()
            except Exception as e:
                log.exception("An error occurred while starting AMSI ETW: %s", e)
            return True

        def stop(self):
            if not HAVE_ETW:
                return
            log.debug("Stopping AMSI_ETW...")
            self.capture.stop()

            """Upload the file that contains the metadata for all of the events."""
            if not self.log_file or not os.path.exists(self.log_file.name):
                log.debug("No logfile to upload")
                return
            self.log_file.close()

            try:
                if os.stat(self.log_file.name).st_size > 0:
                    upload_to_host(self.log_file.name, f"{self.upload_prefix}/amsi.jsonl")
                else:
                    log.debug("No AMSI events were collected.")
            except Exception:
                log.exception("Exception was raised while uploading amsi.jsonl")
                raise
            finally:
                os.unlink(self.log_file.name)
                self.log_file = None
