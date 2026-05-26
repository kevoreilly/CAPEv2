import binascii
import json
import logging
import os
import tempfile

from lib.common.results import upload_buffer_to_host, upload_to_host
from lib.common.etw_utils import (
    ETWAuxiliaryWrapper,
    ETWProviderWrapper,
    HAVE_ETW,
    ProviderInfo,
    GUID,
)

log = logging.getLogger(__name__)


if HAVE_ETW:

    class AMSIETWProvider(ETWProviderWrapper):
        def __init__(
            self,
            logfile=None,
            upload_prefix="aux/amsi_etw",
            upload_assemblies=False,
            ring_buf_size=1024,
            max_str_len=1024,
            min_buffers=0,
            max_buffers=0,
            filters=None,
        ):
            self.upload_prefix = upload_prefix
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

            super().__init__(
                session_name="ETW_AMSI",
                providers=providers,
                event_id_filters=[1101],
                ring_buf_size=ring_buf_size,
                max_str_len=max_str_len,
                min_buffers=min_buffers,
                max_buffers=max_buffers,
                filters=filters,
                logfile=logfile,
            )

        def on_event(self, event_tufo):
            event_id, event = event_tufo
            content = event.pop("content", None)
            if content:
                dump_path = f"{self.upload_prefix}/{event['hash'][2:].lower()}"
                try:
                    decoded_content = binascii.unhexlify(content[2:])
                    if event.get("appname", "") in ("DotNet", "coreclr"):
                        # The content is the full in-memory .NET assembly PE.
                        if self.upload_assemblies:
                            event["dump_path"] = dump_path + ".bin"
                            upload_buffer_to_host(decoded_content, event["dump_path"])
                        else:
                            log.debug(
                                "Skipping upload of %d byte CLR assembly - amsi_etw_assemblies option was not set",
                                len(decoded_content),
                            )
                    else:
                        # The content is UTF-16 encoded text. We'll store it as utf-8, just like all other text files.
                        decoded_content = decoded_content.decode(
                            "utf-16", errors="replace"
                        ).encode("utf-8")
                        event["dump_path"] = dump_path + ".txt"
                        upload_buffer_to_host(decoded_content, event["dump_path"])
                except Exception as e:
                    log.error("Error processing AMSI event content: %s", e)

            if self.logfile:
                # Write the event metadata as a line in the jsonl log file.
                json.dump(event, self.logfile)
                self.logfile.write("\n")


class AMSI_ETW(ETWAuxiliaryWrapper):
    """ETW logging"""

    def __init__(self, options, config):
        super().__init__(options, config, "amsi_etw")

        self.upload_prefix = "aux/amsi_etw"
        self.upload_assemblies = options.get("amsi_etw_assemblies", False)
        if self.upload_assemblies:
            log.debug("Will upload Dotnet assembly content")
        else:
            log.debug("Will discard Dotnet assembly content")

        if HAVE_ETW and self.enabled:
            self.log_file = tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", delete=False
            )
            self.capture = AMSIETWProvider(
                logfile=self.log_file,
                upload_prefix=self.upload_prefix,
                upload_assemblies=self.upload_assemblies,
            )

    def upload_results(self):
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
            if self.log_file and os.path.exists(self.log_file.name):
                os.unlink(self.log_file.name)
            self.log_file = None
