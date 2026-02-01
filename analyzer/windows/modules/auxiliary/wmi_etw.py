import logging
import os

from lib.common.results import upload_to_host
from lib.common.etw_utils import (
    ETWAuxiliaryWrapper,
    ETWProviderWrapper,
    HAVE_ETW,
    ProviderInfo,
    GUID,
    et,
)

log = logging.getLogger(__name__)

__author__ = "[Andrea Oliveri starting from code of Canadian Centre for Cyber Security]"


if HAVE_ETW:

    class WMIETWProvider(ETWProviderWrapper):
        def __init__(
            self,
            level=et.TRACE_LEVEL_INFORMATION,
            logfile=None,
            no_conout=False,
        ):
            providers = [
                ProviderInfo(
                    "Microsoft-Windows-WMI-Activity",
                    GUID("{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}"),
                    level,
                )
            ]
            super().__init__(
                session_name="WMI_ETW",
                providers=providers,
                ring_buf_size=4096,
                max_str_len=4096,
                logfile=logfile,
                no_conout=no_conout,
            )


class WMI_ETW(ETWAuxiliaryWrapper):
    """ETW logging"""

    def __init__(self, options, config):
        super().__init__(options, config, "wmi_etw")

        self.output_dir = "C:\\wmi\\"
        try:
            os.mkdir(self.output_dir)
        except Exception as e:
            log.debug(e)

        self.log_file = os.path.join(self.output_dir, "wmi_provider.log")

        if HAVE_ETW and self.enabled:
            self.capture = WMIETWProvider(
                logfile=self.log_file, level=255, no_conout=True
            )

    def upload_results(self):
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
            dumppath = os.path.join("aux", "wmi_etw.json")
            log.debug("WMI_ETW Aux Module is uploading %s", f)
            upload_to_host(f, dumppath)

