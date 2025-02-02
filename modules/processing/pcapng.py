import logging
import os
import shutil
import subprocess
import tempfile

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists
from utils.tls import tlslog_to_sslkeylogfile

EDITCAP = "editcap"
EDITCAP_TIMEOUT = 60

log = logging.getLogger(__name__)


class PcapNg(Processing):
    """Injects TLS keys into a .pcap, resulting in a .pcapng file.

    Requires the `editcap` executable."""

    key = "pcapng"

    def set_path(self, analysis_path):
        """Set paths.
        @param analysis_path: analysis folder path.
        """
        super().set_path(analysis_path)
        # The file CAPE Monitor logs TLS keys to
        self.tlsdump_log = os.path.join(self.analysis_path, "tlsdump", "tlsdump.log")
        # The file logged to by libraries that support the SSLKEYLOGFILE env var
        self.sslkeys_log = os.path.join(self.analysis_path, "aux/sslkeylogfile", "sslkeys.log")
        self.pcapng_path = self.pcap_path + "ng"

    def run(self):
        retval = {}

        if not path_exists(self.pcap_path):
            log.debug('pcap not found, nothing to do "%s"', self.pcap_path)
            return retval

        if os.path.getsize(self.pcap_path) == 0:
            log.debug('pcap is empty, nothing to do "%s"', self.pcap_path)
            return retval

        if not shutil.which(EDITCAP):
            log.error("%s not in path and is required", EDITCAP)
            return retval

        try:
            failmsg = "failed to generate .pcapng"
            tls_dir = os.path.dirname(self.tlsdump_log)
            # Combine all TLS logs into a single file in a format that can be read by editcap
            with tempfile.NamedTemporaryFile("w", dir=tls_dir, encoding="utf-8") as dest_ssl_key_log:
                # Write CAPEMON keys
                if self.file_exists_not_empty(self.tlsdump_log):
                    log.debug("writing tlsdump.log to temp key log file")
                    tlslog_to_sslkeylogfile(self.tlsdump_log, dest_ssl_key_log.name)
                # Write SSLKEYLOGFILE keys
                if self.file_exists_not_empty(self.sslkeys_log):
                    log.debug("writing SSLKEYLOGFILE to temp key log file")
                    self.append_file_contents_to_file(self.sslkeys_log, dest_ssl_key_log.name)
                self.generate_pcapng(dest_ssl_key_log.name)
                retval = {"sha256": File(self.pcapng_path).get_sha256()}
        except subprocess.CalledProcessError as exc:
            log.error("%s: editcap exited with code: %d", failmsg, exc.returncode)
        except subprocess.TimeoutExpired:
            log.error("%s: editcap reached timeout", failmsg)
        except OSError as exc:
            log.error("%s: %s", failmsg, exc)

        return retval

    def file_exists_not_empty(self, path):
        return bool(path_exists(path) and os.path.getsize(path) > 0)

    def append_file_contents_to_file(self, file_with_contents, append_to_file):
        with open(file_with_contents, "r") as src, open(append_to_file, "a+") as dst:
            dst.write(src.read())

    def generate_pcapng(self, sslkeylogfile_path):
        # ToDo bail if file is empty
        cmd = [EDITCAP, "--inject-secrets", "tls," + sslkeylogfile_path, self.pcap_path, self.pcapng_path]
        log.debug("generating pcapng with command '%s", cmd)
        subprocess.check_call(cmd, timeout=EDITCAP_TIMEOUT)
