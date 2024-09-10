import logging
import os
import tempfile

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

SSLKEYLOGFILE = "SSLKEYLOGFILE"


class SslKeyLogFile(Auxiliary):
    """Collect SSLKEYLOGFILE logs from guests."""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.sslkeylogfile
        if self.enabled:
            self.upload_prefix = "aux/sslkeylogfile"
            self.upload_file = "sslkeys.log"
            self.log_path = ""

    def upload_sslkeylogfile(self):
        """Upload SSLKEYLOGFILE log to the host if present."""
        try:
            if self.log_path and os.path.isfile(self.log_path):
                log.debug('Attemping to upload SSLKEYLOGFILE from "%s"', self.log_path)
                upload_to_host(self.log_path, f"{self.upload_prefix}/{self.upload_file}")
                log.debug("SSLKEYLOGFILE uploaded")
        except Exception:
            log.exception("SslKeyLogFile encountered an exception while uploading '%s'", self.log_path)
            raise

    def start(self):
        if not self.enabled:
            log.debug("SslKeyLogFile auxiliary module not enabled")
            return
        log.info("SslKeyLogFile auxiliary module enabled")
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as keylog:
            # Set SSLKEYLOGFILE system environment variable
            log.info("Setting %s to %s", SSLKEYLOGFILE, keylog.name)
            # Set system env
            xcode = os.system("Setx {0} {1} /m".format(SSLKEYLOGFILE, keylog.name))
            # Update local process env
            os.environ[SSLKEYLOGFILE] = keylog.name

            if xcode != 0:
                log.info("Failed to set %s", SSLKEYLOGFILE)

            self.log_path = keylog.name

    def finish(self):
        if self.enabled:
            self.upload_sslkeylogfile()
