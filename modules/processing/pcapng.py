import logging

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.pcap_utils import PcapToNg, file_exists_not_empty, is_pcapng
from pathlib import Path

log = logging.getLogger(__name__)


class PcapNg(Processing):
    """Generate a pcapng file during processing."""

    key = "pcapng"

    def set_path(self, analysis_path: str) -> None:
        """Set paths.
        @param analysis_path: analysis folder path.
        """
        super().set_path(analysis_path)
        self.tlsdump_log = Path(analysis_path) / "tlsdump" / "tlsdump.log"
        self.sslkeys_log = Path(analysis_path) / "aux" / "sslkeylogfile" / "sslkeys.log"
        self.pcapng_path = Path(self.pcap_path + "ng")

    def run(self) -> dict[str, str | None]:
        PcapToNg(self.pcap_path, self.tlsdump_log, self.sslkeys_log).generate(self.pcapng_path)
        if not file_exists_not_empty(self.pcapng_path):
            log.warning("pcapng file was not created: %s", self.pcapng_path)
            return {}
        if not is_pcapng(self.pcapng_path):
            log.warning("generated pcapng file is not valid: %s", self.pcapng_path)
            return {}
        return {"sha256": File(str(self.pcapng_path)).get_sha256()}
