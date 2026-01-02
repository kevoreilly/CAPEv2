# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import binascii
import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists

try:
    import re2 as re
except Exception:
    import re

log = logging.getLogger(__name__)


class TLSMasterSecrets(Processing):
    """Cross-references TLS master secrets extracted from the monitor and key
    information extracted from the PCAP to dump a master secrets file
    compatible with, e.g., Wireshark."""

    order = 3
    key = "dumptls"

    def run(self):
        # Build server random <-> session id mapping from the PCAP.
        metakeys = {row["server_random"]: row["session_id"] for row in self.results.get("network", {}).get("tls", [])}

        results = {}
        dump_tls_log = os.path.join(self.analysis_path, "tlsdump", "tlsdump.log")
        if not path_exists(dump_tls_log):
            return results

        with open(dump_tls_log, "r") as f:
            for entry in f:
                try:
                    for m in re.finditer(
                        r"client_random:\s*(?P<client_random>[a-f0-9]+)\s*,\s*server_random:\s*(?P<server_random>[a-f0-9]+)\s*,\s*master_secret:\s*(?P<master_secret>[a-f0-9]+)\s*",
                        entry,
                        re.I,
                    ):
                        try:
                            server_random = binascii.a2b_hex(m.group("server_random").strip())
                            master_secret = binascii.a2b_hex(m.group("master_secret").strip())
                            if server_random not in metakeys:
                                log.debug("Was unable to extract TLS master secret for server random %s, skipping it", server_random)
                                continue
                            results[metakeys[server_random]] = master_secret
                        except Exception as e:
                            log.warning("Problem dealing with tlsdump error: %s line: %s", e, m.group(0))
                except Exception as e:
                    log.warning("Problem dealing with tlsdump error: %s line: %s", e, entry)

        if results:
            # Write the TLS master secrets file.
            with open(self.tlsmaster_path, "w") as f:
                for session_id, master_secret in sorted(results.items()):
                    f.write(f"RSA Session-ID:{session_id} Master-Key:{master_secret}\n")
