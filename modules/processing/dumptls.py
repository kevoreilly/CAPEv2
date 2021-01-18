# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import logging
import binascii
from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

class TLSMasterSecrets(Processing):
    """Cross-references TLS master secrets extracted from the monitor and key
    information extracted from the PCAP to dump a master secrets file
    compatible with, e.g., Wireshark."""

    order = 3
    key = "dumptls"

    def run(self):
        metakeys = {}

        # Build server random <-> session id mapping from the PCAP.
        for row in self.results.get("network", {}).get("tls", []) or []:
            metakeys[row["server_random"]] = row["session_id"]

        results = {}
        dump_tls_log = os.path.join(self.analysis_path, "tlsdump", "tlsdump.log")
        if not os.path.exists(dump_tls_log):
            return results

        for entry in open(dump_tls_log, "r").readlines() or []:
            client_random, server_random, master_secret = entry.split(",")
            client_random = binascii.a2b_hex(client_random.split(":")[-1].strip())
            server_random = binascii.a2b_hex(server_random.split(":")[-1].strip())
            master_secret = binascii.a2b_hex(master_secret.split(":")[-1].strip())

            if server_random not in metakeys:
                log.debug("Was unable to extract TLS master secret for server random %s, skipping it.", server_random)
                continue

            results[metakeys[server_random]] = master_secret

        if results:
            # Write the TLS master secrets file.
            with open(self.tlsmaster_path, "w") as f:
                for session_id, master_secret in sorted(results.items()):
                    f.write("RSA Session-ID:{session_id} Master-Key:{master_secret}")
