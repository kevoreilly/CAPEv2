# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# Imports for the batch sort.
# http://stackoverflow.com/questions/10665925/how-to-sort-huge-files-with-python
# http://code.activestate.com/recipes/576755/

import logging
import os
import shutil
import subprocess
import sys
import tempfile


from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists

# required to work webgui
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..")
sys.path.append(CUCKOO_ROOT)

log = logging.getLogger(__name__)
cfg = Config()
polarproxy_cfg = Config("polarproxy")


def run_subprocess(command_args, shell=False):
    """Execute the subprocess, wait for completion.

    Return the exitcode (returncode), the stdout, and the stderr.
    """
    p = subprocess.Popen(
        args=command_args,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = p.communicate()
    return p.returncode, stdout, stderr


class PolarProxyProcessor(Processing):
    """Network analysis."""

    key = "polarproxy"
    order = 1

    def run(self):
        if not path_exists(self.pcap_path):
            log.debug('The PCAP file does not exist at path "%s"', self.pcap_path)
            return {}

        tls_pcap_path = os.path.join(self.analysis_path, "polarproxy", "tls.pcap")
        if not path_exists(tls_pcap_path):
            log.debug('The TLS PCAP file does not exist at path "%s"', tls_pcap_path)
            return {}

        if not path_exists(polarproxy_cfg.cfg.mergecap):
            log.debug('The mergecap application does not exist at path "%s"', polarproxy_cfg.cfg.mergecap)
            return {}

        temp_dir = tempfile.TemporaryDirectory()

        tmp_pcap = os.path.join(temp_dir.name, "tmp.pcap")

        ret, stdout, stderr = run_subprocess([
            polarproxy_cfg.cfg.mergecap,
            # Make snaplen consistent across all packets so wireshark doesn't freak out
            "-s", "262144",
            # Use pcap format instead of pcapng for Snort
            "-F", "pcap",
            # Destination file
            "-w", tmp_pcap,
            # Input files
            self.pcap_path,
            tls_pcap_path
        ])

        if ret == 0:
            log.info("Creating PCAP with decrypted TLS streams")
            shutil.move(tmp_pcap, self.pcap_path)
        else:
            log.warning("Failed to merge pcaps: %s", stderr.decode())

        results = {"pcap_sha256": File(self.pcap_path).get_sha256()}
        return results
