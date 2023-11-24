# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import logging
import os
from contextlib import suppress

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

HAVE_CLAMAV = False
CLAMAV_ENABLED = Config("processing").detections.clamav

if CLAMAV_ENABLED:
    with suppress(ImportError):
        import pyclamd

        HAVE_CLAMAV = True


def get_clamav(file_path):
    """Get ClamAV signatures matches.
    Enable in: processing -> [CAPE] -> clamav

    Requires pyclamd module. Additionally if running with apparmor, an exception must be made.
    apt-get install clamav clamav-daemon clamav-freshclam clamav-unofficial-sigs -y
    poetry run pip install -U pyclamd
    systemctl enable clamav-daemon
    systemctl start clamav-daemon
    usermod -a -G cape clamav
    echo "/opt/CAPEv2/storage/** r," | sudo tee -a /etc/apparmor.d/local/usr.sbin.clamd
    @return: matched ClamAV signatures.
    """
    matches = []

    if HAVE_CLAMAV and os.path.getsize(file_path) > 0:
        try:
            cd = pyclamd.ClamdUnixSocket()
            results = cd.allmatchscan(file_path)
            if results:
                for entry in results[file_path]:
                    if entry[0] == "FOUND" and entry[1] not in matches:
                        matches.append(entry[1])
        except ConnectionError:
            log.warning("failed to connect to clamd socket")
        except Exception as e:
            log.warning("failed to scan file with clamav %s", e)

    return matches
