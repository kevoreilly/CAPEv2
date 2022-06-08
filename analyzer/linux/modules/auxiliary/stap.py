# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import subprocess
import time

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host
from lib.core.config import Config

log = logging.getLogger(__name__)


class STAP(Auxiliary):
    """System-wide syscall trace with stap."""

    priority = -10  # low prio to wrap tightly around the analysis

    def __init__(self, options={}, analyzer=None):
        self.config = Config(cfg="analysis.conf")
        self.proc = None

    def start(self):
        # helper function locating the stap module
        def has_stap(p):
            for fn in os.listdir(p):
                if fn.startswith("stap_") and fn.endswith(".ko"):
                    return os.path.join(p, fn)
            return False

        path_cfg = self.config.get("analyzer_stap_path")
        cuckoo_path = os.path.join("/root", ".cuckoo")
        cape_path = os.path.join("/root", ".cape")
        if path_cfg and os.path.exists(path_cfg):
            path = path_cfg
        elif os.path.exists(cuckoo_path) and has_stap(cuckoo_path):
            path = has_stap(cuckoo_path)
        elif os.path.exists(cape_path) and has_stap(cape_path):
            path = has_stap(cape_path)
        else:
            log.warning("Could not find STAP LKM, aborting systemtap analysis")
            return False

        stap_start = time.time()
        self.proc = subprocess.Popen(
            [
                "staprun",
                "-vv",
                "-x",
                str(os.getpid()),
                "-o",
                "stap.log",
                path,
            ],
            stderr=subprocess.PIPE,
        )

        while b"systemtap_module_init() returned 0" not in self.proc.stderr.readline():
            pass

        self.proc.terminate()
        self.proc.wait()

        stap_stop = time.time()
        log.info("STAP aux module startup took %.2f seconds", stap_stop - stap_start)
        return True

    def stop(self):
        try:
            r = self.proc.poll()
            log.debug("stap subprocess retval %d", r)
            self.proc.kill()
        except Exception as e:
            log.warning("Exception killing stap: %s", e)

        upload_to_host("stap.log", "stap/stap.log", False)
