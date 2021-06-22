# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
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
            only_stap = [fn for fn in os.listdir(p) if fn.startswith("stap_") and fn.endswith(".ko")]
            if only_stap:
                return os.path.join(p, only_stap[0])
            return False

        path_cfg = self.config.get("analyzer_stap_path", None)
        if path_cfg and os.path.exists(path_cfg):
            path = path_cfg
        elif os.path.exists("/root/.cuckoo") and has_stap("/root/.cuckoo"):
            path = has_stap("/root/.cuckoo")
        elif os.path.exists("/root/.cape") and has_stap("/root/.cape"):
            path = has_stap("root/.cape")
        else:
            log.warning("Could not find STAP LKM, aborting systemtap analysis.")
            return False

        stap_start = time.time()
        self.proc = subprocess.Popen(["staprun", "-vv", "-x", str(os.getpid()), "-o", "stap.log", path,], stderr=subprocess.PIPE)

        while "systemtap_module_init() returned 0" not in self.proc.stderr.readline().decode("utf8"):
            pass

        self.proc.terminate()
        self.proc.wait()

        stap_stop = time.time()
        log.info("STAP aux module startup took %.2f seconds" % (stap_stop - stap_start))
        return True

    def stop(self):
        try:
            r = self.proc.poll()
            log.debug("stap subprocess retval %r", r)
            self.proc.kill()
        except Exception as e:
            log.warning("Exception killing stap: %s", e)

        upload_to_host("stap.log", "stap/stap.log", False)
