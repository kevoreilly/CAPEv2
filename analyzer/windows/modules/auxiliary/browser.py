# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import time
from threading import Thread

from lib.api.process import Process
from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)


class Browser(Auxiliary, Thread):
    """Launch a browser 30 seconds into the analysis"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.enabled = config.browser
        self.do_run = self.enabled
        self.seconds_elapsed = 0

    def stop(self):
        self.do_run = False

    def run(self):
        self.do_run = self.options.get("startbrowser", False)
        url = self.options.get("url")
        browserdelay = int(self.options.get("browserdelay", 30))
        while self.do_run:
            time.sleep(1)
            self.seconds_elapsed += 1
            if self.seconds_elapsed == browserdelay:
                iexplore = os.path.join(os.getenv("ProgramFiles"), "Internet Explorer", "iexplore.exe")
                ie = Process()
                if not url:
                    url = "https://www.yahoo.com/"
                ie.execute(path=iexplore, args=f'"{url}"', suspended=False)
                ie.close()
