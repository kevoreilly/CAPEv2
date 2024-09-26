import logging
import os
import subprocess
import tempfile
from threading import Thread
import time

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host


log = logging.getLogger(__name__)


class Browsermonitor(Auxiliary, Thread):
    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.do_run = False
        self.enabled = config.browsermonitor
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self.browser_logfile = ''
        self.last_modification = 0.0
        self._is_first_save = True

    def _find_browser_extension(self):
        log.debug("find_browser_extension start")
        temp_dir = tempfile.gettempdir()
        log.debug(temp_dir)
        while not self.browser_logfile and self.do_run:
            temp_dir_list = os.listdir(temp_dir)
            for directory in temp_dir_list:
                tmp_directory = os.path.join(temp_dir, directory)
                if not os.path.isdir(tmp_directory):
                    continue
                if not directory.startswith('tmp'):
                    continue
                tmp_dir_files = os.listdir(tmp_directory)
                for file in tmp_dir_files:
                    if file.startswith('bext_') and file.endswith('.json'):
                        self.browser_logfile = os.path.join(temp_dir, directory, file)
                        log.debug(f'Found extension logs: {self.browser_logfile}')
                        break
            time.sleep(1)

    def _collect_browser_logs(self):
        if (not self._is_first_save and
            self.last_modification != os.path.getmtime(self.browser_logfile)):
            return
        self.last_modification = os.path.getmtime(self.browser_logfile)
        upload_to_host(self.browser_logfile, 'browser/requests.log')
        self._is_first_save = False

    def run(self):
        self.do_run = True
        if self.enabled:
            self._find_browser_extension()
            self.last_modification = os.path.getmtime(self.browser_logfile)
            log.debug(f'last modification: {self.last_modification}')
            while self.do_run:
                self._collect_browser_logs()
                time.sleep(1)
            return True
        return False

    def stop(self):
        if self.enabled:
            self.do_run = False
            if self.browser_logfile:
                self._collect_browser_logs()
        return True