import glob
import logging
import os
import subprocess
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.core.config import Config

log = logging.getLogger(__name__)


class During_script(Thread, Auxiliary):
    # De-priortise during_script to run last in Auxiliary
    start_priority = -10

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config
        # Go to the temp folder to look for during_script.py
        tmp_folder = os.environ["TEMP"]
        matched_files = glob.glob(os.path.join(tmp_folder, "during_script.*"))

        # Check if the file exists and if the during_script is enabled
        if matched_files and self.enabled.during_script:
            log.debug("during_script matched_files: %s", matched_files)
            self.file_path = matched_files[0]
            self.file_ext = os.path.splitext(self.file_path)[-1]
            self.do_run = True
            if self.file_ext == ".py":
                self.executable = ["python.exe"]
            elif self.file_ext == ".ps1":
                self.executable = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "bypass", "-File"]
            else:
                self.executable = ["powershell.exe"]

            during_script_args = self.options.get("during_script_args", [])
            if during_script_args:
                try:
                    self.during_script_args_list = during_script_args.split(" ")
                except AttributeError:
                    self.during_script_args_list = during_script_args
            else:
                self.during_script_args_list = []
        else:
            self.do_run = False

    def start(self):
        if not self.do_run:
            return
        try:
            nf = NetlogFile()
            nf.init("logs/during_script.log")
            self.executable.append(self.file_path)
            if isinstance(self.during_script_args_list, list):
                for args in self.during_script_args_list:
                    self.executable.append(args)
            else:
                self.executable.append(self.during_script_args_list)
            log.info("During_script command: %s", " ".join(self.executable))
            popen = subprocess.Popen(self.executable, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            for stdout_line in iter(popen.stdout.readline, ""):
                nf.sock.send(stdout_line.encode())
            popen.stdout.close()
            nf.close()
            return_code = popen.wait()
            log.info("Running during_script, saved output to logs/during_script.logs")
            if return_code:
                log.error("Process stderr: %s", popen.stderr)
                raise subprocess.CalledProcessError(return_code, str(self.executable))
        except Exception as e:
            log.error("Error running during_script due to error: %s", e)
            return False
        return True

    def stop(self):
        self.do_run = False
