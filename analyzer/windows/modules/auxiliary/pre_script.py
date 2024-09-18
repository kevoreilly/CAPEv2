import glob
import logging
import os
import subprocess

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.core.config import Config

log = logging.getLogger(__name__)


class Pre_script(Auxiliary):
    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config
        tmp_folder = os.environ["TEMP"]
        try:
            self.prescript_detection = bool(self.options.get("prescript_detection", False))
        except ValueError:
            log.error("Invalid option for prescript_detection specified, defaulting to False")
            self.prescript_detection = False
        if self.prescript_detection:
            prescript_path = os.path.join(".", "prescripts")
            matched_files = [os.path.join(prescript_path, "prescript_detection.py")]
        else:
            # Go to the temp folder to look for pre_script.py
            matched_files = glob.glob(os.path.join(tmp_folder, "pre_script.*"))

        # Check if the file exists and if the pre_script is enabled
        if matched_files and self.enabled.pre_script:
            self.file_path = matched_files[0]
            self.file_ext = os.path.splitext(self.file_path)[-1]
            self.do_run = True

            log.debug("pre_script matched_files: %s", matched_files)
            # Try to retrieve timeout for pre_script_timeout (Default 60)
            try:
                self.timeout = int(self.options.get("pre_script_timeout", 60))
            except ValueError:
                log.error("Invalid timeout value specified, defaulting to 60 seconds")
                self.timeout = 60

            pre_script_args = self.options.get("pre_script_args", [])
            if pre_script_args:
                try:
                    self.pre_script_args_list = pre_script_args.split(" ")
                except AttributeError:
                    self.pre_script_args_list = pre_script_args
            else:
                self.pre_script_args_list = []

            # Setting Executable for python if the file ext is py else powershell
            if self.file_ext == ".py":
                self.executable = ["python.exe"]
            elif self.file_ext == ".ps1":
                self.executable = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "bypass", "-File"]
            else:
                self.executable = ["powershell.exe"]
        else:
            self.do_run = False

    def start(self):
        if not self.do_run:
            return
        try:
            self.executable.append(self.file_path)
            if isinstance(self.pre_script_args_list, list):
                for args in self.pre_script_args_list:
                    self.executable.append(args)
            else:
                self.executable.append(self.pre_script_args_list)
            log.info("Pre_script command: %s", " ".join(self.executable))
            p = subprocess.check_output(self.executable, timeout=self.timeout, stderr=subprocess.STDOUT)

            nf = NetlogFile()
            nf.init("logs/pre_script.log")
            nf.sock.send(p)
            nf.close()
            log.info("Successfully ran pre_script, saved output to logs/pre_script.logs")
            return True
        except subprocess.CalledProcessError as e:
            log.error("Error, return code: %s", e.returncode)
            log.error("Error, Process stdout: %s", e.output)
        except Exception as e:
            log.error("Error running pre_script due to error: %s", e)
            return False

    def stop(self):
        self.do_run = False
