# Copyright (C) 2022 Quadrant Information Security, written by Zane C. Bowers-Hadley
# This file is part of CAPE Sandbox - https://capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

# This calls the specified command, pointing it at the report.json as
# well as setting $ENV{CAPE_TASK_ID} to the task ID of the run in question.
#
# The following set in reporting.conf would enable it and run "/foo/bar.sh".
#
# [zexecreport]
# enabled=yes
# command=/foo/bar.sh
#
# The name of this module should place it after most everything if using
# it for something other than report.json, but if using it for something
# else in the reporting folder or the like, you will want to make sure
# that it's name comes before "zexecreport".

import logging
import os
import subprocess

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

repconf = Config("reporting")


class ZExecReport(Report):
    """Execute the specified command pointed at report.json"""

    order = 10001

    def run(self, results: dict):
        """Writes report.
        @param results: CAPE results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
            task_id = str(results["info"]["id"])
            path = os.path.join(self.reports_path, "report.json")
            cmd_results = subprocess.run((repconf.zexecreport.command, path), capture_output=True, env={"CAPE_TASK_ID": task_id})
            if cmd_results.returncode != 0:
                log.error(
                    "CAPE_TASK_ID= %s command=%s exit=%s stdout=%s stderror=%s",
                    task_id,
                    cmd_results.returncode,
                    repconf.zexecreport.command,
                    cmd_results.stdout.decode(),
                    cmd_results.stderr.decode(),
                )
            else:
                log.info(
                    "CAPE_TASK_ID= %s command=%s stdout=%s stderror=%s",
                    task_id,
                    repconf.zexecreport.command,
                    cmd_results.stdout.decode(),
                    cmd_results.stderr.decode(),
                )
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Error encountered running the specified command: {e}") from e
