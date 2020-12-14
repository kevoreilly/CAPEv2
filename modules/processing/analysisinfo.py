# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import codecs
import time
import logging
import os
from datetime import datetime

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from lib.cuckoo.common.utils import get_options
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooProcessingError

try:
    import requests

    HAVE_REQUEST = True
except ImportError:
    HAVE_REQUEST = False


log = logging.getLogger(__name__)
report_cfg = Config("reporting")

db = Database()


class AnalysisInfo(Processing):
    """General information about analysis session."""

    def had_timeout(self):
        """ Test if the analysis had a timeout
        """
        if os.path.exists(self.log_path):
            try:
                analysis_log = codecs.open(self.log_path, "rb", "utf-8").read()
            except ValueError as e:
                raise CuckooProcessingError("Error decoding %s: %s" % (self.log_path, e))
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening %s: %s" % (self.log_path, e))
            else:
                if "INFO: Analysis timeout hit, terminating analysis" in analysis_log:
                    return True
        return False

    def get_package(self):
        """ Get the actually used package name
        """
        package = self.task["package"]
        if not package and os.path.exists(self.log_path):
            try:
                analysis_log = codecs.open(self.log_path, "rb", "utf-8").read()
            except ValueError as e:
                raise CuckooProcessingError("Error decoding %s: %s" % (self.log_path, e))
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening %s: %s" % (self.log_path, e))
            else:
                try:
                    idx = analysis_log.index('INFO: Automatically selected analysis package "')
                    package = analysis_log[idx + 47 :].split('"', 1)[0]
                except:
                    pass
        return package

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "info"

        try:
            started = time.strptime(self.task["started_on"], "%Y-%m-%d %H:%M:%S")
            started = datetime.fromtimestamp(time.mktime(started))
            ended = time.strptime(self.task["completed_on"], "%Y-%m-%d %H:%M:%S")
            ended = datetime.fromtimestamp(time.mktime(ended))
        except:
            log.critical("Failed to get start/end time from Task.")
            duration = -1
        else:
            duration = (ended - started).seconds

        # Fetch sqlalchemy object.
        task = db.view_task(self.task["id"], details=True)

        if task and task.guest:
            # Get machine description ad json.
            machine = task.guest.to_dict()
            # Remove useless task_id.
            del machine["task_id"]
            # Save.
            self.task["machine"] = machine
        distributed = dict()
        parsed_options = get_options(self.task["options"])
        parent_sample_details = False
        if "maint_task_id" not in parsed_options:
            parent_sample_details = db.list_sample_parent(task_id=self.task["id"])
        source_url = db.get_source_url(sample_id=self.task["sample_id"])

        return dict(
            version=CUCKOO_VERSION,
            started=self.task["started_on"],
            ended=self.task.get("completed_on", "none"),
            duration=duration,
            id=int(self.task["id"]),
            category=self.task["category"],
            custom=self.task["custom"],
            machine=self.task["machine"],
            package=self.get_package(),
            timeout=self.had_timeout(),
            shrike_url=self.task["shrike_url"],
            shrike_refer=self.task["shrike_refer"],
            shrike_msg=self.task["shrike_msg"],
            shrike_sid=self.task["shrike_sid"],
            parent_id=self.task["parent_id"],
            tlp=self.task["tlp"],
            parent_sample=parent_sample_details,
            distributed=distributed,
            options=parsed_options,
            source_url=source_url,
        )
