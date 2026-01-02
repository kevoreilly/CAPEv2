# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import codecs
import logging
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import get_options
from lib.cuckoo.core.database import Database

# https://stackoverflow.com/questions/14989858/get-the-current-git-hash-in-a-python-script/68215738#68215738

log = logging.getLogger(__name__)

db = Database()


def get_running_commit() -> str:
    try:
        git_folder = Path(CUCKOO_ROOT, ".git")
        head_name = Path(git_folder, "HEAD").read_text().split("\n")[0].split(" ")[-1]
        return Path(git_folder, head_name).read_text().replace("\n", "")
    except Exception as e:
        log.error("Error getting running commit hash: %s", str(e))
        return "unknown"


CAPE_CURRENT_COMMIT_HASH = get_running_commit()


class AnalysisInfo(Processing):
    """General information about analysis session."""

    def had_timeout(self):
        """Test if the analysis had a timeout"""
        if path_exists(self.log_path):
            try:
                with codecs.open(self.log_path, "rb", "utf-8") as f:
                    analysis_log = f.read()
                if "INFO: Analysis timeout hit, terminating analysis" in analysis_log:
                    return True
            except ValueError as e:
                raise CuckooProcessingError(f"Error decoding {self.log_path}: {e}") from e
            except (IOError, OSError) as e:
                raise CuckooProcessingError(f"Error opening {self.log_path}: {e}") from e
        return False

    def get_package(self):
        """Get the actually used package name"""
        package = self.task["package"]
        if isinstance(package, dict) and package.get("name", ""):
            package = package["name"]
        if not package and path_exists(self.log_path):
            try:
                with codecs.open(self.log_path, "rb", "utf-8") as f:
                    analysis_log = f.read()
            except ValueError as e:
                raise CuckooProcessingError(f"Error decoding {self.log_path}: {e}") from e
            except (IOError, OSError) as e:
                raise CuckooProcessingError(f"Error opening {self.log_path}: {e}") from e
            else:
                with suppress(Exception):
                    idx = analysis_log.index('INFO: Automatically selected analysis package "')
                    package = analysis_log[idx + 47 :].split('"', 1)[0]
        return package

    def run(self):
        """Run information gathering.
        @return: information dict.
        """
        self.key = "info"
        self.order = 1

        try:
            started = time.strptime(self.task["started_on"], "%Y-%m-%d %H:%M:%S")
            started = datetime.fromtimestamp(time.mktime(started))
            ended = time.strptime(self.task["completed_on"], "%Y-%m-%d %H:%M:%S")
            ended = datetime.fromtimestamp(time.mktime(ended))
        except Exception:
            log.critical("Failed to get start/end time from Task")
            duration = -1
        else:
            duration = (ended - started).seconds

        # Fetch sqlalchemy object.
        task = db.view_task(self.task["id"], details=True)

        if task and task.guest:
            # Get machine description as json.
            machine = task.guest.to_dict()
            # Remove useless task_id.
            del machine["task_id"]
            # Save.
            self.task["machine"] = machine
        parsed_options = get_options(self.task["options"])
        parent_sample_details = False
        if "maint_task_id" not in parsed_options:
            parent_sample_details = db.get_parent_sample_from_task(task_id=self.task["id"])
            if parent_sample_details:
                parent_sample_details = parent_sample_details.to_dict()
        source_url = db.get_source_url(sample_id=self.task["sample_id"])

        return {
            "version": CUCKOO_VERSION,
            "started": self.task["started_on"],
            "ended": self.task.get("completed_on", "none"),
            "duration": duration,
            "id": int(self.task["id"]),
            "category": self.task["category"],
            "custom": self.task["custom"],
            "machine": self.task["machine"],
            "package": self.get_package(),
            "timeout": self.had_timeout(),
            "tlp": self.task["tlp"],
            "parent_sample": parent_sample_details,
            "options": parsed_options,
            "source_url": source_url,
            "route": self.task.get("route"),
            "user_id": self.task.get("user_id"),
            "CAPE_current_commit": CAPE_CURRENT_COMMIT_HASH,
        }
