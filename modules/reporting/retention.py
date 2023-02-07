# Copyright (C) 2010-2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import shutil
from collections import defaultdict
from datetime import datetime, timedelta
from multiprocessing import Lock
from pathlib import Path

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_mkdir
from lib.cuckoo.core.database import TASK_REPORTED, Database, Task

log = logging.getLogger(__name__)
repconf = Config("reporting")
db = Database()
lock = Lock()

# Global connections
if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_delete_data

if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
    from dev_utils.elasticsearchdb import delete_analysis_and_related_calls, elastic_handler

    es = elastic_handler


def delete_files(curtask, delfiles, target_id):
    delfiles_list = delfiles
    if not isinstance(delfiles, list):
        delfiles_list = [delfiles]

    for _delent in delfiles_list:
        delent = _delent.format(target_id)
        if os.path.isdir(delent):
            try:
                shutil.rmtree(delent)
                log.debug("Task #%s deleting %s due to retention quota", curtask, delent)
            except (IOError, OSError) as e:
                log.warn("Error removing %s: %s", delent, e)
        elif path_exists(delent):
            try:
                path_delete(delent)
                log.debug("Task #%s deleting %s due to retention quota", curtask, delent)
            except OSError as e:
                log.warn("Error removing %s: %s", delent, e)


class Retention(Report):
    """Used to manage data retention and delete task data from
    disk after they have become older than the configured values.
    """

    order = 10000

    def run(self, results):
        # Curtask used for logging when deleting files
        curtask = results["info"]["id"]

        # Since we should be the last run reporting module, make sure we don't delay
        # an analyst from being able to see results for their analysis on account
        # of this taking some time
        db.set_status(curtask, TASK_REPORTED)

        # Retains the last Task ID checked for retention settings per category
        taskCheck = defaultdict(int)
        # Handle the case where someone doesn't restart cuckoo and issues
        # process.py manually, the directiry structure is created in the
        # startup of cuckoo.py
        retPath = os.path.join(CUCKOO_ROOT, "storage", "retention")
        confPath = os.path.join(CUCKOO_ROOT, "conf", "reporting.conf")

        if not os.path.isdir(retPath):
            log.warn("Retention log directory doesn't exist, creating it now")
            path_mkdir(retPath)
        else:
            try:
                taskFile = os.path.join(retPath, "task_check.log")
                with open(taskFile, "r") as taskLog:
                    taskCheck = json.loads(taskLog.read())
            except Exception as e:
                log.warn("Failed to load retention log, if this is not the time running retention, review the error: %s", e)
            curtime = datetime.now()
            since_retlog_modified = curtime - datetime.fromtimestamp(os.path.getmtime(taskFile))
            since_conf_modified = curtime - datetime.fromtimestamp(os.path.getmtime(confPath))

            # We'll only do anything in this module once every 'run_every' hours, or immediately
            # after changes to reporting.conf
            if since_retlog_modified < timedelta(hours=self.options["run_every"]) and since_conf_modified > since_retlog_modified:
                return

        # only allow one reporter to execute this code, otherwise rmtree will race, etc
        if not lock.acquire(False):
            return
        try:
            delLocations = {
                "memory": [CUCKOO_ROOT + "/storage/analyses/{0}/memory.dmp", CUCKOO_ROOT + "/storage/analyses/{0}/memory.dmp.zip"],
                "procmemory": CUCKOO_ROOT + "/storage/analyses/{0}/memory",
                "pcap": CUCKOO_ROOT + "/storage/analyses/{0}/dump.pcap",
                "sortedpcap": CUCKOO_ROOT + "/storage/analyses/{0}/dump_sorted.pcap",
                "bsonlogs": CUCKOO_ROOT + "/storage/analyses/{0}/logs",
                "dropped": CUCKOO_ROOT + "/storage/analyses/{0}/files",
                "screencaps": CUCKOO_ROOT + "/storage/analyses/{0}/shots",
                "reports": CUCKOO_ROOT + "/storage/analyses/{0}/reports",
                # Handled seperately
                "mongo": None,
                "elastic": None,
            }
            retentions = self.options
            del retentions["enabled"]
            del retentions["run_every"]
            saveTaskLogged = {}
            for item in retentions.keys():
                # We only want to query the database for tasks that we have
                # retentions set for.
                if not self.options[item]:
                    continue
                # Sanitation
                if item not in taskCheck or taskCheck[item] == 0:
                    lastTaskLogged = None
                else:
                    lastTaskLogged = taskCheck[item]
                add_date = datetime.now() - timedelta(days=retentions[item])
                buf = db.list_tasks(added_before=add_date, id_after=lastTaskLogged, order_by=Task.id.asc())
                lastTask = 0
                if buf:
                    # We need to delete some data
                    for tid in buf:
                        lastTask = tid.to_dict()["id"]
                        if item not in ("mongo", "elastic"):
                            delete_files(curtask, delLocations[item], lastTask)
                        elif item == "mongo":
                            if repconf.mongodb.enabled:
                                mongo_delete_data([lastTask])
                        elif item == "elastic":
                            if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
                                delete_analysis_and_related_calls(lastTask)
                    saveTaskLogged[item] = int(lastTask)
                else:
                    saveTaskLogged[item] = 0

            # Write the task log for future reporting, to avoid returning tasks
            # that we have already deleted data from.
            _ = Path(retPath / "task_check.log").write_text(json.dumps(saveTaskLogged))
        finally:
            lock.release()
