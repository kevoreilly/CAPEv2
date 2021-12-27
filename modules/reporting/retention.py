# Copyright (C) 2010-2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import json
import logging
import os
import shutil
from collections import defaultdict
from datetime import datetime, timedelta
from multiprocessing import Lock

from bson.objectid import ObjectId

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.core.database import TASK_REPORTED, Database, Task

log = logging.getLogger(__name__)
repconf = Config("reporting")
db = Database()
lock = Lock()

# Global connections
if repconf.mongodb and repconf.mongodb.enabled:
    from pymongo import MongoClient

    results_db = MongoClient(
        repconf.mongodb.host,
        port=repconf.mongodb.port,
        username=repconf.mongodb.get("username"),
        password=repconf.mongodb.get("password"),
        authSource=repconf.mongodb.get("authsource", "cuckoo"),
    )[repconf.mongodb.get("db", "cuckoo")]

if repconf.elasticsearchdb and repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
    from elasticsearch import Elasticsearch

    idx = f"{repconf.elasticsearchdb.index}-*"
    try:
        es = Elasticsearch(
            hosts=[
                {
                    "host": repconf.elasticsearchdb.host,
                    "port": repconf.elasticsearchdb.port,
                }
            ],
            timeout=60,
        )
    except Exception as e:
        log.warning("Unable to connect to ElasticSearch: %s", e)


def delete_mongo_data(curtask, tid):
    # TODO: Class-ify this or make it a function in utils, some code reuse
    # between this/process.py/django view
    analyses = results_db.analysis.find({"info.id": int(tid)})
    if analyses.count() > 0:
        for analysis in analyses:
            for process in analysis.get("behavior", {}).get("processes", []):
                for call in process["calls"]:
                    results_db.calls.remove({"_id": ObjectId(call)})
            results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})
        log.debug("Task #%s deleting MongoDB data for Task #%s", curtask, tid)


"""
def delete_elastic_data(curtask, tid):
    # TODO: Class-ify this or make it a function in utils, some code reuse
    # between this/process.py/django view
    analyses = es.search(index=fullidx, doc_type="analysis", q=f'info.id: "{tid}"')["hits"]["hits"]
    if len(analyses) > 0:
        for analysis in analyses:
            esidx = analysis["_index"]
            esid = analysis["_id"]
            if analysis["_source"]["behavior"]:
                for process in analysis["_source"]["behavior"]["processes"]:
                    for call in process["calls"]:
                        es.delete(
                            index=esidx, doc_type="calls", id=call,
                        )
            es.delete(
                index=esidx, doc_type="analysis", id=esid,
            )
        log.debug("Task #%s deleting ElasticSearch data for Task #%s", curtask, tid)
"""


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
        elif os.path.exists(delent):
            try:
                os.remove(delent)
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
            os.mkdir(retPath)
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
                if self.options[item] == False:
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
                        if item != "mongo" and item != "elastic":
                            delete_files(curtask, delLocations[item], lastTask)
                        elif item == "mongo":
                            if repconf.mongodb and repconf.mongodb.enabled:
                                delete_mongo_data(curtask, lastTask)
                        """
                        elif item == "elastic":
                            if repconf.elasticsearchdb and repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
                                delete_elastic_data(curtask, lastTask)
                        """
                    saveTaskLogged[item] = int(lastTask)
                else:
                    saveTaskLogged[item] = 0

            # Write the task log for future reporting, to avoid returning tasks
            # that we have already deleted data from.
            with open(os.path.join(retPath, "task_check.log"), "w") as taskLog:
                taskLog.write(json.dumps(saveTaskLogged))
        finally:
            lock.release()
