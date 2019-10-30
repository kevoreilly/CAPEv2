# Copyright (C) 2010-2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import shutil
import logging
import argparse
from multiprocessing.pool import ThreadPool

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from datetime import datetime, timedelta

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report

from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.core.database import Database, Task, TASK_REPORTED
from bson.objectid import ObjectId

log = logging.getLogger(__name__)
cfg = Config("reporting")
ccfg = Config("cuckoo")
db = Database()

resolver_pool = ThreadPool(20)

# only allow one reporter to execute this code, otherwise rmtree will race, etc
delete_files = True
mongo = True
if os.path.exists("last_id"):
    lastTaskLogged = open("last_id", "rb").read().strip()
else:
    lastTaskLogged = 1

# Global connections
if cfg.mongodb and cfg.mongodb.enabled:
    from pymongo import MongoClient
    from pymongo.errors import AutoReconnect
    host = cfg.mongodb.get("host", "127.0.0.1")
    port = cfg.mongodb.get("port", 27017)
    mdb = cfg.mongodb.get("db", "cuckoo")

    try:
        results_db = MongoClient(host, port)[mdb]
    except Exception as e:
        log.warning("Unable to connect to MongoDB: %s", str(e))

def delete_mongo_data(tid):
    global results_db
    # TODO: Class-ify this or make it a function in utils, some code reuse
    # between this/process.py/django view
    analyses = results_db.analysis.find({"info.id": int(tid)})
    if analyses.count > 0:
        for analysis in analyses:
            log.info("deleting MongoDB data for Task #{0}".format(tid))
            for process in analysis.get("behavior", {}).get("processes", []):
                for call in process["calls"]:
                    results_db.calls.remove({"_id": ObjectId(call)})
            results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})


class Retention(Report):
    """Used to manage data retention and delete task data from
    disk after they have become older than the configured values.
    """

    def executor(self, tid):
        global results_db
        # We need to delete some data
        try:
            lastTask = tid.to_dict()["id"]
            print("Going to remove", lastTask)
            if mongo and cfg.mongodb and cfg.mongodb.enabled:
                delete_mongo_data(lastTask)
        except AutoReconnect:
            results_db = MongoClient(host, port)[mdb]

    def run(self, options):
        task_id = False
        old = datetime.now() - timedelta(days=options.days)
        if delete_files:
            to_remove = []
            to_remove = [root for root, dirs, files in os.walk(CUCKOO_ROOT + "/storage/analyses/", topdown=False) if datetime.fromtimestamp(os.path.getmtime(root)) < old]
            resolver_pool.map(lambda root: shutil.rmtree(root), to_remove)

        if mongo:
            buf = db.list_tasks(added_before=old, id_after=lastTaskLogged, order_by=Task.id.desc())
            if not buf:
                return

            task_id = buf[0].to_dict()["id"]
            resolver_pool.map(lambda tid: self.executor(tid.to_dict()["id"]), buf)

        if task_id:
            w = open("last_id", "w")
            w.write(task_id)
            w.close()

if __name__ == '__main__':
    opt = argparse.ArgumentParser('value', description='Remove all reports older than X days')
    opt.add_argument('-d', '--days', action='store', type=int, help='Older then this days will be removed')
    options = opt.parse_args()
    if options.days:
        ret = Retention()
        ret.run(options)
    else:
        print(opt.print_help())
