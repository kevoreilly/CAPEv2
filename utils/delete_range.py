#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import time
import logging
import argparse
import signal
import multiprocessing

log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, Task, TASK_REPORTED, TASK_COMPLETED, TASK_RUNNING
from lib.cuckoo.common.utils import delete_folder
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING
from lib.cuckoo.core.plugins import GetFeeds, RunProcessing, RunSignatures
from lib.cuckoo.core.plugins import RunReporting
from lib.cuckoo.core.startup import init_modules, ConsoleHandler

# Global DB pointer.
db = Database()

# http://api.mongodb.com/python/current/faq.html#using-pymongo-with-multiprocessing
# this required for Distributed mode

def init_logging(debug=False):
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)
    
    fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "process_all.log"))

    fh.setFormatter(formatter)
    log.addHandler(fh)

    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    logging.getLogger("urllib3").setLevel(logging.WARNING)

def tasks_delete(task_id):
    response = {}

    task = db.view_task(task_id)
    if task:
        if db.delete_task(task_id):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage",
                                       "analyses", "%d" % task_id))

            log.info("Deleted task: %u.", task_id)
        else:
            log.error("Error deleting task: %u.", task_id)

    else:
        log.error("Task not found: %u.", task_id)

    return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--start", help="First job in range to delete", required=True)
    parser.add_argument("-e", "--end", help="Last job in range to delete", required=True)
    args = parser.parse_args()

    init_modules()

    TotalTasks = Database().count_tasks()

    init_logging()

    for task_id in range (int(args.start), int(args.end)+1):
        print("About to delete task {}".format(task_id))
        tasks_delete(task_id)
        
if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
    
