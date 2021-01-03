# encoding: utf-8
#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# ToDo
# https://github.com/cuckoosandbox/cuckoo/pull/1694/files
from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import time
import json
import shutil
import queue
import hashlib
import logging
from logging import handlers
import tarfile
import argparse
import threading
from io import BytesIO
from zipfile import ZipFile
from datetime import datetime
from itertools import combinations
import distutils.util
from sqlalchemy import Column, ForeignKey, Integer, Text, String, Boolean, DateTime, or_, and_, desc
from sqlalchemy.exc import SQLAlchemyError, OperationalError

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import store_temp_file, get_options
from lib.cuckoo.common.dist_db import Node, StringList, Task, Machine, create_session
from lib.cuckoo.core.database import (
    Database,
    TASK_COMPLETED,
    TASK_REPORTED,
    TASK_RUNNING,
    TASK_PENDING,
    TASK_FAILED_REPORTING,
    TASK_DISTRIBUTED_COMPLETED,
    TASK_DISTRIBUTED,
)
from lib.cuckoo.core.database import Task as MD_Task

# we need original db to reserve ID in db,
# to store later report, from master or worker
reporting_conf = Config("reporting")

# init
logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

STATUSES = {}
ID2NAME = {}
SERVER_TAGS = {}
main_db = Database()

dead_count = 5
if reporting_conf.distributed.dead_count:
    dead_count = reporting_conf.distributed.dead_count

INTERVAL = 10

# controller of dead nodes
failed_count = dict()
# status controler count to reset number
status_count = dict()

lock_retriever = threading.Lock()
dist_lock = threading.BoundedSemaphore(int(reporting_conf.distributed.dist_threads))
fetch_lock = threading.BoundedSemaphore(1)

delete_enabled = False
failed_clean_enabled = False


def required(package):
    sys.exit("The %s package is required: pip3 install %s" % (package, package))

try:
    from flask import Flask, request, make_response, jsonify
except ImportError:
    required("flask")

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    required("requests")

try:
    requests.packages.urllib3.disable_warnings()
except AttributeError:
    pass

try:
    from flask_restful import abort, reqparse
    from flask_restful import Api as RestApi, Resource as RestResource
except ImportError:
    required("flask-restful")

session = create_session(reporting_conf.distributed.db, echo=False)


def node_status(url, name, ht_user, ht_pass):
    try:
        r = requests.get(os.path.join(url, "cuckoo", "status/"), params={"username": ht_user, "password": ht_pass}, verify=False, timeout=200)
        return r.json().get("data", {})["tasks"]
    except Exception as e:
        log.critical("Possible invalid Cuckoo node (%s): %s", name, e)
    return {}


def node_fetch_tasks(status, url, ht_user, ht_pass, action="fetch", since=0):
    try:
        url = os.path.join(url, "tasks", "list/")
        params = dict(status=status, ids=True, username=ht_user, password=ht_pass)
        if action == "fetch":
            params["completed_after"] = since
        r = requests.get(url, params=params, verify=False)
        if not r.ok:
            log.error(f"Error fetching task list. Status code: {r.status_code}")
            return []
        return r.json().get("data", [])
    except Exception as e:
        log.critical("Error listing completed tasks (node %s): %s", url, e)

    return []


def node_list_machines(url, ht_user, ht_pass):
    try:
        r = requests.get(os.path.join(url, "machines", "list/"), params={"username": ht_user, "password": ht_pass}, verify=False)
        for machine in r.json()["data"]:
            yield Machine(name=machine["name"], platform=machine["platform"], tags=machine["tags"])
    except Exception as e:
        abort(404, message="Invalid CAPE node (%s): %s" % (url, e))


def node_get_report(task_id, fmt, url, ht_user, ht_pass, stream=False):
    try:
        url = os.path.join(url, "tasks", "get", "report", "%d/" % task_id, fmt)
        return requests.get(url, stream=stream, params={"username": ht_user, "password": ht_pass}, verify=False, timeout=300)
    except Exception as e:
        log.critical("Error fetching report (task #%d, node %s): %s", task_id, url, e)


def node_submit_task(task_id, node_id):

    db = session()
    node = db.query(Node).filter_by(id=node_id).first()
    task = db.query(Task).filter_by(id=task_id).first()
    check = False
    try:
        if node.name == "master":
            return

        # Remove the earlier appended comma
        if task.tags:
            if task.tags[-1] == ",":
                task.tags = task.tags[:-1]

        data = dict(
            package=task.package,
            timeout=task.timeout,
            priority=task.priority,
            options=task.options,
            machine=task.machine,
            platform=task.platform,
            tags=task.tags,
            custom=task.custom,
            clock=task.clock,
            memory=task.memory,
            enforce_timeout=task.enforce_timeout,
            username=node.ht_user,
            password=node.ht_pass,
        )

        if task.category in ("file", "pcap"):
            if task.category == "pcap":
                data = {"pcap": 1}

            url = os.path.join(node.url, "tasks", "create", "file/")
            # If the file does not exist anymore, ignore it and move on
            # to the next file.
            if not os.path.exists(task.path):
                task.finished = True
                task.retrieved = True
                main_db.set_status(task.main_task_id, TASK_FAILED_REPORTING)
                try:
                    db.commit()
                except Exception as e:
                    log.exception(e)
                    db.rollback()
                return
            files = dict(file=open(task.path, "rb"))
            r = requests.post(url, data=data, files=files, verify=False)
        elif task.category == "url":
            url = os.path.join(node.url, "tasks", "create", "url/")
            r = requests.post(url, data={"url": task.path, "options": task.options, "username": node.ht_user, "password": node.ht_pass}, verify=False)
        elif task.category == "static":
            url = os.path.join(node.url, "tasks", "create", "static/")
            log.info("Static isn't finished")
        else:
            log.debug("Target category is: {}".format(task.category))
            db.close()
            return

        # encoding problem
        if r.status_code == 500 and task.category == "file":
            r = requests.post(url, data=data, files={"file": ("file", open(task.path, "rb").read())}, verify=False)

        # Zip files preprocessed, so only one id
        if r and r.status_code == 200:
            if "task_ids" in r.json().get("data", {}) and len(r.json().get("data", {})["task_ids"]) > 0 and r.json().get("data", {})["task_ids"] is not None:
                task.task_id = r.json().get("data", {})["task_ids"][0]
                check = True
            elif "task_id" in r.json() and r.json()["task_id"] > 0 and r.json()["task_id"] is not None:
                task.task_id = r.json()["task_id"]
                check = True
            else:
                log.debug("Failed to submit task {} to node: {}, code: {}".format(task_id, node.name, r.status_code))

            log.debug("Submitted task to worker: {} - {} - {} - {}".format(node.name, task.task_id, task.main_task_id, r.json()))

        elif r.status_code == 500:
            log.debug((r.status_code, r.text))

        elif r.status_code == 429:
            log.info((r.status_code, "see api auth for more details"))

        else:
            log.info("Node: {} - Task submit to worker failed: {} - {}".format(node.id, r.status_code, r.content))

        if check:
            task.node_id = node.id


            # We have to refresh() the task object because otherwise we get
            # the unmodified object back in further sql queries..
            # TODO Commit once, refresh() all at once. This could potentially
            # become a bottleneck.
            try:
                db.commit()
                db.refresh(task)
            except Exception as e:
                print(e)
                db.rollback()

    except Exception as e:
        log.exception(e)
        log.critical("Error submitting task (task #%d, node %s): %s", task.id, node.name, e)


    db.commit()
    db.close()
    return check


class Retriever(threading.Thread):

    def run(self):
        self.cleaner_queue = queue.Queue()
        self.fetcher_queue = queue.Queue()
        self.cfg = Config()
        self.t_is_none = dict()
        self.status_count = dict()
        self.current_queue = dict()
        self.current_two_queue = dict()
        self.stop_dist = threading.Event()

        for x in range(int(reporting_conf.distributed.dist_threads)):
            if dist_lock.acquire(blocking=False):
                thread = threading.Thread(target=self.fetch_latest_reports, args=())
                thread.daemon = True
                thread.start()

        if fetch_lock.acquire(blocking=False):
            thread = threading.Thread(target=self.fetcher, args=())
            thread.daemon = True
            thread.start()

        # Delete the task and all its associated files.
        # (It will still remain in the nodes" database, though.)
        if reporting_conf.distributed.remove_task_on_worker or delete_enabled:
            thread = threading.Thread(target=self.remove_from_worker, args=())
            thread.daemon = True
            thread.start()

        if reporting_conf.distributed.failed_cleaner or failed_clean_enabled:
            thread = threading.Thread(target=self.failed_cleaner, args=())
            thread.daemon = True
            thread.start()

        thread = threading.Thread(target=self.free_space_mon, args=())
        thread.daemon = True
        thread.start()

        if reporting_conf.callback.enabled:
            thread = threading.Thread(target=self.notification_loop, args=())
            thread.daemon = True
            thread.start()

    def free_space_mon(self):
        # If not enough free disk space is available, then we print an
        # error message and wait another round (this check is ignored
        # when the freespace configuration variable is set to zero).
        while True:
            if self.cfg.cuckoo.freespace:
                # Resolve the full base path to the analysis folder, just in
                # case somebody decides to make a symbolic link out of it.
                dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")

                if hasattr(os, "statvfs"):
                    dir_stats = os.statvfs(dir_path)

                    # Calculate the free disk space in megabytes.
                    space_available = dir_stats.f_bavail * dir_stats.f_frsize
                    space_available /= 1024 * 1024

                    if space_available < self.cfg.cuckoo.freespace:
                        log.error("Not enough free disk space! (Only %d MB!)", space_available)
                        self.stop_dist.set()
                        continue
                    else:
                        self.stop_dist.clear()

                time.sleep(60)

    def zip_files(self, files):
        in_memory = BytesIO()
        zf = ZipFile(in_memory, mode="w")

        for file in files:
            zf.writestr(os.path.basename(file), open(file, "rb").read())

        zf.close()
        in_memory.seek(0)

        # read the data
        data = in_memory.read()
        in_memory.close()

        return data

    def notification_loop(self):
        urls = reporting_conf.callback.url.split(",")

        db = session()
        while True:

            tasks = db.query(Task).filter_by(finished=True, retrieved=True, notificated=False).order_by(Task.id.desc()).all()
            if tasks is not None:
                for task in tasks:
                    main_db.set_status(task.main_task_id, TASK_REPORTED)
                    log.debug("reporting main_task_id: {}".format(task.main_task_id))
                    for url in urls:
                        try:
                            res = requests.post(url, data=json.dumps({"task_id": int(task.main_task_id)}))
                            if res and res.ok:
                                # log.info(res.content)
                                task.notificated = True
                                #db.commit()
                                #db.refresh(task)
                            else:
                                log.info("failed to report: {} - {}".format(task.main_task_id, res.status_code))
                        except requests.exceptions.ConnectionError:
                            log.info("Can't report to callback")
                        except Exception as e:
                            log.info("failed to report: {} - {}".format(task.main_task_id, e))
            db.commit()
            time.sleep(20)
        db.close()

    def failed_cleaner(self):
        db = session()
        while True:
            for node in db.query(Node).filter_by(enabled=True).all():
                log.info("Checking for failed tasks on: {}".format(node.name))
                for status in ("failed_analysis", "failed_processing"):
                    for task in node_fetch_tasks(status, node.url, node.ht_user, node.ht_pass, action="delete"):
                        t = db.query(Task).filter_by(task_id=task["id"], node_id=node.id).order_by(Task.id.desc()).first()
                        if t is not None:
                            log.info("Cleaning failed_analysis for id:{}, node:{}: main_task_id: {}".format(t.id, t.node_id, t.main_task_id))
                            main_db.set_status(t.main_task_id, TASK_FAILED_REPORTING)
                            t.finished = True
                            t.retrieved = True
                            t.notificated = True
                            lock_retriever.acquire()
                            if (t.node_id, t.task_id) not in self.cleaner_queue.queue:
                                self.cleaner_queue.put((t.node_id, t.task_id))
                            lock_retriever.release()
                        else:
                            log.debug("failed_cleaner t is None for: {} - node_id: {}".format(task["id"], node.id))
                            lock_retriever.acquire()
                            if (node.id, task["id"]) not in self.cleaner_queue.queue:
                                self.cleaner_queue.put((node.id, task["id"]))
                            lock_retriever.release()
                    db.commit()
            time.sleep(600)
        db.close()

    def fetcher(self):
        """ Method that runs forever """
        last_checks = dict()
        # to not exit till cleaner works
        db = session()
        while not self.stop_dist.isSet():
            for node in db.query(Node).filter_by(enabled=True).all():
                self.status_count.setdefault(node.name, 0)
                last_checks.setdefault(node.name, 0)
                last_checks[node.name] += 1
                # reset it every 10 calls
                if node.last_check:
                    last_check = int(node.last_check.strftime("%s"))
                else:
                    last_check = 0
                if last_checks[node.name] == 10:
                    last_check = 0
                    last_checks[node.name] = 0
                limit = 0
                for task in node_fetch_tasks("reported", node.url, node.ht_user, node.ht_pass, "fetch", last_check):
                    tasker = (
                        db.query(Task)
                        .filter_by(finished=False, retrieved=False, task_id=task["id"], node_id=node.id, deleted=False)
                        .order_by(Task.id.desc())
                        .first()
                    )
                    if tasker is None:
                        self.cleaner_queue.put((node.id, task["id"]))
                        continue
                    try:
                        if task["id"] not in self.current_queue.get(node.id, []) and (task["id"], node.id) not in self.fetcher_queue.queue:
                            limit += 1
                            self.fetcher_queue.put((task, node.id))
                            # log.debug("{} - {}".format(task, node.id))
                            completed_on = datetime.strptime(task["completed_on"], "%Y-%m-%d %H:%M:%S")
                            if node.last_check is None or completed_on > node.last_check:
                                node.last_check = completed_on
                                db.commit()
                                db.refresh(node)
                            if limit == 50:
                                break
                    except Exception as e:
                        self.status_count[node.name] += 1
                        log.info(e)
                        if self.status_count[node.name] == dead_count:
                            log.info("[-] {} dead".format(node.name))
                            # node_data = db.query(Node).filter_by(name=node.name).first()
                            # node_data.enabled = False
                            # db.commit()
            db.commit()
            time.sleep(5)
        db.close()

    # This should be executed as external thread as it generates bottle neck
    def fetch_latest_reports(self):
        db = session()
        # to not exit till cleaner works
        while not self.stop_dist.isSet():
            task, node_id = self.fetcher_queue.get()

            self.current_queue.setdefault(node_id, list()).append(task["id"])

            try:
                # In the case that a Cuckoo node has been reset over time it"s
                # possible that there are multiple combinations of
                # node-id/task-id, in this case we take the last one available.
                # (This makes it possible to re-setup a Cuckoo node).
                t = (
                    db.query(Task)
                    .filter_by(node_id=node_id, task_id=task["id"], retrieved=False, finished=False)
                    .order_by(Task.id.desc())
                    .first()
                )
                if t is None:
                    self.t_is_none.setdefault(node_id, list()).append(task["id"])

                    # sometime it not deletes tasks in workers of some fails or something
                    # this will do the trick
                    # log.debug("tf else,")
                    if (node_id, task.get("id")) not in self.cleaner_queue.queue:
                        self.cleaner_queue.put((node_id, task.get("id")))
                    continue

                log.debug(
                    "Fetching dist report for: id: {}, task_id: {}, main_task_id:{} from node: {}".format(
                        t.id, t.task_id, t.main_task_id, ID2NAME[t.node_id] if t.node_id in ID2NAME else t.node_id
                    )
                )
                # set completed_on time
                main_db.set_status(t.main_task_id, TASK_DISTRIBUTED_COMPLETED)
                # set reported time
                main_db.set_status(t.main_task_id, TASK_REPORTED)

                t.finished = True
                t.retrieved = True
                db.commit()

                # Fetch each requested report.
                node = db.query(Node).filter_by(id=node_id).first()
                report = node_get_report(t.task_id, "dist", node.url, node.ht_user, node.ht_pass, stream=True)

                if report is None:
                    log.info("dist report retrieve failed NONE: task_id: {} from node: {}".format(t.task_id, node_id))
                    continue

                if report.status_code != 200:
                    log.info("dist report retrieve failed - status_code {}: task_id: {} from node: {}".format(report.status_code, t.task_id, node_id))
                    if report.status_code == 400 and (node_id, task.get("id")) not in self.cleaner_queue.queue:
                        self.cleaner_queue.put((node_id, task.get("id")))
                    continue

                report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "{}".format(t.main_task_id))
                if not os.path.exists(report_path):
                    os.makedirs(report_path, mode=0o777)
                try:
                    fileobj = BytesIO(report.content)
                    if report.content:
                        file = tarfile.open(fileobj=fileobj, mode="r:bz2")  # errorlevel=0
                        try:
                            file.extractall(report_path)
                            if (node_id, task.get("id")) not in self.cleaner_queue.queue:
                                self.cleaner_queue.put((node_id, task.get("id")))
                        except OSError:
                            log.error("Permission denied: {}".format(report_path))

                        if os.path.exists(t.path):
                            sample = open(t.path, "rb").read()
                            sample_sha256 = hashlib.sha256(sample).hexdigest()
                            destination = os.path.join(CUCKOO_ROOT, "storage", "binaries")
                            if not os.path.exists(destination):
                                os.makedirs(destination, mode=0o755)
                            destination = os.path.join(destination, sample_sha256)
                            if not os.path.exists(destination):
                                shutil.move(t.path, destination)
                            # creating link to analysis folder
                            try:
                                os.symlink(destination, os.path.join(report_path, "binary"))
                            except Exception as e:
                                pass

                    else:
                        log.error("Tar file is empty")
                        # closing StringIO objects
                        fileobj.close()
                except tarfile.ReadError:
                    log.error("Task id: {} from node.id: {} Read error, fileobj.len: {}".format(t.task_id, t.node_id, fileobj.len))
                except Exception as e:
                    logging.exception("Exception: %s" % e)
                    if os.path.exists(os.path.join(report_path, "reports", "report.json")):
                        os.remove(os.path.join(report_path, "reports", "report.json"))
            except Exception as e:
                logging.exception(e)
            self.current_queue[node_id].remove(task["id"])
            db.commit()
        db.close()

    def remove_from_worker(self):
        db = session()
        nodes = dict()
        details = dict()
        for node in db.query(Node).all():
            nodes.setdefault(node.id, node)

        while True:
            node_id, task_id = self.cleaner_queue.get()
            details.setdefault(node_id, list())
            details[node_id].append(str(task_id))
            if task_id in self.t_is_none.get(node_id, list()):
                self.t_is_none[node_id].remove(task_id)

            node = nodes[node_id]
            if node and details[node_id]:
                try:
                    url = os.path.join(node.url, "tasks", "delete_many")
                    log.debug("Removing task id(s): {0} - from node: {1}".format(",".join(details[node_id]), node.name))
                    res = requests.post(url, data={"ids": ",".join(details[node_id]), "username": node.ht_user, "password": node.ht_pass}, verify=False)
                    if res and res.status_code != 200:
                        log.info("{} - {}".format(res.status_code, res.content))
                    details[node_id] = list()
                except Exception as e:
                    log.critical("Error deleting task (task #%d, node %s): %s", task_id, node.name, e)

            db.commit()
            time.sleep(20)
        db.close()


class StatusThread(threading.Thread):

    def submit_tasks(self, node_id, pend_tasks_num, options_like=False, force_push_push=False, db=None):
        # HACK do not create a new session if the current one (passed as parameter) is still valid.
        try:
            node = db.query(Node).filter_by(name=node_id).first()
        except (OperationalError, SQLAlchemyError) as e:
            log.warning("Got an operational Exception when trying to submit tasks: {}".format(e))
            return False

        if node.name not in SERVER_TAGS:
            self.load_vm_tags(db, node.id, node.name)

        limit = 0

        # check if we have tasks with no node_id and task_id, but with main_task_id
        bad_tasks = db.query(Task).filter(Task.node_id==None, Task.task_id==None, Task.main_task_id != None).all()
        if bad_tasks:
            for task in bad_tasks:
                db.delete(task)
                db.commit()
                main_db.set_status(task.main_task_id, TASK_PENDING)

        if node.name != "master":
            # don"t do nothing if nothing in pending
            # Get tasks from main_db submitted through web interface
            main_db_tasks = main_db.list_tasks(status=TASK_PENDING, options_like=options_like, limit=pend_tasks_num, order_by=MD_Task.priority.desc())
            if not main_db_tasks:
                return True
            if main_db_tasks:
                for t in main_db_tasks:
                    force_push = False
                    try:
                        options = get_options(t.options)
                        # check if node exist and its correct
                        if "node=" in t.options:
                            requested_node = options.get("node")
                            if requested_node not in STATUSES:
                                # if the requested node is not available
                                force_push = True
                            elif requested_node != node.name:
                                # otherwise keep looping
                                continue
                        if "timeout=" in t.options:
                            t.timeout = options.get("timeout", 0)
                    except Exception as e:
                        log.error(e, exc_info=True)
                    # wtf are you doing in pendings?
                    tasks = db.query(Task).filter_by(main_task_id=t.id).all()
                    if tasks:
                        for task in tasks:
                            #log.info("Deleting incorrectly uploaded file from dist db, main_task_id: {}".format(t.id))
                            if node.name == "master":
                                main_db.set_status(t.id, TASK_RUNNING)
                            else:
                                main_db.set_status(t.id, TASK_DISTRIBUTED)
                            #db.delete(task)
                        db.commit()
                        continue

                    # Check if file exist, if no wipe from db and continue, rare cases
                    if t.category in ("file", "pcap", "static") and not os.path.exists(t.target):
                        log.info("Task id: {} - File doesn't exist: {}".format(t.id, t.target))
                        main_db.delete_task(t.id)
                        continue

                    # Convert array of tags into comma separated list
                    tags = ",".join([tag.name for tag in t.tags])
                    # Append a comma, to make LIKE searches more precise
                    if tags:
                        tags += ","

                    #sanity check
                    if "x86" in tags and "x64" in tags:
                        tags = tags.replace("x86,", "")
                    if "msoffice-crypt-tmp" in t.target and "password=" in t.options:
                        t.options = t.options.replace("password=", "pwd=")
                    args = dict(package=t.package, category=t.category, timeout=t.timeout, priority=t.priority,
                                options=t.options+",main_task_id={}".format(t.id), machine=t.machine, platform=t.platform,
                                tags=tags, custom=t.custom, memory=t.memory, clock=t.clock,
                                enforce_timeout=t.enforce_timeout, main_task_id=t.id)
                    task = Task(path=t.target, **args)

                    db.add(task)
                    try:
                        db.commit()
                    except Exception as e:
                        log.exception(e)
                        log.info("TASK_FAILED_REPORTING")
                        db.rollback()
                        log.info(e)
                        continue

                    if force_push or force_push_push:
                        # Submit appropriate tasks to node
                        submitted = node_submit_task(task.id, node.id)
                        if submitted:
                            if node.name == "master":
                                main_db.set_status(t.id, TASK_RUNNING)
                            else:
                                main_db.set_status(t.id, TASK_DISTRIBUTED)
                        limit += 1
                        if limit == pend_tasks_num or limit == len(main_db_tasks):
                            db.commit()
                            log.info("Pushed all tasks")
                            return True

                # Only get tasks that have not been pushed yet.
                q = db.query(Task).filter(or_(Task.node_id==None, Task.task_id==None), Task.finished==False)
                if q is None:
                    db.commit()
                    return True
                # Order by task priority and task id.
                q = q.order_by(-Task.priority, Task.main_task_id)
                # if we have node set in options push
                if reporting_conf.distributed.enable_tags:
                    # Create filter query from tasks in ta
                    tags = [getattr(Task, "tags") == ""]
                    for tg in SERVER_TAGS[node.name]:
                        if len(tg.split(",")) == 1:
                            tags.append(getattr(Task, "tags") == (tg + ","))
                        else:
                            tg = tg.split(",")
                            # ie. LIKE "%,%,%,"
                            t_combined = [getattr(Task, "tags").like("%s" % ("%," * len(tg)))]
                            for tag in tg:
                                t_combined.append(getattr(Task, "tags").like("%%%s%%" % (tag + ",")))
                            tags.append(and_(*t_combined))
                    # Filter by available tags
                    q = q.filter(or_(*tags))
                to_upload = q.limit(pend_tasks_num).all()
                if not to_upload:
                    db.commit()
                    log.info("nothing to upload? How? o_O")
                    return True
                # Submit appropriate tasks to node
                log.debug("going to upload {} tasks to node {}".format(pend_tasks_num, node.name))
                for task in to_upload:
                    submitted = node_submit_task(task.id, node.id)
                    if submitted:
                        if node.name == "master":
                            main_db.set_status(task.main_task_id, TASK_RUNNING)
                        else:
                            main_db.set_status(task.main_task_id, TASK_DISTRIBUTED)
                    else:
                        print("something is wrong with submission of task: {}".format(task.id))
                        db.delete(task)
                        db.commit()
                    limit += 1
                    if limit == pend_tasks_num:
                        db.commit()
                        return True
        db.commit()
        return True

    def load_vm_tags(self, db, node_id, node_name):
        global SERVER_TAGS
        # Get available node tags
        machines = db.query(Machine).filter_by(node_id=node_id).all()

        # Get available tag combinations
        ta = set()
        for m in machines:
            for i in range(1, len(m.tags) + 1):
                for tag in combinations(m.tags, i):
                    ta.add(','.join(tag))
        SERVER_TAGS[node_name] = list(ta)

    def run(self):
        global main_db
        global retrieve
        global STATUSES
        MINIMUMQUEUE = dict()

        # handle another user case,
        # when master used to only store data and not process samples

        db = session()
        if reporting_conf.distributed.master_storage_only == "no":
            master = db.query(Node).filter_by(name="master").first()
            if master is None:
                master_storage_only = True
            elif db.query(Machine).filter_by(node_id=master.id).count() == 0:
                master_storage_only = True
        else:
            master_storage_only = True
        db.close()

        #MINIMUMQUEUE but per Node depending of number vms
        for node in db.query(Node).filter_by(enabled=True).all():
            MINIMUMQUEUE[node.name] = db.query(Machine).filter_by(node_id=node.id).count()
            ID2NAME[node.id] = node.name
            self.load_vm_tags(db, node.id, node.name)

        db.commit()
        statuses = {}
        while True:


            # HACK: This exception handling here is a big hack as well as db should check if the
            # there is any issue with the current session (expired or database is down.).
            try:
                # Request a status update on all Cuckoo nodes.
                for node in db.query(Node).filter_by(enabled=True).all():
                    status = node_status(node.url, node.name, node.ht_user, node.ht_pass)
                    if not status:
                        failed_count.setdefault(node.name, 0)
                        failed_count[node.name] += 1
                        # This will declare worker as dead after X failed connections checks
                        if failed_count[node.name] == dead_count:
                            log.info("[-] {} dead".format(node.name))
                            #node.enabled = False
                            db.commit()
                            #STATUSES[node.name]["enabled"] = False
                        continue
                    failed_count[node.name] = 0
                    log.info("Status.. %s -> %s", node.name, status)
                    statuses[node.name] = status
                    statuses[node.name]["enabled"] = True
                    STATUSES = statuses
                    try:
                        #first submit tasks with specified node
                        res = self.submit_tasks(node.name, MINIMUMQUEUE[node.name], options_like="node={}".format(node.name), force_push_push=True, db=db)
                        if not res:
                            continue
                        # Balance the tasks, works fine if no tags are set

                        node_name = min(STATUSES, key=lambda k: STATUSES[k]["completed"] + STATUSES[k]["pending"] + STATUSES[k]["running"])
                        if node_name != node.name:
                            node = db.query(Node).filter_by(name=node_name).first()

                        pend_tasks_num = MINIMUMQUEUE[node.name] - (STATUSES[node.name]["pending"] + STATUSES[node.name]["running"])
                    except KeyError:
                        # servers hotplug
                        MINIMUMQUEUE[node.name] = db.query(Machine).filter_by(node_id=node.id).count()
                        continue
                    if pend_tasks_num <= 0:
                        continue
                    # If - master only used for storage, not check master queue
                    # elif -  master also analyze samples, check master queue
                    # send tasks to workers if master queue has extra tasks(pending)
                    if master_storage_only:
                        res = self.submit_tasks(node.name, pend_tasks_num, db=db)
                        if not res:
                            continue

                    elif statuses.get("master", {}).get("pending", 0) > MINIMUMQUEUE.get("master", 0) and status["pending"] < MINIMUMQUEUE[node.name]:
                        res = self.submit_tasks(node.name, pend_tasks_num, db=db)
                        if not res:
                            continue
                db.commit()
            except Exception as e:
                log.error("Got an exception when trying to check nodes status and submit tasks: {}.".format(e), exc_info=True)

                #ToDo hard test this rollback, this normally only happens on db restart and similar
                db.rollback()
            time.sleep(INTERVAL)

        db.close()


def output_json(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {})
    return resp


class NodeBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("name", type=str)
        self._parser.add_argument("url", type=str)
        self._parser.add_argument("ht_user", type=str, default="")
        self._parser.add_argument("ht_pass", type=str, default="")
        self._parser.add_argument("enabled", type=distutils.util.strtobool, default=None)


class NodeRootApi(NodeBaseApi):
    def get(self):
        nodes = {}
        db = session()
        for node in db.query(Node).all():
            machines = []
            for machine in node.machines.all():
                machines.append(dict(name=machine.name, platform=machine.platform, tags=machine.tags,))

            nodes[node.name] = dict(name=node.name, url=node.url, machines=machines, enabled=node.enabled,)
        db.close()
        return dict(nodes=nodes)

    def post(self):
        db = session()
        args = self._parser.parse_args()
        node = Node(name=args["name"], url=args["url"], ht_user=args["ht_user"], ht_pass=args["ht_pass"])

        if db.query(Node).filter_by(name=args["name"]).first():
            return dict(success=False, message="Node called %s already exists" % args["name"])

        machines = []
        for machine in node_list_machines(args["url"], args["ht_user"], args["ht_pass"]):
            machines.append(dict(name=machine.name, platform=machine.platform, tags=machine.tags,))
            node.machines.append(machine)
            db.add(machine)

        db.add(node)
        db.commit()
        db.close()
        return dict(name=args["name"], machines=machines)


class NodeApi(NodeBaseApi):
    def get(self, name):
        db = session()
        node = db.query(Node).filter_by(name=name).first()
        db.close()
        return dict(name=node.name, url=node.url)

    def put(self, name):
        db = session()
        args = self._parser.parse_args()
        node = db.query(Node).filter_by(name=name).first()

        if not node:
            return dict(error=True, error_value="Node doesn't exist")

        for k, v in args.items():
            if v is not None:
                setattr(node, k, v)
        db.commit()
        return dict(error=False, error_value="Successfully modified node: %s" % node.name)

    def delete(self, name):
        db = session()
        node = db.query(Node).filter_by(name=name).first()
        node.enabled = False
        db.commit()
        db.close()


class TaskBaseApi(RestResource):
    def __init__(self, *args, **kwargs):
        RestResource.__init__(self, *args, **kwargs)

        self._parser = reqparse.RequestParser()
        self._parser.add_argument("package", type=str, default="")
        self._parser.add_argument("timeout", type=int, default=0)
        self._parser.add_argument("priority", type=int, default=1)
        self._parser.add_argument("options", type=str, default="")
        self._parser.add_argument("machine", type=str, default="")
        self._parser.add_argument("platform", type=str, default="windows")
        self._parser.add_argument("tags", type=str, default="")
        self._parser.add_argument("custom", type=str, default="")
        self._parser.add_argument("memory", type=str, default="0")
        self._parser.add_argument("clock", type=int)
        self._parser.add_argument("enforce_timeout", type=bool, default=False)


class TaskInfo(RestResource):
    def get(self, main_task_id):
        response = {"status": 0}
        db = session()
        task_db = db.query(Task).filter_by(main_task_id=main_task_id).first()
        if task_db and task_db.node_id:
            node = db.query(Node).filter_by(id=task_db.node_id).first()
            response = {"status": 1, "task_id": task_db.task_id, "url": node.url, "name": node.name}
        else:
            response = {"status": "pending"}
        db.close()
        return response


class StatusRootApi(RestResource):
    def get(self):
        null = None
        db = session()
        tasks = db.query(Task).filter(Task.node_id != null)

        tasks = dict(
            processing=tasks.filter_by(finished=False).count(),
            processed=tasks.filter_by(finished=True).count(),
            pending=db.query(Task).filter_by(node_id=None).count(),
        )
        db.close()
        return jsonify({"nodes": STATUSES, "tasks": tasks})


class DistRestApi(RestApi):
    def __init__(self, *args, **kwargs):
        RestApi.__init__(self, *args, **kwargs)
        self.representations = {
            "application/json": output_json,
        }


def update_machine_table(node_name):
    db = session()
    node = db.query(Node).filter_by(name=node_name).first()

    # get new vms
    new_machines = node_list_machines(node.url, node.ht_user, node.ht_pass)

    # delete all old vms
    _ = db.query(Machine).filter_by(node_id=node.id).delete()

    log.info("Available VM's on %s:" % node_name)
    # replace with new vms
    for machine in new_machines:
        log.info("-->\t%s" % machine.name)
        node.machines.append(machine)
        db.add(machine)

    db.commit()

    log.info("Updated the machine table for node: %s" % node_name)


def delete_vm_on_node(node_name, vm_name):
    db = session()
    node = db.query(Node).filter_by(name=node_name).first()
    vm = db.query(Machine).filter_by(name=vm_name, node_id=node.id).first()

    if not vm:
        log.error("The selected VM does not exist")
        return

    status = node.delete_machine(vm_name)

    if status:
        # delete vm in dist db
        vm = db.query(Machine).filter_by(name=vm_name, node_id=node.id).delete()
        db.commit()
    db.close()


def node_enabled(node_name, status):
    db = session()
    node = db.query(Node).filter_by(name=node_name).first()
    node.enabled = status
    db.commit()
    db.close()


def cron_cleaner():
    """ Method that runs forever """

    # Check if we are not runned
    if os.path.exists("/tmp/dist_cleaner.pid"):
        log.info("we running")
        sys.exit()

    pid = open("/tmp/dist_cleaner.pid", "wb")
    pid.write(b"")
    pid.close()

    db = session()
    nodes = dict()
    details = dict()

    for node in db.query(Node).all():
        nodes.setdefault(node.id, node)

    tasks = db.query(Task).filter_by(notificated=True, deleted=False).order_by(Task.id.desc()).all()
    if tasks is not None:
        for task in tasks:
            node = nodes[task.node_id]
            if node:
                details.setdefault(node.id, list())
                details[node.id].append(str(task.task_id))
                task.deleted = True

        for node in details:
            if node and not details[node]:
                continue
            try:
                url = os.path.join(nodes[node].url, "tasks", "delete_many")
                log.info("Removing task id(s): {0} - from node: {1}".format(",".join(details[node]), nodes[node].name))
                res = requests.post(url, data={"ids": ",".join(details[node]), "username": nodes[node].ht_user, "password": nodes[node].ht_pass}, verify=False)
                if res and res.status_code != 200:
                    log.info("{} - {}".format(res.status_code, res.content))
                    db.rollback()
            except Exception as e:
                log.critical("Error deleting task (tasks #%s, node %s): %s", ",".join(details[node]), nodes[node].name, e)
                db.rollback()

    db.commit()
    db.close()
    os.remove("/tmp/dist_cleaner.pid")


def create_app(database_connection):
    # http://flask-sqlalchemy.pocoo.org/2.1/config/
    # https://github.com/tmeryu/flask-sqlalchemy/blob/master/flask_sqlalchemy/__init__.py#L787
    app = Flask("Distributed CAPE")
    # app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
    app.config["SQLALCHEMY_POOL_SIZE"] = int(reporting_conf.distributed.dist_threads) + 5
    app.config["SECRET_KEY"] = os.urandom(32)
    restapi = DistRestApi(app)
    restapi.add_resource(NodeRootApi, "/node")
    restapi.add_resource(NodeApi, "/node/<string:name>")
    restapi.add_resource(StatusRootApi, "/status")
    restapi.add_resource(TaskInfo, "/task/<int:main_task_id>")

    return app


def init_logging(debug=False):
    formatter = logging.Formatter("%(asctime)s %(levelname)s:%(module)s:%(threadName)s - %(message)s")
    log = logging.getLogger()

    if not os.path.exists(os.path.join(CUCKOO_ROOT, "log")):
        os.makedirs(os.path.join(CUCKOO_ROOT, "log"))
    fh = handlers.TimedRotatingFileHandler(os.path.join(CUCKOO_ROOT, "log", "dist.log"), when="midnight", backupCount=10)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    handler_stdout = logging.StreamHandler(sys.stdout)
    handler_stdout.setFormatter(formatter)
    log.addHandler(handler_stdout)

    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    return log

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="0.0.0.0", help="Host to listen on")
    p.add_argument("port", nargs="?", type=int, default=9003, help="Port to listen on")
    p.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    p.add_argument("--uptime-logfile", type=str, help="Uptime logfile path")
    p.add_argument("--node", type=str, help="Node name to update in distributed DB")
    p.add_argument("--delete-vm", type=str, help="VM name to delete from Node")
    p.add_argument("--disable", action="store_true", help="Disable Node provided in --node")
    p.add_argument("--enable", action="store_true", help="Enable Node provided in --node")
    p.add_argument("--clean-workers", action="store_true", help="Delete reported and notificated tasks from workers")
    p.add_argument("-ec", "--enable-clean", action="store_true", help="Enable delete tasks from nodes, also will remove tasks submited by humands and not dist")
    p.add_argument("-ef", "--enable-failed-clean", action="store_true", default=False, help="Enable delete failed tasks from nodes, also will remove tasks submited by humands and not dist")
    p.add_argument("-fr", "--force-reported", action="store", help="change report to reported")

    args = p.parse_args()
    log = init_logging(args.debug)

    if args.enable_clean:
        cron_cleaner()
        sys.exit()

    if args.force_reported:
        # set completed_on time
        main_db.set_status(args.force_reported, TASK_DISTRIBUTED_COMPLETED)
        # set reported time
        main_db.set_status(args.force_reported, TASK_REPORTED)
        sys.exit()

    delete_enabled = args.enable_clean
    failed_clean_enabled = args.enable_failed_clean
    if args.node:
        if args.delete_vm:
            delete_vm_on_node(args.node, args.delete_vm)
        if args.enable:
            node_enabled(args.node, True)
        if args.disable:
            node_enabled(args.node, False)
        if not args.delete_vm and not args.disable and not args.enable:
            update_machine_table(args.node)
        sys.exit()

    else:
        app = create_app(database_connection=reporting_conf.distributed.db)

        t = StatusThread()
        t.daemon = True
        t.start()

        retrieve = Retriever()
        retrieve.daemon = True
        retrieve.start()

        app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)

else:
    app = create_app(database_connection=reporting_conf.distributed.db)

    # this allows run it with gunicorn/uwsgi
    log = init_logging(True)
    retrieve = Retriever()
    retrieve.daemon = True
    retrieve.start()

    t = StatusThread()
    t.daemon = True
    t.start()
