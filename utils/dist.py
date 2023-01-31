# encoding: utf-8
#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# ToDo
# https://github.com/cuckoosandbox/cuckoo/pull/1694/files
import argparse
import distutils.util
import hashlib
import json
import logging
import os
import queue
import shutil
import sys
import threading
import time
import timeit
import zipfile
from contextlib import suppress
from datetime import datetime, timedelta
from io import BytesIO
from itertools import combinations
from logging import handlers
from urllib.parse import urlparse

from sqlalchemy import and_, or_
from sqlalchemy.exc import OperationalError, SQLAlchemyError

try:
    import pyzipper
except ImportError:
    sys.exti("Missed pyzipper dependency: pip3 install pyzipper -U")

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dist_db import ExitNodes, Machine, Node, Task, create_session
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_get_size, path_mkdir, path_mount_point, path_write_file
from lib.cuckoo.common.socket_utils import send_socket_command
from lib.cuckoo.common.utils import get_options
from lib.cuckoo.core.database import (
    TASK_BANNED,
    TASK_DISTRIBUTED,
    TASK_DISTRIBUTED_COMPLETED,
    TASK_FAILED_REPORTING,
    TASK_PENDING,
    TASK_REPORTED,
    TASK_RUNNING,
    Database,
)
from lib.cuckoo.core.database import Task as MD_Task

dist_conf = Config("distributed")

HAVE_GCP = False
if dist_conf.GCP.enabled:
    from lib.cuckoo.common.gcp import HAVE_GCP, autodiscovery

# we need original db to reserve ID in db,
# to store later report, from master or worker

reporting_conf = Config("reporting")
web_conf = Config("web")

zip_pwd = web_conf.zipped_download.zip_pwd
if not isinstance(zip_pwd, bytes):
    zip_pwd = zip_pwd.encode()

# init
logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

dist_ignore_patterns = shutil.ignore_patterns(*[pattern.strip() for pattern in dist_conf.distributed.ignore_patterns.split(",")])
STATUSES = {}
ID2NAME = {}
SERVER_TAGS = {}
main_db = Database()

dead_count = 5
if dist_conf.distributed.dead_count:
    dead_count = dist_conf.distributed.dead_count


NFS_FETCH = dist_conf.distributed.get("nfs")
RESTAPI_FETCH = dist_conf.distributed.get("restapi")

INTERVAL = 10

# controller of dead nodes
failed_count = {}
# status controler count to reset number
status_count = {}

lock_retriever = threading.Lock()
dist_lock = threading.BoundedSemaphore(int(dist_conf.distributed.dist_threads))
fetch_lock = threading.BoundedSemaphore(1)

delete_enabled = False
failed_clean_enabled = False


def required(package):
    sys.exit("The %s package is required: pip3 install %s" % (package, package))


try:
    from flask import Flask, jsonify, make_response
except ImportError:
    required("flask")

try:
    import requests
except ImportError:
    required("requests")

with suppress(AttributeError):
    requests.packages.urllib3.disable_warnings()

try:
    from flask_restful import Api as RestApi
    from flask_restful import Resource as RestResource
    from flask_restful import abort, reqparse
except ImportError:
    required("flask-restful")

session = create_session(dist_conf.distributed.db, echo=False)

binaries_folder = os.path.join(CUCKOO_ROOT, "storage", "binaries")
if not path_exists(binaries_folder):
    path_mkdir(binaries_folder, mode=0o755)


def node_status(url: str, name: str, apikey: str) -> dict:
    try:
        r = requests.get(
            os.path.join(url, "cuckoo", "status/"), headers={"Authorization": f"Token {apikey}"}, verify=False, timeout=300
        )
        return r.json().get("data", {})
    except Exception as e:
        log.critical("Possible invalid CAPE node (%s): %s", name, e)
    return {}


def node_fetch_tasks(status, url, apikey, action="fetch", since=0):
    try:
        url = os.path.join(url, "tasks", "list/")
        params = dict(status=status, ids=True)
        if action == "fetch":
            params["completed_after"] = since
        r = requests.get(url, params=params, headers={"Authorization": f"Token {apikey}"}, verify=False)
        if not r.ok:
            log.error(f"Error fetching task list. Status code: {r.status_code} - {r.url}")
            log.info("Saving error to /tmp/dist_error.html")
            _ = path_write_file("/tmp/dist_error.html", r.content)
            return []
        return r.json().get("data", [])
    except Exception as e:
        log.critical("Error listing completed tasks (node %s): %s", url, e)

    return []


def node_list_machines(url, apikey):
    try:
        r = requests.get(os.path.join(url, "machines", "list/"), headers={"Authorization": f"Token {apikey}"}, verify=False)
        for machine in r.json()["data"]:
            yield Machine(name=machine["name"], platform=machine["platform"], tags=machine["tags"])
    except Exception as e:
        abort(404, message="Invalid CAPE node (%s): %s" % (url, e))


def node_list_exitnodes(url, apikey):
    try:
        r = requests.get(os.path.join(url, "exitnodes/"), headers={"Authorization": f"Token {apikey}"}, verify=False)
        for exitnode in r.json()["data"]:
            yield exitnode
    except Exception as e:
        abort(404, message="Invalid CAPE node (%s): %s" % (url, e))


def node_get_report(task_id, fmt, url, apikey, stream=False):
    try:
        url = os.path.join(url, "tasks", "get", "report", "%d/" % task_id, fmt)
        return requests.get(url, stream=stream, headers={"Authorization": f"Token {apikey}"}, verify=False, timeout=800)
    except Exception as e:
        log.critical("Error fetching report (task #%d, node %s): %s", task_id, url, e)


def node_get_report_nfs(task_id, worker_name, main_task_id) -> bool:

    worker_path = os.path.join(CUCKOO_ROOT, dist_conf.NFS.mount_folder, str(worker_name))

    if not path_mount_point(worker_path):
        log.error(f"[-] Worker: {worker_name} is not mounted to: {worker_path}!")
        return True

    worker_path = os.path.join(worker_path, "storage", "analyses", str(task_id))

    if not path_exists(worker_path):
        log.error(f"File on destiny doesn't exist: {worker_path}")
        return True

    analyses_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(main_task_id))
    if not path_exists(analyses_path):
        path_mkdir(analyses_path, mode=0o755, exist_ok=False)

    try:
        shutil.copytree(worker_path, analyses_path, ignore=dist_ignore_patterns, ignore_dangling_symlinks=True, dirs_exist_ok=True)
    except Exception as e:
        log.exception(e)
        return False

    return True


def _delete_many(node, ids, nodes, db):

    if nodes[node].name == "master":
        return
    try:
        url = os.path.join(nodes[node].url, "tasks", "delete_many/")
        apikey = nodes[node].apikey
        log.debug("Removing task id(s): {0} - from node: {1}".format(ids, nodes[node].name))
        res = requests.post(
            url,
            headers={"Authorization": f"Token {apikey}"},
            data={"ids": ids, "delete_mongo": False},
            verify=False,
        )
        if res and res.status_code != 200:
            log.info("{} - {}".format(res.status_code, res.content))
            db.rollback()

    except Exception as e:
        log.critical("Error deleting task (tasks #%s, node %s): %s", ids, nodes[node].name, e)
        db.rollback()


def node_submit_task(task_id, node_id):

    db = session()
    node = db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey).filter_by(id=node_id).first()
    task = db.query(Task).filter_by(id=task_id).first()
    check = False
    try:
        if node.name == "master":
            return

        # Remove the earlier appended comma
        if task.tags:
            if task.tags[-1] == ",":
                task.tags = task.tags[:-1]
        apikey = node.apikey
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
            route=task.route,
        )

        if task.category in ("file", "pcap"):
            if task.category == "pcap":
                data = {"pcap": 1}

            url = os.path.join(node.url, "tasks", "create", "file/")
            # If the file does not exist anymore, ignore it and move on
            # to the next file.
            if not path_exists(task.path):
                task.finished = True
                task.retrieved = True
                main_db.set_status(task.main_task_id, TASK_FAILED_REPORTING)
                try:
                    db.commit()
                except Exception as e:
                    log.exception(e)
                    db.rollback()
                return
            try:
                files = dict(file=open(task.path, "rb"))
                r = requests.post(url, data=data, files=files, headers={"Authorization": f"Token {apikey}"}, verify=False)
            except OSError:
                task.finished = True
                task.retrieved = True
                main_db.set_status(task.main_task_id, TASK_FAILED_REPORTING)
                try:
                    db.commit()
                except Exception as e:
                    log.exception(e)
                    db.rollback()
                return
        elif task.category == "url":
            url = os.path.join(node.url, "tasks", "create", "url/")
            r = requests.post(
                url, data={"url": task.path, "options": task.options}, headers={"Authorization": f"Token {apikey}"}, verify=False
            )
        elif task.category == "static":
            url = os.path.join(node.url, "tasks", "create", "static/")
            files = dict(file=open(task.path, "rb"))
            r = requests.post(url, data=data, files=files, headers={"Authorization": f"Token {apikey}"}, verify=False)
        else:
            log.debug("Target category is: {}".format(task.category))
            db.close()
            return

        # encoding problem
        if r.status_code == 500 and task.category == "file":
            r = requests.post(url, data=data, files={"file": ("file", open(task.path, "rb").read())}, verify=False)

        # Zip files preprocessed, so only one id
        if r and r.status_code == 200:
            if (
                "task_ids" in r.json().get("data", {})
                and len(r.json().get("data", {})["task_ids"]) > 0
                and r.json().get("data", {})["task_ids"] is not None
            ):
                task.task_id = r.json().get("data", {})["task_ids"][0]
                check = True
            elif r.json().get("task_id", 0) > 0:
                task.task_id = r.json()["task_id"]
                check = True
            else:
                log.debug(
                    "Failed to submit task {} to node: {}, code: {}, msg: {}".format(task_id, node.name, r.status_code, r.content)
                )

            log.debug("Submitted task to worker: {} - {} - {}".format(node.name, task.task_id, task.main_task_id))

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


# class Retriever():
class Retriever(threading.Thread):
    def run(self):
        self.cleaner_queue = queue.Queue()
        self.fetcher_queue = queue.Queue()
        self.cfg = Config()
        self.t_is_none = {}
        self.status_count = {}
        self.current_queue = {}
        self.current_two_queue = {}
        self.stop_dist = threading.Event()
        self.threads = []

        if dist_conf.GCP.enabled and HAVE_GCP:
            # autodiscovery is generic name so in case if we have AWS or Azure it should implement the logic inside
            thread = threading.Thread(target=autodiscovery, name="autodiscovery", args=())
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        for _ in range(int(dist_conf.distributed.dist_threads)):
            if dist_lock.acquire(blocking=False):
                if NFS_FETCH:
                    thread = threading.Thread(target=self.fetch_latest_reports_nfs, name="fetch_latest_reports_nfs", args=())
                elif RESTAPI_FETCH:
                    thread = threading.Thread(target=self.fetch_latest_reports, name="fetch_latest_reports", args=())
                if RESTAPI_FETCH or NFS_FETCH:
                    thread.daemon = True
                    thread.start()
                    self.threads.append(thread)

        if fetch_lock.acquire(blocking=False):
            thread = threading.Thread(target=self.fetcher, name="fetcher", args=())
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        # Delete the task and all its associated files.
        # (It will still remain in the nodes" database, though.)
        if dist_conf.distributed.remove_task_on_worker or delete_enabled:
            thread = threading.Thread(target=self.remove_from_worker, name="remove_from_worker", args=())
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        if dist_conf.distributed.failed_cleaner or failed_clean_enabled:
            thread = threading.Thread(target=self.failed_cleaner, name="failed_to_clean", args=())
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        thread = threading.Thread(target=self.free_space_mon, name="free_space_mon", args=())
        thread.daemon = True
        thread.start()
        self.threads.append(thread)

        if reporting_conf.callback.enabled:
            thread = threading.Thread(target=self.notification_loop, name="notification_loop", args=())
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

        # thread monitoring
        for thr in self.threads:
            try:
                thr.join(timeout=0.0)
                log.info(f"Thread: {thr.getName()} - Alive: {thr.is_alive()}")
            except Exception as e:
                log.exception(e)
            time.sleep(60)

    # import from utils
    def free_space_mon(self):
        # If not enough free disk space is available, then we print an
        # error message and wait another round (this check is ignored
        # when the freespace configuration variable is set to zero).
        while True:
            if self.cfg.cuckoo.freespace:
                # Resolve the full base path to the analysis folder, just in
                # case somebody decides to make a symbolic link out of it.
                dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")

                if hasattr(os, "statvfs") and path_exists(dir_path):
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

    def notification_loop(self):
        urls = reporting_conf.callback.url.split(",")
        headers = {"x-api-key": reporting_conf.callback.key}

        db = session()
        while True:

            tasks = db.query(Task).filter_by(finished=True, retrieved=True, notificated=False).order_by(Task.id.desc()).all()
            if tasks is not None:
                for task in tasks:
                    main_db.set_status(task.main_task_id, TASK_REPORTED)
                    log.debug("reporting main_task_id: {}".format(task.main_task_id))
                    for url in urls:
                        try:
                            res = requests.post(url, headers=headers, data=json.dumps({"task_id": int(task.main_task_id)}))
                            if res and res.ok:
                                # log.info(res.content)
                                task.notificated = True
                                # db.commit()
                                # db.refresh(task)
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
            for node in db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey).filter_by(enabled=True).all():
                log.info("Checking for failed tasks on: {}".format(node.name))
                for status in ("failed_analysis", "failed_processing"):
                    for task in node_fetch_tasks(status, node.url, node.apikey, action="delete"):
                        t = db.query(Task).filter_by(task_id=task["id"], node_id=node.id).order_by(Task.id.desc()).first()
                        if t is not None:
                            log.info(
                                "Cleaning failed_analysis for id:{}, node:{}: main_task_id: {}".format(
                                    t.id, t.node_id, t.main_task_id
                                )
                            )
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
        """Method that runs forever"""
        last_checks = {}
        # to not exit till cleaner works
        db = session()
        while not self.stop_dist.isSet():
            # .with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.last_check)
            for node in db.query(Node).filter_by(enabled=True).all():
                self.status_count.setdefault(node.name, 0)
                last_checks.setdefault(node.name, 0)
                last_checks[node.name] += 1
                # reset it every 10 calls
                if hasattr(node, "last_check") and node.last_check:
                    last_check = int(node.last_check.strftime("%s"))
                else:
                    last_check = 0
                if last_checks[node.name] == 3:
                    last_check = 0
                    last_checks[node.name] = 0
                limit = 0
                for task in node_fetch_tasks("reported", node.url, node.apikey, "fetch", last_check):
                    tasker = (
                        db.query(Task)
                        .filter_by(finished=False, retrieved=False, task_id=task["id"], node_id=node.id, deleted=False)
                        .order_by(Task.id.desc())
                        .first()
                    )
                    if tasker is None:
                        # log.debug(f"Node ID: {node.id} - Task ID: {task['id']} - adding to cleaner")
                        self.cleaner_queue.put((node.id, task["id"]))
                        continue
                    try:
                        if (
                            task["id"] not in self.current_queue.get(node.id, [])
                            and (task["id"], node.id) not in self.fetcher_queue.queue
                        ):
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
    def fetch_latest_reports_nfs(self):
        db = session()
        # to not exit till cleaner works
        while not self.stop_dist.isSet():
            task, node_id = self.fetcher_queue.get()

            self.current_queue.setdefault(node_id, []).append(task["id"])

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
                    self.t_is_none.setdefault(node_id, []).append(task["id"])

                    # sometime it not deletes tasks in workers of some fails or something
                    # this will do the trick
                    # log.debug("tf else,")
                    if (node_id, task.get("id")) not in self.cleaner_queue.queue:
                        self.cleaner_queue.put((node_id, task.get("id")))
                    continue

                log.debug(
                    "Fetching dist report for: id: {}, task_id: {}, main_task_id: {} from node: {}".format(
                        t.id, t.task_id, t.main_task_id, ID2NAME[t.node_id] if t.node_id in ID2NAME else t.node_id
                    )
                )
                # set completed_on time
                main_db.set_status(t.main_task_id, TASK_DISTRIBUTED_COMPLETED)
                # set reported time
                main_db.set_status(t.main_task_id, TASK_REPORTED)

                # Fetch each requested report.
                report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", f"{t.main_task_id}")
                # ToDo option
                node = db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey).filter_by(id=node_id).first()
                start_copy = timeit.default_timer()
                copied = node_get_report_nfs(t.task_id, node.name, t.main_task_id)
                timediff = timeit.default_timer() - start_copy
                log.info(
                    f"It took {timediff:.2f} seconds to copy report {t.task_id} from node: {node.name} for task: {t.main_task_id}"
                )

                if not copied:
                    log.error(f"Can't copy report {t.task_id} from node: {node.name} for task: {t.main_task_id}")
                    continue

                # this doesn't exist for some reason
                if path_exists(t.path):
                    sample = open(t.path, "rb").read()
                    sample_sha256 = hashlib.sha256(sample).hexdigest()
                    destination = os.path.join(binaries_folder, sample_sha256)
                    if not path_exists(destination) and path_exists(t.path):
                        try:
                            shutil.move(t.path, destination)
                        except FileNotFoundError as e:
                            print(f"Failed to move: {t.path} - {e}")
                            pass

                    # creating link to analysis folder
                    if path_exists(destination):
                        try:
                            os.symlink(destination, os.path.join(report_path, "binary"))
                        except Exception as e:
                            print(f"Failed link binary: {e}")
                            pass

                t.retrieved = True
                t.finished = True
                db.commit()

            except Exception as e:
                log.exception(e)
            self.current_queue[node_id].remove(task["id"])
            db.commit()
        db.close()

    # This should be executed as external thread as it generates bottle neck
    def fetch_latest_reports(self):
        db = session()
        # to not exit till cleaner works
        while not self.stop_dist.isSet():
            task, node_id = self.fetcher_queue.get()

            self.current_queue.setdefault(node_id, []).append(task["id"])

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
                    self.t_is_none.setdefault(node_id, []).append(task["id"])

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

                # Fetch each requested report.
                node = db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey).filter_by(id=node_id).first()
                report = node_get_report(t.task_id, "dist/", node.url, node.apikey, stream=True)

                if report is None:
                    log.info("dist report retrieve failed NONE: task_id: {} from node: {}".format(t.task_id, node_id))
                    continue

                if report.status_code != 200:
                    log.info(
                        "dist report retrieve failed - status_code {}: task_id: {} from node: {}".format(
                            report.status_code, t.task_id, node_id
                        )
                    )
                    if report.status_code == 400 and (node_id, task.get("id")) not in self.cleaner_queue.queue:
                        self.cleaner_queue.put((node_id, task.get("id")))
                        log.info(f"Status code: {report.status_code} - MSG: {report.text}")
                    continue

                log.info(f"Report size for task {t.task_id} is: {int(report.headers.get('Content-length', 1))/int(1<<20):,.0f} MB")

                report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "{}".format(t.main_task_id))
                if not path_exists(report_path):
                    path_mkdir(report_path, mode=0o755)
                try:
                    if report.content:
                        # with pyzipper.AESZipFile(BytesIO(report.content)) as zf:
                        #    zf.setpassword(zip_pwd)
                        with zipfile.ZipFile(BytesIO(report.content)) as zf:
                            try:
                                zf.extractall(report_path)
                                if (node_id, task.get("id")) not in self.cleaner_queue.queue:
                                    self.cleaner_queue.put((node_id, task.get("id")))
                            except OSError:
                                log.error("Permission denied: {}".format(report_path))

                        if path_exists(t.path):
                            sample = open(t.path, "rb").read()
                            sample_sha256 = hashlib.sha256(sample).hexdigest()
                            destination = os.path.join(CUCKOO_ROOT, "storage", "binaries")
                            if not path_exists(destination):
                                path_mkdir(destination, mode=0o755)
                            destination = os.path.join(destination, sample_sha256)
                            if not path_exists(destination) and path_exists(t.path):
                                shutil.move(t.path, destination)
                            # creating link to analysis folder
                            if path_exists(t.path):
                                with suppress(Exception):
                                    os.symlink(destination, os.path.join(report_path, "binary"))

                        else:
                            log.debug(f"{t.path} doesn't exist")

                        t.retrieved = True
                        t.finished = True
                        db.commit()

                    else:
                        log.error("Zip file is empty")
                except pyzipper.zipfile.BadZipFile:
                    log.error("File is not a zip file")
                except Exception as e:
                    log.exception("Exception: %s" % e)
                    if path_exists(os.path.join(report_path, "reports", "report.json")):
                        path_delete(os.path.join(report_path, "reports", "report.json"))
            except Exception as e:
                log.exception(e)
            self.current_queue[node_id].remove(task["id"])
            db.commit()
        db.close()

    def remove_from_worker(self):
        db = session()
        nodes = {}
        for node in db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey).all():
            nodes.setdefault(node.id, node)

        while True:
            details = {}
            for _ in range(self.cleaner_queue.qsize()):
                node_id, task_id = self.cleaner_queue.get()
                details.setdefault(node_id, []).append(str(task_id))
                if task_id in self.t_is_none.get(node_id, []):
                    self.t_is_none[node_id].remove(task_id)

            for node_id in details:
                node = nodes[node_id]
                if node and details[node_id]:
                    ids = ",".join(list(set(details[node_id])))
                    _delete_many(node_id, ids, nodes, db)

            db.commit()
            time.sleep(20)


class StatusThread(threading.Thread):
    def submit_tasks(self, node_id, pend_tasks_num, options_like=False, force_push_push=False, db=None):
        # HACK do not create a new session if the current one (passed as parameter) is still valid.
        try:
            node = db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey).filter_by(name=node_id).first()
        except (OperationalError, SQLAlchemyError) as e:
            log.warning(f"Got an operational Exception when trying to submit tasks: {e}")
            return False

        if node.name not in SERVER_TAGS:
            self.load_vm_tags(db, node.id, node.name)

        limit = 0

        # check if we have tasks with no node_id and task_id, but with main_task_id
        bad_tasks = db.query(Task).filter(Task.node_id.is_(None), Task.task_id.is_(None), Task.main_task_id.is_not(None)).all()
        if bad_tasks:
            for task in bad_tasks:
                db.delete(task)
                db.commit()
                main_db.set_status(task.main_task_id, TASK_PENDING)

        if node.name != "master":
            # don"t do nothing if nothing in pending
            # Get tasks from main_db submitted through web interface
            main_db_tasks = main_db.list_tasks(
                status=TASK_PENDING, options_like=options_like, limit=pend_tasks_num, order_by=MD_Task.priority.desc()
            )
            if not main_db_tasks:
                return True
            if main_db_tasks:
                for t in main_db_tasks:
                    options = get_options(t.options)
                    # Check if file exist, if no wipe from db and continue, rare cases
                    if t.category in ("file", "pcap", "static"):

                        if not path_exists(t.target):
                            log.info(f"Task id: {t.id} - File doesn't exist: {t.target}")
                            main_db.set_status(t.id, TASK_BANNED)
                            continue

                        if not web_conf.general.allow_ignore_size and "ignore_size_check" not in options:
                            # We can't upload size bigger than X to our workers. In case we extract archive that contains bigger file.
                            file_size = path_get_size(t.target)
                            if file_size > web_conf.general.max_sample_size:
                                log.warning(f"File size: {file_size} is bigger than allowed: {web_conf.general.max_sample_size}")
                                main_db.set_status(t.id, TASK_BANNED)
                                continue

                    force_push = False
                    try:
                        # check if node exist and its correct
                        if options.get("node"):
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
                            # log.info("Deleting incorrectly uploaded file from dist db, main_task_id: {}".format(t.id))
                            if node.name == "master":
                                main_db.set_status(t.id, TASK_RUNNING)
                            else:
                                main_db.set_status(t.id, TASK_DISTRIBUTED)
                            # db.delete(task)
                        db.commit()
                        continue

                    # Convert array of tags into comma separated list
                    tags = ",".join([tag.name for tag in t.tags])
                    # Append a comma, to make LIKE searches more precise
                    if tags:
                        tags += ","

                    # sanity check
                    if "x86" in tags and "x64" in tags:
                        tags = tags.replace("x86,", "")

                    if "msoffice-crypt-tmp" in t.target and "password=" in t.options:
                        # t.options = t.options.replace(f"password={options['password']}", "")
                        options["password"]
                    # if options.get("node"):
                    #    t.options = t.options.replace(f"node={options['node']}", "")
                    if options.get("node"):
                        del options["node"]
                    t.options = ",".join([f"{k}={v}" for k, v in options.items()])
                    if t.options:
                        t.options += ","

                    t.options += "main_task_id={}".format(t.id)
                    args = dict(
                        package=t.package,
                        category=t.category,
                        timeout=t.timeout,
                        priority=t.priority,
                        options=t.options,
                        machine=t.machine,
                        platform=t.platform,
                        tags=tags,
                        custom=t.custom,
                        memory=t.memory,
                        clock=t.clock,
                        enforce_timeout=t.enforce_timeout,
                        main_task_id=t.id,
                        route=t.route,
                    )
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
                        if limit in (pend_tasks_num, len(main_db_tasks)):
                            db.commit()
                            log.info("Pushed all tasks")
                            return True

                # Only get tasks that have not been pushed yet.
                q = db.query(Task).filter(or_(Task.node_id.is_(None), Task.task_id.is_(None)), Task.finished.is_(False))
                if q is None:
                    db.commit()
                    return True
                # Order by task priority and task id.
                q = q.order_by(-Task.priority, Task.main_task_id)
                # if we have node set in options push
                if dist_conf.distributed.enable_tags:
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
                        log.info("something is wrong with submission of task: {}".format(task.id))
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
                    ta.add(",".join(tag))
        SERVER_TAGS[node_name] = list(ta)

    def run(self):
        global main_db
        global retrieve
        global STATUSES
        MINIMUMQUEUE = {}

        # handle another user case,
        # when master used to only store data and not process samples

        db = session()
        master_storage_only = False
        if not dist_conf.distributed.master_storage_only:
            master = db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey).filter_by(name="master").first()
            if master is None:
                master_storage_only = True
            elif db.query(Machine).filter_by(node_id=master.id).count() == 0:
                master_storage_only = True
        else:
            master_storage_only = True
        db.close()

        # MINIMUMQUEUE but per Node depending of number vms
        for node in (
            db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.enabled).filter_by(enabled=True).all()
        ):
            MINIMUMQUEUE[node.name] = db.query(Machine).filter_by(node_id=node.id).count()
            ID2NAME[node.id] = node.name
            self.load_vm_tags(db, node.id, node.name)

        db.commit()
        statuses = {}
        while True:

            # HACK: This exception handling here is a big hack as well as db should check if the
            # there is any issue with the current session (expired or database is down.).
            try:
                # Remove disabled nodes
                for node in (
                    db.query(Node)
                    .with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.enabled)
                    .filter_by(enabled=False)
                    .all()
                    or []
                ):
                    if node.name in STATUSES:
                        STATUSES.pop(node.name)

                # Request a status update on all CAPE nodes.
                for node in (
                    db.query(Node)
                    .with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.enabled)
                    .filter_by(enabled=True)
                    .all()
                ):
                    status = node_status(node.url, node.name, node.apikey)
                    if not status:
                        failed_count.setdefault(node.name, 0)
                        failed_count[node.name] += 1
                        # This will declare worker as dead after X failed connections checks
                        if failed_count[node.name] == dead_count:
                            log.info("[-] {} dead".format(node.name))
                            # node.enabled = False
                            db.commit()
                            if node.name in STATUSES:
                                STATUSES.pop(node.name)
                        continue
                    failed_count[node.name] = 0
                    log.info("Status.. %s -> %s", node.name, status["tasks"])
                    statuses[node.name] = status
                    statuses[node.name]["enabled"] = True
                    STATUSES = statuses
                    try:
                        # first submit tasks with specified node
                        res = self.submit_tasks(
                            node.name,
                            MINIMUMQUEUE[node.name],
                            options_like="node={}".format(node.name),
                            force_push_push=True,
                            db=db,
                        )
                        if not res:
                            continue
                        # Balance the tasks, works fine if no tags are set

                        node_name = min(
                            STATUSES,
                            key=lambda k: STATUSES[k]["tasks"]["completed"]
                            + STATUSES[k]["tasks"]["pending"]
                            + STATUSES[k]["tasks"]["running"],
                        )
                        if node_name != node.name:
                            node = (
                                db.query(Node)
                                .with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.enabled)
                                .filter_by(name=node_name)
                                .first()
                            )

                        pend_tasks_num = MINIMUMQUEUE[node.name] - (
                            STATUSES[node.name]["tasks"]["pending"] + STATUSES[node.name]["tasks"]["running"]
                        )
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

                    elif (
                        statuses.get("master", {}).get("tasks", {}).get("pending", 0) > MINIMUMQUEUE.get("master", 0)
                        and status["tasks"]["pending"] < MINIMUMQUEUE[node.name]
                    ):
                        res = self.submit_tasks(node.name, pend_tasks_num, db=db)
                        if not res:
                            continue
                db.commit()
            except Exception as e:
                log.error("Got an exception when trying to check nodes status and submit tasks: {}.".format(e), exc_info=True)

                # ToDo hard test this rollback, this normally only happens on db restart and similar
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
        self._parser.add_argument("name", type=str, location="form")
        self._parser.add_argument("url", type=str, location="form")
        self._parser.add_argument("apikey", type=str, default="", location="form")
        self._parser.add_argument("exitnodes", type=distutils.util.strtobool, default=None, location="form")
        self._parser.add_argument("enabled", type=distutils.util.strtobool, default=None, location="form")


class NodeRootApi(NodeBaseApi):
    def get(self):
        nodes = {}
        db = session()
        for node in db.query(Node).all():
            machines = [
                dict(
                    name=machine.name,
                    platform=machine.platform,
                    tags=machine.tags,
                )
                for machine in node.machines.all()
            ]

            nodes[node.name] = dict(
                name=node.name,
                url=node.url,
                machines=machines,
                enabled=node.enabled,
            )
        db.close()
        return dict(nodes=nodes)

    def post(self):
        db = session()
        args = self._parser.parse_args()
        node = Node(name=args["name"], url=args["url"], apikey=args["apikey"])

        if db.query(Node).filter_by(name=args["name"]).first():
            return dict(success=False, message="Node called %s already exists" % args["name"])

        machines = []
        for machine in node_list_machines(args["url"], args["apikey"]):
            machines.append(dict(name=machine.name, platform=machine.platform, tags=machine.tags))
            node.machines.append(machine)
            db.add(machine)

        exitnodes = []
        for exitnode in node_list_exitnodes(args["url"], args.get("apikey")):
            exitnode_db = db.query(ExitNodes).filter_by(name=exitnode).first()
            if exitnode_db:
                exitnode = exitnode_db
            else:
                exitnode = ExitNodes(name=exitnode)
            exitnodes.append(dict(name=exitnode.name))
            node.exitnodes.append(exitnode)
            db.add(exitnode)

        db.add(node)
        db.commit()
        db.close()

        if NFS_FETCH:
            # Add entry to /etc/fstab, create folder and mount server
            hostname = urlparse(args["url"]).netloc.split(":")[0]
            send_socket_command(dist_conf.NFS.fstab_socket, "add_entry", [hostname, args["name"]], {})

        return dict(name=args["name"], machines=machines, exitnodes=exitnodes)


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
            if k == "exitnodes":
                exitnodes = []
                for exitnode in node_list_exitnodes(node.url, node.apikey):
                    exitnode_db = db.query(ExitNodes).filter_by(name=exitnode).first()
                    if exitnode_db:
                        exitnode = exitnode_db
                    else:
                        exitnode = ExitNodes(name=exitnode)
                    exitnodes.append(dict(name=exitnode.name))
                    node.exitnodes.append(exitnode)
                    db.add(exitnode)
                db.add(node)
            else:
                if v is not None:
                    setattr(node, k, v)
        db.commit()
        db.close()
        return dict(error=False, error_value=f"Successfully modified node: {name}")

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
        self._parser.add_argument("package", type=str, default="", location="form")
        self._parser.add_argument("timeout", type=int, default=0, location="form")
        self._parser.add_argument("priority", type=int, default=1, location="form")
        self._parser.add_argument("options", type=str, default="", location="form")
        self._parser.add_argument("machine", type=str, default="", location="form")
        self._parser.add_argument("platform", type=str, default="windows", location="form")
        self._parser.add_argument("tags", type=str, default="", location="form")
        self._parser.add_argument("custom", type=str, default="", location="form")
        self._parser.add_argument("memory", type=str, default="0", location="form")
        self._parser.add_argument("clock", type=int, location="form")
        self._parser.add_argument("enforce_timeout", type=bool, default=False, location="form")


class TaskInfo(RestResource):
    def get(self, main_task_id):
        response = {"status": 0}
        db = session()
        task_db = db.query(Task).filter_by(main_task_id=main_task_id).first()
        if task_db and task_db.node_id:
            node = (
                db.query(Node)
                .with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.enabled)
                .filter_by(id=task_db.node_id)
                .first()
            )
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
    new_machines = node_list_machines(node.url, node.apikey)

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


def cron_cleaner(clean_x_hours=False):
    """Method that runs forever"""

    # Check if we are not runned
    if path_exists("/tmp/dist_cleaner.pid"):
        log.info("we running")
        sys.exit()

    pid = open("/tmp/dist_cleaner.pid", "wb")
    pid.write(b"")
    pid.close()

    db = session()
    nodes = {}
    details = {}

    for node in db.query(Node).with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.enabled).all():
        nodes.setdefault(node.id, node)

    # Allow force cleanup notificated but for some reason not deleted even when it set to deleted
    if clean_x_hours:
        tasks = (
            db.query(Task)
            .filter(Task.notificated.is_(True), Task.clock >= datetime.now() - timedelta(hours=clean_x_hours))
            .order_by(Task.id.desc())
            .all()
        )
    else:
        tasks = db.query(Task).filter_by(notificated=True, deleted=False).order_by(Task.id.desc()).all()
    if tasks is not None:
        for task in tasks:
            node = nodes[task.node_id]
            if node:
                details.setdefault(node.id, []).append(str(task.task_id))
                task.deleted = True

        for node in details:
            if node and not details[node]:
                continue

            ids = ",".join(details[node])
            _delete_many(node, ids, nodes, db)

    db.commit()
    db.close()
    path_delete("/tmp/dist_cleaner.pid")


def create_app(database_connection):
    # http://flask-sqlalchemy.pocoo.org/2.1/config/
    # https://github.com/tmeryu/flask-sqlalchemy/blob/master/flask_sqlalchemy/__init__.py#L787
    app = Flask("Distributed CAPE")
    # app.config["SQLALCHEMY_DATABASE_URI"] = database_connection
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
    app.config["SQLALCHEMY_POOL_SIZE"] = int(dist_conf.distributed.dist_threads) + 5
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

    if not path_exists(os.path.join(CUCKOO_ROOT, "log")):
        path_mkdir(os.path.join(CUCKOO_ROOT, "log"))
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
    p.add_argument(
        "-ec",
        "--enable-clean",
        action="store_true",
        help="Enable delete tasks from nodes, also will remove tasks submited by humands and not dist",
    )
    p.add_argument(
        "-ef",
        "--enable-failed-clean",
        action="store_true",
        default=False,
        help="Enable delete failed tasks from nodes, also will remove tasks submited by humands and not dist",
    )
    p.add_argument("-fr", "--force-reported", action="store", help="change report to reported")
    p.add_argument(
        "-ch",
        "--clean-hours",
        action="store",
        type=int,
        default=0,
        help="Clean tasks for last X hours",
    )

    args = p.parse_args()
    log = init_logging(args.debug)

    if args.enable_clean:
        cron_cleaner(args.clean_hours)
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
        app = create_app(database_connection=dist_conf.distributed.db)

        t = StatusThread(name="StatusThread")
        t.daemon = True
        t.start()

        retrieve = Retriever(name="Retriever")
        retrieve.daemon = True
        retrieve.start()
        # ret = Retriever()
        # ret.run()

        app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)

else:
    app = create_app(database_connection=dist_conf.distributed.db)

    # this allows run it with gunicorn/uwsgi
    log = init_logging(True)
    retrieve = Retriever(name="Retriever")
    retrieve.daemon = True
    retrieve.start()

    t = StatusThread(name="StatusThread")
    t.daemon = True
    t.start()
