# encoding: utf-8
#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

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

from sqlalchemy import and_, or_, select, func, delete, case
from sqlalchemy.exc import OperationalError, SQLAlchemyError
import pyzipper
import requests

requests.packages.urllib3.disable_warnings()

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.iocs import dump_iocs, load_iocs
from lib.cuckoo.common.cleaners_utils import free_space_monitor
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
    _Database,
    init_database,
)
from lib.cuckoo.core.database import Task as MD_Task
from dev_utils.mongodb import mongo_update_one

dist_conf = Config("distributed")
main_server_name = dist_conf.distributed.get("main_server_name", "master")

HAVE_GCP = False
if dist_conf.GCP.enabled:
    from lib.cuckoo.common.gcp import GCP, HAVE_GCP

    cloud = GCP()

# we need original db to reserve ID in db,
# to store later report, from master or worker

cfg = Config()
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
main_db: _Database = Database()

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
    sys.exit("The %s package is required: poetry run pip install %s" % (package, package))


# todo, consider to migrate to fastAPI?
try:
    from flask import Flask, jsonify, make_response
except ImportError:
    required("flask")

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
    """
    Retrieve the status of a CAPE node.

    This function sends a GET request to the specified CAPE node URL to retrieve its status.
    It uses the provided API key for authorization.

    Args:
        url (str): The base URL of the CAPE node.
        name (str): The name of the CAPE node.
        apikey (str): The API key for authorization.

    Returns:
        dict: A dictionary containing the status data of the CAPE node. If an error occurs,
            an empty dictionary is returned.
    """
    try:
        r = requests.get(
            os.path.join(url, "cuckoo", "status/"), headers={"Authorization": f"Token {apikey}"}, verify=False, timeout=300
        )
        return r.json().get("data", {})
    except Exception as e:
        log.critical("Possible invalid CAPE node (%s): %s", name, e)
    return {}


def node_fetch_tasks(status, url, apikey, action="fetch", since=0):
    """
    Fetches tasks from a remote server based on the given status and other parameters.

    Args:
        status (str): The status of the tasks to fetch (e.g., "completed", "pending").
        url (str): The base URL of the remote server.
        apikey (str): The API key for authentication.
        action (str, optional): The action to perform. Defaults to "fetch".
        since (int, optional): The timestamp to fetch tasks completed after. Defaults to 0.

    Returns:
        list: A list of tasks fetched from the remote server. Returns an empty list if an error occurs.
    """
    try:
        url = os.path.join(url, "tasks", "list/")
        params = dict(status=status, ids=True)
        if action == "fetch":
            params["completed_after"] = since
        r = requests.get(url, params=params, headers={"Authorization": f"Token {apikey}"}, verify=False)
        if not r.ok:
            log.error("Error fetching task list. Status code: %d - %s. Saving error to /tmp/dist_error.html", r.status_code, r.url)
            _ = path_write_file("/tmp/dist_error.html", r.content)
            return []
        return r.json().get("data", [])
    except Exception as e:
        log.critical("Error listing completed tasks (node %s): %s", url, e)

    return []


def node_list_machines(url, apikey):
    """
    Retrieves a list of machines from a CAPE node and yields Machine objects.

    Args:
        url (str): The base URL of the CAPE node.
        apikey (str): The API key for authentication.

    Yields:
        Machine: An instance of the Machine class with the machine's details.

    Raises:
        HTTPException: If the request to the CAPE node fails or returns an error.
    """
    try:
        r = requests.get(os.path.join(url, "machines", "list/"), headers={"Authorization": f"Token {apikey}"}, verify=False)
        for machine in r.json()["data"]:
            yield Machine(name=machine["name"], platform=machine["platform"], tags=machine["tags"])
    except Exception as e:
        abort(404, message="Invalid CAPE node (%s): %s" % (url, e))


def node_list_exitnodes(url, apikey):
    """
    Fetches a list of exit nodes from a given URL using the provided API key.

    Args:
        url (str): The base URL of the CAPE node.
        apikey (str): The API key for authorization.

    Yields:
        dict: Each exit node data as a dictionary.

    Raises:
        HTTPException: If the request fails or the response is invalid.
    """
    try:
        r = requests.get(os.path.join(url, "exitnodes/"), headers={"Authorization": f"Token {apikey}"}, verify=False)
        for exitnode in r.json()["data"]:
            yield exitnode
    except Exception as e:
        abort(404, message="Invalid CAPE node (%s): %s" % (url, e))


def node_get_report(task_id, fmt, url, apikey, stream=False):
    """
    Fetches a report for a given task from a specified URL.

    Args:
        task_id (int): The ID of the task for which the report is to be fetched.
        fmt (str): The format of the report (e.g., 'json', 'html').
        url (str): The base URL of the server from which to fetch the report.
        apikey (str): The API key for authorization.
        stream (bool, optional): Whether to stream the response. Defaults to False.

    Returns:
        requests.Response: The response object containing the report.

    Raises:
        Exception: If there is an error fetching the report.
    """
    try:
        url = os.path.join(url, "tasks", "get", "report", "%d/" % task_id, fmt)
        return requests.get(url, stream=stream, headers={"Authorization": f"Token {apikey}"}, verify=False, timeout=800)
    except Exception as e:
        log.critical("Error fetching report (task #%d, node %s): %s", task_id, url, e)


def node_get_report_nfs(task_id, worker_name, main_task_id) -> bool:
    """
    Retrieves a report from a worker node via NFS and copies it to the main task's analysis directory.

    Args:
        task_id (int): The ID of the task on the worker node.
        worker_name (str): The name of the worker node.
        main_task_id (int): The ID of the main task on the main node.

    Returns:
        bool: True if the operation was successful, False otherwise.

    Raises:
        Exception: If there is an error during the copying process.

    Logs:
        Error messages if the worker node is not mounted, the file does not exist, or if there is an exception during copying.
    """
    worker_path = os.path.join(CUCKOO_ROOT, dist_conf.NFS.mount_folder, str(worker_name))

    if not path_mount_point(worker_path):
        log.error("[-] Worker: %s is not mounted to: %s!", worker_name, worker_path)
        return True

    worker_path = os.path.join(worker_path, "storage", "analyses", str(task_id))

    if not path_exists(worker_path):
        log.error("File on destiny doesn't exist: %s", worker_path)
        return True

    analyses_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(main_task_id))
    if not path_exists(analyses_path):
        path_mkdir(analyses_path, mode=0o755, exist_ok=False)

    try:
        shutil.copytree(worker_path, analyses_path, ignore=dist_ignore_patterns, ignore_dangling_symlinks=True, dirs_exist_ok=True)
    except shutil.Error:
        log.error("Files doens't exist on worker")
    except Exception as e:
        log.exception(e)
        return False

    return True


def _delete_many(node, ids, nodes, db):
    """
    Deletes multiple tasks from a specified node if the node is not the main server.

    Args:
        node (str): The identifier of the node from which tasks are to be deleted.
        ids (list): A list of task IDs to be deleted.
        nodes (dict): A dictionary containing node information, where keys are node identifiers and values are node details.
        db (object): The database connection object to perform rollback in case of failure.

    Returns:
        None

    Raises:
        Exception: If there is an error during the deletion process.

    Logs:
        Debug: Logs the task IDs and node name from which tasks are being deleted.
        Info: Logs the status code and content if the response status code is not 200.
        Critical: Logs the error message if an exception occurs during the deletion process.
    """
    if nodes[node].name == main_server_name:
        return
    try:
        url = os.path.join(nodes[node].url, "tasks", "delete_many/")
        apikey = nodes[node].apikey
        log.debug("Removing task id(s): %s - from node: %s", ids, nodes[node].name)
        res = requests.post(
            url,
            headers={"Authorization": f"Token {apikey}"},
            data={"ids": ids, "delete_mongo": False},
            verify=False,
        )
        if res and res.status_code != 200:
            log.info("%d - %s", res.status_code, res.content)
            db.rollback()

    except Exception as e:
        log.critical("Error deleting task (tasks #%s, node %s): %s", ids, nodes[node].name, e)
        db.rollback()


def node_submit_task(task_id, node_id, main_task_id):
    """
    Submits a task to a specified node for processing.

    Args:
        task_id (int): The ID of the task to be submitted.
        node_id (int): The ID of the node to which the task will be submitted.
        main_task_id (int): The ID of the main task associated with this task.

    Returns:
        bool: True if the task was successfully submitted, False otherwise.

    Raises:
        Exception: If there is an error during the task submission process.

    The function performs the following steps:
    1. Retrieves the node and task information from the database.
    2. Checks if the node is the main server and returns if it is.
    3. Prepares the task data for submission based on the task category.
    4. Submits the task to the node using an HTTP POST request.
    5. Handles different response statuses from the node.
    6. Updates the task status in the database based on the submission result.
    7. Logs relevant information and errors during the process.
    """
    db = session()
    node = db.scalar(select(Node).where(Node.id == node_id))
    task = db.get(Task, task_id)
    check = False
    try:
        if node.name == main_server_name:
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
            tlp=task.tlp,
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
            log.debug("Target category is: %s", task.category)
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
                    "Failed to submit: main_task_id: %d task %d to node: %s, code: %d, msg: %s",
                    task.main_task_id,
                    task_id,
                    node.name,
                    r.status_code,
                    r.content,
                )
                if b"File too big, enable" in r.content:
                    main_db.set_status(task.main_task_id, TASK_BANNED)
            if task.task_id:
                log.debug("Submitted task to worker: %s - %d - %d", node.name, task.task_id, task.main_task_id)

        elif r.status_code == 500:
            log.info("Saving error to /tmp/dist_error.html")
            _ = path_write_file("/tmp/dist_error.html", r.content)
            log.info((r.status_code, r.text[:200]))

        elif r.status_code == 429:
            log.info((r.status_code, "see api auth for more details"))

        else:
            log.info("Node: %d - Task submit to worker failed: %d - %s", node.id, r.status_code, r.text)

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
    """
    A class that retrieves and processes tasks from distributed nodes.

    Methods
    -------
    run():
        Initializes and starts various threads for fetching and processing tasks.

    free_space_mon():
        Monitors free disk space and logs an error if space is insufficient.

    notification_loop():
        Sends notifications for completed tasks to configured callback URLs.

    failed_cleaner():
        Cleans up failed tasks from nodes and updates their status in the database.

    fetcher():
        Continuously fetches tasks from enabled nodes and processes them.

    delete_target_file(task_id: int, sample_sha256: str, target: str):
        Deletes the original file and its binary copy if configured to do so.

    fetch_latest_reports_nfs():
        Fetches the latest reports from nodes using NFS and processes them.

    fetch_latest_reports():
        Fetches the latest reports from nodes using REST API and processes them.

    remove_from_worker():
        Removes tasks from worker nodes and updates their status in the database.
    """

    def run(self):
        self.cleaner_queue = queue.Queue()
        self.fetcher_queue = queue.Queue()
        self.t_is_none = {}
        self.status_count = {}
        self.current_queue = {}
        self.current_two_queue = {}
        self.stop_dist = threading.Event()
        self.threads = []

        if dist_conf.GCP.enabled and HAVE_GCP:
            # autodiscovery is generic name so in case if we have AWS or Azure it should implement the logic inside
            thread = threading.Thread(target=cloud.autodiscovery, name="autodiscovery", args=())
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
                log.info("Thread: %s - Alive: %s", thr.name, str(thr.is_alive()))
            except Exception as e:
                log.exception(e)
            time.sleep(60)

    def free_space_mon(self):
        """
        Monitors the free disk space in the analysis folder and logs an error
        message if the available space is below the configured threshold. This
        check is performed periodically every 10 minutes. The check is ignored
        if the 'freespace' configuration variable is set to zero.

        The analysis folder path is resolved to its full base path to handle
        cases where it might be a symbolic link.

        Returns:
            None
        """
        # If not enough free disk space is available, then we print an
        # error message and wait another round (this check is ignored
        # when the freespace configuration variable is set to zero).
        if cfg.cuckoo.freespace:
            # Resolve the full base path to the analysis folder, just in
            # case somebody decides to make a symbolic link out of it.
            dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")
            while True:
                free_space_monitor(dir_path, analysis=True)
                time.sleep(600)

    def notification_loop(self):
        """
        Continuously checks for completed tasks that have not been notified and sends notifications to specified URLs.

        This method runs an infinite loop that:
        1. Queries the database for tasks that are finished, retrieved, but not yet notified.
        2. For each task, updates the main task status to `TASK_REPORTED`.
        3. Sends a POST request to each URL specified in the configuration with the task ID in the payload.
        4. Marks the task as notified if the POST request is successful.
        5. Logs the status of each notification attempt.

        The loop sleeps for 20 seconds before repeating the process.

        Raises:
            requests.exceptions.ConnectionError: If there is a connection error while sending the POST request.
            Exception: For any other exceptions that occur during the notification process.
        """
        urls = reporting_conf.callback.url.split(",")
        headers = {"x-api-key": reporting_conf.callback.key}

        with session() as db:
            while True:
                stmt = (
                    select(Task)
                    .where(Task.finished.is_(True), Task.retrieved.is_(True), Task.notificated.is_(False))
                    .order_by(Task.id.desc())
                )

                for task in db.scalars(stmt):
                    with main_db.session.begin():
                        main_db.set_status(task.main_task_id, TASK_REPORTED)
                    log.debug("reporting main_task_id: %d", task.main_task_id)
                    for url in urls:
                        try:
                            res = requests.post(url, headers=headers, data=json.dumps({"task_id": int(task.main_task_id)}))
                            if res and res.ok:
                                task.notificated = True
                            else:
                                log.info("failed to report: %d - %d", task.main_task_id, res.status_code)
                        except requests.exceptions.ConnectionError:
                            log.info("Can't report to callback")
                        except Exception as e:
                            log.info("failed to report: %d - %s", task.main_task_id, str(e))
                db.commit()
                time.sleep(20)

    def failed_cleaner(self):
        """
        Periodically checks for failed tasks on enabled nodes and cleans them up.

        This method continuously queries the database for nodes that are enabled and
        checks for tasks that have failed either during analysis or processing. If a
        failed task is found, it updates the task status to indicate failure, marks
        the task as finished, retrieved, and notified, and then adds the task to the
        cleaner queue for further processing.

        The method runs indefinitely, sleeping for 600 seconds between each iteration.

        Attributes:
            self.cleaner_queue (Queue): A queue to hold tasks that need to be cleaned.

        Notes:
            - This method acquires and releases a lock (`lock_retriever`) to ensure
                thread-safe operations when adding tasks to the cleaner queue.
            - The method commits changes to the database after processing each node.
            - The method closes the database session before exiting.

        Raises:
            Any exceptions raised during database operations or task processing are
            not explicitly handled within this method.
        """
        db = session()
        while True:
            nodes = db.execute(select(Node.id, Node.name, Node.url, Node.apikey).where(Node.enabled.is_(True)))
            for node in nodes:
                log.info("Checking for failed tasks on: %s", node.name)
                for task in node_fetch_tasks("failed_analysis|failed_processing", node.url, node.apikey, action="delete"):
                    task_stmt = select(Task).where(Task.task_id == task["id"], Task.node_id == node.id).order_by(Task.id.desc())
                    t = db.scalar(task_stmt)
                    if t is not None:
                        log.info("Cleaning failed for id: %d, node: %s: main_task_id: %d", t.id, t.node_id, t.main_task_id)
                        with main_db.session.begin():
                            main_db.set_status(t.main_task_id, TASK_FAILED_REPORTING)
                        t.finished = True
                        t.retrieved = True
                        t.notificated = True
                        lock_retriever.acquire()
                        if (t.node_id, t.task_id) not in self.cleaner_queue.queue:
                            self.cleaner_queue.put((t.node_id, t.task_id))
                        lock_retriever.release()
                    else:
                        log.debug("failed_cleaner t is None for: %s - node_id: %d", str(task["id"]), node.id)
                        lock_retriever.acquire()
                        if (node.id, task["id"]) not in self.cleaner_queue.queue:
                            self.cleaner_queue.put((node.id, task["id"]))
                        lock_retriever.release()
                db.commit()
            time.sleep(600)
        db.close()

    def fetcher(self):
        """
        Method that runs indefinitely to fetch tasks from nodes and process them.

        This method continuously checks for tasks from enabled nodes and processes them.
        It maintains a status count and last check time for each node. If a node's tasks
        are fetched successfully, they are added to the fetcher queue. If a node is deemed
        dead after a certain number of failures, it is logged.

        Attributes:
            last_checks (dict): Dictionary to keep track of the last check time for each node.
            status_count (dict): Dictionary to keep track of the status count for each node.
            stop_dist (threading.Event): Event to signal stopping the distribution.
            cleaner_queue (queue.Queue): Queue to hold tasks that need cleaning.
            fetcher_queue (queue.Queue): Queue to hold tasks that need fetching.
            current_queue (dict): Dictionary to keep track of the current queue for each node.

        Raises:
            Exception: If an error occurs during task processing, it is logged and the status count is incremented
        """
        last_checks = {}
        # to not exit till cleaner works
        with session() as db:
            while True:
                if self.stop_dist.is_set():
                    time.sleep(60)
                    continue
                # .with_entities(Node.id, Node.name, Node.url, Node.apikey, Node.last_check)
                nodes = db.scalars(select(Node).where(Node.enabled.is_(True)))
                for node in nodes:
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
                    task_ids = []
                    for task in node_fetch_tasks("reported", node.url, node.apikey, "fetch", last_check):
                        task_ids.append(task["id"])

                    if True:
                        stmt = (
                            select(Task)
                            .where(
                                Task.finished.is_(False),
                                Task.retrieved.is_(False),
                                Task.node_id == node.id,
                                Task.deleted.is_(False),
                                Task.task_id.in_(task_ids),
                            )
                            .order_by(Task.id.desc())
                        )
                        tasker = db.scalars(stmt)

                        if tasker is None:
                            # log.debug(f"Node ID: {node.id} - Task ID: {task['id']} - adding to cleaner")
                            self.cleaner_queue.put((node.id, task["id"]))
                            continue

                        for task in tasker:
                            try:
                                if (
                                    task.task_id not in self.current_queue.get(node.id, [])
                                    and (task.task_id, node.id) not in self.fetcher_queue.queue
                                ):
                                    limit += 1
                                    self.fetcher_queue.put(({"id": task.task_id}, node.id))
                                    # log.debug("%s - %d", task, node.id)
                                    """
                                    completed_on = datetime.strptime(task["completed_on"], "%Y-%m-%d %H:%M:%S")
                                    if node.last_check is None or completed_on > node.last_check:
                                        node.last_check = completed_on
                                        db.commit()
                                        db.refresh(node)
                                    #if limit == 50:
                                    #    break
                                    """
                            except Exception as e:
                                self.status_count[node.name] += 1
                                log.exception(e)
                                if self.status_count[node.name] == dead_count:
                                    log.info("[-] %s dead", node.name)
                                    # node_data = db.query(Node).filter_by(name=node.name).first()
                                    # node_data.enabled = False
                                    # db.commit()
                db.commit()
                # time.sleep(5)

    def delete_target_file(self, task_id: int, sample_sha256: str, target: str):
        """
        Deletes the target file and its binary copy if certain conditions are met.

        Args:
            task_id (int): The ID of the task associated with the file.
            sample_sha256 (str): The SHA-256 hash of the sample file.
            target (str): The path to the target file.

        Behavior:
            - Deletes the target file if `cfg.cuckoo.delete_original` is True and the target file exists.
            - Deletes the binary copy of the file if `cfg.cuckoo.delete_bin_copy` is True and no other tasks are using the sample.

        Note:
            - The function checks if the target file exists before attempting to delete it.
            - The function checks if the binary copy is still in use by other tasks before deleting it.
        """
        # Is ok to delete original file, but we need to lookup on delete_bin_copy if no more pendings tasks
        if cfg.cuckoo.delete_original and target and path_exists(target):
            path_delete(target)

        if cfg.cuckoo.delete_bin_copy:
            copy_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sample_sha256)
            if path_exists(copy_path):
                with main_db.session.begin():
                    sample_still_used = main_db.sample_still_used(sample_sha256, task_id)
                if not sample_still_used:
                    path_delete(copy_path)

    # This should be executed as external thread as it generates bottle neck
    def fetch_latest_reports_nfs(self):
        """
        Fetches the latest reports from NFS (Network File System) for distributed tasks.

        This method continuously checks for new tasks in the fetcher queue and processes them.
        It retrieves the task details from the database, fetches the corresponding report from
        the specified node, and updates the task status in the main database.

        The method performs the following steps:
        1. Continuously checks for new tasks in the fetcher queue.
        2. Retrieves task details from the database.
        3. Fetches the report from the specified node.
        4. Updates the task status in the main database.
        5. Moves the report to the appropriate location.
        6. Creates a symbolic link to the analysis folder.
        7. Deletes the target file if necessary.
        8. Marks the task as retrieved and finished in the database.

        The method handles various exceptions and logs relevant information for debugging purposes.

        Note:
            This method runs indefinitely until the `stop_dist` event is set.

        Raises:
            Exception: If any error occurs during the processing of tasks.

        """
        # db = session()
        with session() as db:
            # to not exit till cleaner works
            while True:
                if self.stop_dist.is_set():
                    time.sleep(60)
                    continue
                task, node_id = self.fetcher_queue.get()

                self.current_queue.setdefault(node_id, []).append(task["id"])
                try:
                    # In the case that a worker node has been reset over time it"s
                    # possible that there are multiple combinations of
                    # node-id/task-id, in this case we take the last one available.
                    # (This makes it possible to re-setup a worker node).
                    stmt = (
                        select(Task)
                        .where(
                            Task.node_id == node_id,
                            Task.task_id == task["id"],
                            Task.retrieved.is_(False),
                            Task.finished.is_(False),
                        )
                        .order_by(Task.id.desc())
                    )
                    t = db.scalar(stmt)
                    if t is None:
                        self.t_is_none.setdefault(node_id, []).append(task["id"])

                        # sometime it not deletes tasks in workers of some fails or something
                        # this will do the trick
                        log.debug("tf else,")
                        if (node_id, task.get("id")) not in self.cleaner_queue.queue:
                            self.cleaner_queue.put((node_id, task.get("id")))
                        continue

                    log.debug(
                        "Fetching dist report for: id: %d, task_id: %d, main_task_id: %d from node: %s",
                        t.id,
                        t.task_id,
                        t.main_task_id,
                        ID2NAME[t.node_id] if t.node_id in ID2NAME else t.node_id,
                    )
                    with main_db.session.begin():
                        # set completed_on time
                        main_db.set_status(t.main_task_id, TASK_DISTRIBUTED_COMPLETED)
                        # set reported time
                        main_db.set_status(t.main_task_id, TASK_REPORTED)

                    # Fetch each requested report.
                    report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(t.main_task_id))
                    # ToDo option
                    node = db.scalar(select(Node).where(Node.id == node_id))

                    start_copy = timeit.default_timer()
                    copied = node_get_report_nfs(t.task_id, node.name, t.main_task_id)

                    if not copied:
                        log.error("Can't copy report %d from node: %s for task: %d", t.task_id, node.name, t.main_task_id)
                        continue

                    timediff = timeit.default_timer() - start_copy
                    log.info(
                        "It took %s seconds to copy report %d from node: %s for task: %d",
                        f"{timediff:.2f}",
                        t.task_id,
                        node.name,
                        t.main_task_id,
                    )

                    # this doesn't exist for some reason
                    if path_exists(t.path):
                        sample_sha256 = None
                        sample_parent = None
                        with main_db.session.begin():
                            samples = main_db.find_sample(task_id=t.main_task_id)
                            if samples:
                                sample_sha256 = samples[0].sample.sha256
                                if hasattr(samples[0].sample, "parent_links"):
                                    for parent in samples[0].sample.parent_links:
                                        if parent.task_id == t.main_task_id:
                                            sample_parent = parent.parent.to_dict()
                                            break

                        if sample_sha256 is None:
                            # keep fallback for now
                            sample = open(t.path, "rb").read()
                            sample_sha256 = hashlib.sha256(sample).hexdigest()

                        destination = os.path.join(binaries_folder, sample_sha256)
                        if not path_exists(destination) and path_exists(t.path):
                            try:
                                shutil.move(t.path, destination)
                            except FileNotFoundError as e:
                                log.error("Failed to move: %s - %s", t.path, str(e))
                        # creating link to analysis folder
                        if path_exists(destination):
                            try:
                                os.symlink(destination, os.path.join(report_path, "binary"))
                            except Exception:
                                # print(f"Failed link binary: {e}")
                                pass

                        self.delete_target_file(t.main_task_id, sample_sha256, t.path)

                    if sample_parent:
                        try:
                            report = load_iocs(t.main_task_id, detail=True)
                            report["info"].update({"parent_sample": sample_parent})
                            dump_iocs(report, t.main_task_id)
                            # ToDo insert into mongo
                            mongo_update_one(
                                "analysis", {"info.id": int(t.main_task_id)}, {"$set": {"info.parent_sample": sample_parent}}
                            )
                        except Exception as e:
                            log.exception("Failed to save iocs for parent sample: %s", str(e))

                    t.retrieved = True
                    t.finished = True
                    db.commit()

                except Exception as e:
                    log.exception(e)
                self.current_queue[node_id].remove(task["id"])
                db.commit()

    # This should be executed as external thread as it generates bottle neck
    def fetch_latest_reports(self):
        """
        Continuously fetches the latest reports from distributed nodes and processes them.

        This method runs in an infinite loop until `self.stop_dist` is set. It retrieves tasks from the `fetcher_queue`,
        fetches the corresponding reports from the nodes, and processes them. The reports are saved to the local storage
        and the task status is updated in the database.

        The method handles various scenarios such as:
        - Task not found or already processed.
        - Report retrieval failures.
        - Report extraction and saving.
        - Handling of sample binaries associated with the tasks.

        The method also manages a cleaner queue to handle tasks that need to be cleaned up.

        Raises:
            Exception: If any unexpected error occurs during the report fetching and processing.
        """
        db = session()
        # to not exit till cleaner works
        while True:
            if self.stop_dist.is_set():
                time.sleep(60)
                continue
            task, node_id = self.fetcher_queue.get()

            self.current_queue.setdefault(node_id, []).append(task["id"])

            try:
                # In the case that a Cuckoo node has been reset over time it"s
                # possible that there are multiple combinations of
                # node-id/task-id, in this case we take the last one available.
                # (This makes it possible to re-setup a Cuckoo node).
                stmt = (
                    select(Task)
                    .where(
                        Task.node_id == node_id,
                        Task.task_id == task["id"],
                        Task.retrieved.is_(False),
                        Task.finished.is_(False),
                    )
                    .order_by(Task.id.desc())
                )
                t = db.scalar(stmt)
                if t is None:
                    self.t_is_none.setdefault(node_id, []).append(task["id"])

                    # sometime it not deletes tasks in workers of some fails or something
                    # this will do the trick
                    # log.debug("tf else,")
                    if (node_id, task.get("id")) not in self.cleaner_queue.queue:
                        self.cleaner_queue.put((node_id, task.get("id")))
                    continue

                log.debug(
                    "Fetching dist report for: id: %d, task_id: %d, main_task_id: %d from node: %s",
                    t.id,
                    t.task_id,
                    t.main_task_id,
                    ID2NAME[t.node_id] if t.node_id in ID2NAME else t.node_id,
                )
                with main_db.session.begin():
                    # set completed_on time
                    main_db.set_status(t.main_task_id, TASK_DISTRIBUTED_COMPLETED)
                    # set reported time
                    main_db.set_status(t.main_task_id, TASK_REPORTED)

                # Fetch each requested report.
                node = db.scalar(select(Node).where(Node.id == node_id))
                report = node_get_report(t.task_id, "dist/", node.url, node.apikey, stream=True)

                if report is None:
                    log.info("dist report retrieve failed NONE: task_id: %d from node: %d", t.task_id, node_id)
                    continue

                if report.status_code != 200:
                    log.info(
                        "dist report retrieve failed - status_code %d: task_id: %d from node: %s",
                        report.status_code,
                        t.task_id,
                        node_id,
                    )
                    if report.status_code == 400 and (node_id, task.get("id")) not in self.cleaner_queue.queue:
                        self.cleaner_queue.put((node_id, task.get("id")))
                        log.info("Status code: %d - MSG: %s", report.status_code, report.text)
                    continue

                log.info(
                    "Report size for task %s is: %s MB",
                    t.task_id,
                    f"{int(report.headers.get('Content-length', 1)) / int(1 << 20):,.0f}",
                )

                report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(t.main_task_id))
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
                                log.error("Permission denied: %s", report_path)

                        if path_exists(t.path):
                            sample_sha256 = None
                            with main_db.session.begin():
                                samples = main_db.find_sample(task_id=t.main_task_id)
                                if samples:
                                    sample_sha256 = samples[0].sample.sha256
                            if sample_sha256 is None:
                                # keep fallback for now
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

                                self.delete_target_file(t.main_task_id, sample_sha256, t.path)

                        else:
                            log.debug("%s doesn't exist", t.path)

                        t.retrieved = True
                        t.finished = True
                        db.commit()

                    else:
                        log.error("Zip file is empty")
                except pyzipper.zipfile.BadZipFile:
                    log.error("File is not a zip file")
                except Exception as e:
                    log.exception("Exception: %s", str(e))
                    if path_exists(os.path.join(report_path, "reports", "report.json")):
                        path_delete(os.path.join(report_path, "reports", "report.json"))
            except Exception as e:
                log.exception(e)
            self.current_queue[node_id].remove(task["id"])
            db.commit()
        db.close()

    def remove_from_worker(self):
        """
        Removes tasks from worker nodes.

        This method continuously processes tasks from the cleaner queue and removes them from the worker nodes.
        It retrieves the list of nodes from the database and processes tasks in the cleaner queue.
        If a task is found in the `t_is_none` dictionary for a node, it is removed from the list.
        The method then sends a request to delete the tasks from the worker node.

        The method performs the following steps:
        1. Retrieves the list of nodes from the database.
        2. Continuously processes tasks from the cleaner queue.
        3. Groups tasks by node ID.
        4. Removes tasks from the `t_is_none` dictionary if present.
        5. Sends a request to delete tasks from the worker node.
        6. Commits the changes to the database.
        7. Sleeps for 20 seconds before processing the next batch of tasks.

        Note:
            The method runs indefinitely until manually stopped.

        ToDo:
            Determine if additional actions are needed when the length of `t_is_none[node_id]` exceeds 50.

        """
        nodes = {}
        with session() as db:
            for node in db.scalars(select(Node)):
                nodes.setdefault(node.id, node)

        while True:
            details = {}
            # print("cleaner size is ", self.cleaner_queue.qsize())
            for _ in range(self.cleaner_queue.qsize()):
                node_id, task_id = self.cleaner_queue.get()
                details.setdefault(node_id, []).append(str(task_id))
                if task_id in self.t_is_none.get(node_id, []):
                    self.t_is_none[node_id].remove(task_id)

                    if len(self.t_is_none[node_id]) > 50:
                        break

                    # ToDo Do we need to do something here?

            for node_id in details:
                node = nodes[node_id]
                if node and details[node_id]:
                    ids = ",".join(list(set(details[node_id])))
                    print(ids)
                    _delete_many(node_id, ids, nodes, db)

                db.commit()
                time.sleep(20)


class StatusThread(threading.Thread):
    """
    A thread that handles the submission of tasks to nodes and manages the status of nodes.

    Methods
    -------
    submit_tasks(node_id, pend_tasks_num, options_like=False, force_push_push=False, db=None)
        Submits tasks to a specified node.

    load_vm_tags(db, node_id, node_name)
        Loads the tags for virtual machines associated with a node.

    run()
        The main loop that continuously checks the status of nodes and submits tasks.
    """

    def submit_tasks(self, node_name, pend_tasks_num, options_like=False, force_push_push=False, db=None):
        """
        Submits tasks to a specified node.

        Args:
            node_name (str): The identifier of the node to which tasks will be submitted.
            pend_tasks_num (int): The number of pending tasks to be submitted.
            options_like (bool, optional): Flag to filter tasks based on options. Defaults to False.
            force_push_push (bool, optional): Flag to forcefully push tasks to the node. Defaults to False.
            db (Session, optional): The database session to use. Defaults to None.

        Returns:
            bool: True if tasks were successfully submitted, False otherwise.

        Raises:
            OperationalError: If there is an operational error when querying the database.
            SQLAlchemyError: If there is a SQLAlchemy error when querying the database.
        """
        # HACK do not create a new session if the current one (passed as parameter) is still valid.
        try:
            # ToDo name should be id?
            node = db.scalar(select(Node).where(Node.name == node_name))
        except (OperationalError, SQLAlchemyError) as e:
            log.warning("Got an operational Exception when trying to submit tasks: %s", str(e))
            return False

        if node.name not in SERVER_TAGS:
            self.load_vm_tags(db, node.id, node.name)

        limit = 0
        # ToDo delete instead of select
        # check if we have tasks with no node_id and task_id, but with main_task_id
        stmt = select(Task).where(Task.node_id.is_(None), Task.task_id.is_(None), Task.main_task_id.is_not(None))
        bad_tasks = db.scalars(stmt)
        if bad_tasks:
            for task in bad_tasks:
                db.delete(task)
                db.commit()
                with main_db.session.begin():
                    main_db.set_status(task.main_task_id, TASK_PENDING)

        if node.name != main_server_name:
            # don"t do nothing if nothing in pending
            # Get tasks from main_db submitted through web interface
            # Exclude category
            with main_db.session.begin():
                main_db_tasks = main_db.list_tasks(
                    status=TASK_PENDING,
                    options_like=options_like,
                    limit=pend_tasks_num,
                    order_by=MD_Task.priority.desc(),
                    for_update=True,
                )
                if not main_db_tasks:
                    return True
                if main_db_tasks:
                    for t in main_db_tasks:
                        options = get_options(t.options)
                        # Check if file exist, if no wipe from db and continue, rare cases
                        if t.category in ("file", "pcap", "static"):
                            if not path_exists(t.target):
                                log.info("Task id: %d - File doesn't exist: %s", t.id, t.target)
                                main_db.set_status(t.id, TASK_BANNED)
                                continue

                            if not web_conf.general.allow_ignore_size and "ignore_size_check" not in options:
                                # We can't upload size bigger than X to our workers. In case we extract archive that contains bigger file.
                                file_size = path_get_size(t.target)
                                if file_size > web_conf.general.max_sample_size:
                                    log.warning(
                                        "File size: %d is bigger than allowed: %d", file_size, web_conf.general.max_sample_size
                                    )
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
                            log.exception(e)
                        # wtf are you doing in pendings?
                        tasks = db.scalars(select(Task).where(Task.main_task_id == t.id)).all()
                        if tasks:
                            for task in tasks:
                                log.info("Deleting incorrectly uploaded file from dist db, main_task_id: %s", t.id)
                                if node.name == main_server_name:
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
                        t.options += f"main_task_id={t.id}"
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
                            tlp=t.tlp,
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
                            submitted = node_submit_task(task.id, node.id, t.id)
                            if submitted:
                                if node.name == main_server_name:
                                    main_db.set_status(t.id, TASK_RUNNING)
                                else:
                                    main_db.set_status(t.id, TASK_DISTRIBUTED)
                            limit += 1
                            if limit in (pend_tasks_num, len(main_db_tasks)):
                                db.commit()
                                log.info("Pushed all tasks")
                                return True

                    # ToDo not finished
                    # Only get tasks that have not been pushed yet.
                    """
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
                    """
                    # 1. Start with a select() statement and initial filters.
                    stmt = (
                        select(Task)
                        .where(or_(Task.node_id.is_(None), Task.task_id.is_(None)), Task.finished.is_(False))
                        .order_by(Task.priority.desc(), Task.main_task_id)
                    )
                    # print(stmt, "stmt")
                    # ToDo broken
                    """
                    # 3. Apply the dynamic tag filter.
                    if dist_conf.distributed.enable_tags:
                        tags_conditions = [Task.tags == ""]
                        for tg in SERVER_TAGS[node.name]:
                            tags_list = tg.split(",")
                            if len(tags_list) == 1:
                                tags_conditions.append(Task.tags == f"{tg},")
                            else:
                                # The pattern of building a list of conditions for `and_` or `or_`
                                # works the same way with the modern .where() clause.
                                t_combined = [Task.tags.like(f"%{tag},%") for tag in tags_list]
                                tags_conditions.append(and_(*t_combined))

                        stmt = stmt.where(or_(*tags_conditions))
                    """
                    # 4. Apply the limit and execute the query.
                    to_upload = db.scalars(stmt.limit(pend_tasks_num)).all()
                    print(to_upload, node.name, pend_tasks_num)

                    if not to_upload:
                        db.commit()
                        log.info("nothing to upload? How? o_O")
                        return False
                    # Submit appropriate tasks to node
                    log.debug("going to upload %d tasks to node %s", pend_tasks_num, node.name)
                    for task in to_upload:
                        submitted = node_submit_task(task.id, node.id, task.main_task_id)
                        if submitted:
                            if node.name == main_server_name:
                                main_db.set_status(task.main_task_id, TASK_RUNNING)
                            else:
                                main_db.set_status(task.main_task_id, TASK_DISTRIBUTED)
                        else:
                            log.info("something is wrong with submission of task: %d", task.id)
                            db.delete(task)
                            db.commit()
                        limit += 1
                        if limit == pend_tasks_num:
                            db.commit()
                            return True
        db.commit()
        return True

    def load_vm_tags(self, db, node_id, node_name):
        """
        Load virtual machine tags for a specific node and store them in the global SERVER_TAGS dictionary.

        Args:
            db (Session): The database session to query the machines.
            node_id (int): The ID of the node to load tags for.
            node_name (str): The name of the node to load tags for.

        Returns:
            None
        """
        global SERVER_TAGS
        # Get available node tags
        machines = db.scalars(select(Machine).where(Machine.node_id == node_id))
        # Todo need all?

        # Get available tag combinations
        ta = set()
        for m in machines:
            for i in range(1, len(m.tags) + 1):
                for tag in combinations(m.tags, i):
                    ta.add(",".join(tag))
        SERVER_TAGS[node_name] = list(ta)

    def run(self):
        global retrieve, STATUSES
        MINIMUMQUEUE = {}

        # handle another user case,
        # when master used to only store data and not process samples

        db = session()
        master_storage_only = False
        if not dist_conf.distributed.master_storage_only:
            stmt1 = select(Node.id, Node.name, Node.url, Node.apikey).where(Node.name == main_server_name)
            master = db.stelar(stmt1)
            if master is None:
                master_storage_only = True
            elif db.scalar(select(func.count(Machine.id)).where(Machine.node_id == master.id)) == 0:
                master_storage_only = True
        else:
            master_storage_only = True
        db.close()

        # MINIMUMQUEUE but per Node depending of number vms
        nodes = db.scalars(select(Node).where(Node.enabled.is_(True)))
        for node in nodes:
            MINIMUMQUEUE[node.name] = db.scalar(select(func.count(Machine.id)).where(Machine.node_id == node.id))
            ID2NAME[node.id] = node.name
            self.load_vm_tags(db, node.id, node.name)

        db.commit()
        statuses = {}
        while True:
            # HACK: This exception handling here is a big hack as well as db should check if the
            # there is any issue with the current session (expired or database is down.).
            try:
                # Remove disabled nodes
                nodes = db.scalars(select(Node).where(Node.enabled.is_(False)))

                for node in nodes or []:
                    if node.name in STATUSES:
                        STATUSES.pop(node.name)

                # Request a status update on all CAPE nodes.
                nodes = db.scalars(select(Node).where(Node.enabled.is_(True)))
                for node in nodes:
                    status = node_status(node.url, node.name, node.apikey)
                    if not status:
                        failed_count.setdefault(node.name, 0)
                        failed_count[node.name] += 1
                        # This will declare worker as dead after X failed connections checks
                        if failed_count[node.name] == dead_count:
                            log.info("[-] %s dead", node.name)
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
                            options_like=f"node={node.name}",
                            force_push_push=True,
                            db=db,
                        )
                        # We return False if nothing uploaded to cicle the nodes in case we have tags related tasks
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
                            node = db.scalar(select(Node).where(Node.name == node_name))
                        pend_tasks_num = MINIMUMQUEUE[node.name] - (
                            STATUSES[node.name]["tasks"]["pending"] + STATUSES[node.name]["tasks"]["running"]
                        )
                    except KeyError:
                        # servers hotplug
                        MINIMUMQUEUE[node.name] = db.scalar(select(func.count(Machine.id)).where(Machine.node_id == node.id))
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
                        statuses.get(main_server_name, {}).get("tasks", {}).get("pending", 0)
                        > MINIMUMQUEUE.get(main_server_name, 0)
                        and status["tasks"]["pending"] < MINIMUMQUEUE[node.name]
                    ):
                        res = self.submit_tasks(node.name, pend_tasks_num, db=db)
                        if not res:
                            continue
                db.commit()
            except Exception as e:
                log.exception("Got an exception when trying to check nodes status and submit tasks: %s.", str(e))

                # ToDo hard test this rollback, this normally only happens on db restart and similar
                db.rollback()
            time.sleep(INTERVAL)

        db.close()


def output_json(data, code, headers=None):
    """
    Create a JSON response with the given data, HTTP status code, and optional headers.

    Args:
        data (dict): The data to be serialized to JSON.
        code (int): The HTTP status code for the response.
        headers (dict, optional): Additional headers to include in the response. Defaults to None.

    Returns:
        Response: A Flask response object with the JSON data and specified headers.
    """
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
        for node in db.scalars(select(Node)):
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
        node_exist = False
        # On autoscaling we might get the same name but different IP for server. Kinda PUT friendly POST
        node = db.scalar(select(Node).where(Node.name == args["name"]))
        if node:
            if node.url == args["url"]:
                return dict(success=False, message=f"Node called {args['name']} already exists")
            else:
                node.url = args["url"]
        else:
            node = Node(name=args["name"], url=args["url"], apikey=args["apikey"])

        machines = []
        for machine in node_list_machines(args["url"], args["apikey"]):
            machines.append(dict(name=machine.name, platform=machine.platform, tags=machine.tags))
            node.machines.append(machine)
            db.add(machine)

        exitnodes = []
        for exitnode in node_list_exitnodes(args["url"], args.get("apikey")):
            exitnode_db = db.scalar(select(ExitNodes).where(ExitNodes.name == exitnode))
            if exitnode_db:
                exitnode = exitnode_db
            else:
                exitnode = ExitNodes(name=exitnode)
            exitnodes.append(dict(name=exitnode.name))
            node.exitnodes.append(exitnode)
            db.add(exitnode)

        if args.get("enabled"):
            node.enabled = bool(args["enabled"])

        if not node_exist:
            db.add(node)
        db.commit()
        db.close()

        if NFS_FETCH:
            # Add entry to /etc/fstab, create folder and mount server
            hostname = urlparse(args["url"]).netloc.split(":")[0]
            if hostname != main_server_name:
                send_socket_command(dist_conf.NFS.fstab_socket, "add_entry", *[hostname, args["name"]])

        return dict(name=args["name"], machines=machines, exitnodes=exitnodes)


class NodeApi(NodeBaseApi):
    def get(self, name):
        db = session()
        node = db.scalar(select(Node).where(Node.name == name))
        db.close()
        return dict(name=node.name, url=node.url)

    def put(self, name):
        db = session()
        args = self._parser.parse_args()
        node = db.scalar(select(Node).where(Node.name == name))

        if not node:
            return dict(error=True, error_value="Node doesn't exist")

        for k, v in args.items():
            if k == "exitnodes":
                exitnodes = []
                for exitnode in node_list_exitnodes(node.url, node.apikey):
                    exitnode_db = db.scalar(select(ExitNodes).where(ExitNodes.name == exitnode))
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
        node = db.scalar(select(Node).where(Node.name == name))
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
        task_db = db.scalar(select(Task).where(Task.main_task_id == main_task_id))
        if task_db and task_db.node_id:
            node_stmt = select(Node.id, Node.name, Node.url, Node.apikey, Node.enabled).where(Node.id == task_db.node_id)
            node = db.scalar(node_stmt)
            response = {"status": 1, "task_id": task_db.task_id, "url": node.url, "name": node.name}
        else:
            response = {"status": "pending"}
        db.close()
        return response


class StatusRootApi(RestResource):
    def get(self):
        # null = None
        db = session()
        unified_counts = db.execute(
            select(
                func.count(case((and_(Task.node_id.is_not(None), Task.finished.is_(False)), Task.id))).label("processing"),
                func.count(case((and_(Task.node_id.is_not(None), Task.finished.is_(True)), Task.id))).label("processed"),
                func.count(case((Task.node_id.is_(None), Task.id))).label("pending"),
            )
        ).first()
        tasks_counts = {
            "processing": unified_counts.processing,
            "processed": unified_counts.processed,
            "pending": unified_counts.pending,
        }
        return jsonify({"nodes": STATUSES, "tasks": tasks_counts})


class DistRestApi(RestApi):
    def __init__(self, *args, **kwargs):
        RestApi.__init__(self, *args, **kwargs)
        self.representations = {
            "application/json": output_json,
        }


def update_machine_table(node_name):
    db = session()
    node = db.scalar(select(Node).where(Node.name == node_name))

    # get new vms
    new_machines = node_list_machines(node.url, node.apikey)

    # delete all old vms
    db.execute(delete(Machine).where(Machine.node_id == node.id))

    log.info("Available VM's on %s:", node_name)
    # replace with new vms
    for machine in new_machines:
        log.info("-->\t%s", machine.name)
        node.machines.append(machine)
        db.add(machine)

    db.commit()

    log.info("Updated the machine table for node: %s", node_name)


def delete_vm_on_node(node_name, vm_name):
    db = session()
    node = db.scalar(select(Node).where(Node.name == node_name))
    vm = db.scalar(select(Machine).where(Machine.name == vm_name, Machine.node_id == node.id))

    if not vm:
        log.error("The selected VM does not exist")
        return

    status = node.delete_machine(vm_name)

    if status:
        # delete vm in dist db
        db.execute(delete(Machine).where(Machine.name == vm_name, Machine.node_id == node.id))
        db.commit()
    db.close()


def node_enabled(node_name, status):
    db = session()
    node = db.scalar(select(Node).where(Node.name == node_name))
    node.enabled = status
    db.commit()
    db.close()


def cron_cleaner(clean_x_hours=False):
    """
    Method that runs forever to clean up tasks.

    Args:
        clean_x_hours (bool or int, optional): If provided, only clean up tasks that were
        notified and created within the last `clean_x_hours` hours.

    The method performs the following steps:
    1. Checks if the cleaner is already running by looking for a PID file at "/tmp/dist_cleaner.pid".
    2. If the cleaner is not running, it creates a PID file to indicate that it is running.
    3. Connects to the database and retrieves all nodes.
    4. Depending on the `clean_x_hours` argument, it retrieves tasks that need to be cleaned up.
    5. Marks the retrieved tasks as deleted and groups them by node.
    6. Deletes the tasks from the nodes.
    7. Commits the changes to the database and closes the connection.
    8. Deletes the PID file to indicate that the cleaner has finished running.
    """
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

    for node in db.scalars(select(Node)):
        nodes.setdefault(node.id, node)

    # Allow force cleanup notificated but for some reason not deleted even when it set to deleted
    if clean_x_hours:
        stmt = (
            select(Task)
            .where(Task.notificated.is_(True), Task.clock >= datetime.now() - timedelta(hours=clean_x_hours))
            .order_by(Task.id.desc())
        )
    else:
        stmt = select(Task).where(Task.notificated.is_(True), Task.deleted.is_(False)).order_by(Task.id.desc())
    tasks = db.scalars(stmt)
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

    for h in log.handlers[:]:
        if isinstance(h, logging.StreamHandler) and h.stream == sys.stderr:
            log.removeHandler(h)
            h.close()

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
    init_database()

    if args.enable_clean:
        cron_cleaner(args.clean_hours)
        # sys.exit()

    if args.force_reported:
        with main_db.session.begin():
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
    init_database(exists_ok=True)
    app = create_app(database_connection=dist_conf.distributed.db)

    # this allows run it with gunicorn/uwsgi
    log = init_logging(True)
    retrieve = Retriever(name="Retriever")
    retrieve.daemon = True
    retrieve.start()

    t = StatusThread(name="StatusThread")
    t.daemon = True
    t.start()
