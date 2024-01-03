# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import atexit
import logging
import os
import shutil
import sys
from contextlib import suppress
from datetime import datetime, timedelta
from multiprocessing.pool import ThreadPool

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dist_db import Task as DTask
from lib.cuckoo.common.dist_db import create_session
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_get_date, path_is_dir
from lib.cuckoo.common.utils import delete_folder
from lib.cuckoo.core.database import (
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_PENDING,
    TASK_RECOVERED,
    TASK_REPORTED,
    Database,
    Sample,
    Task,
)
from lib.cuckoo.core.startup import create_structure, init_console_logging

log = logging.getLogger(__name__)

cuckoo = Config()
repconf = Config("reporting")
webconf = Config("web")
resolver_pool = ThreadPool(50)
atexit.register(resolver_pool.close)

# Initialize the database connection.
db = Database()
if repconf.mongodb.enabled:
    mdb = repconf.mongodb.get("db", "cuckoo")
    from dev_utils.mongo_hooks import delete_unused_file_docs
    from dev_utils.mongodb import (
        connect_to_mongo,
        mdb,
        mongo_delete_data,
        mongo_drop_database,
        mongo_find,
        mongo_is_cluster,
        mongo_update_one,
    )
elif repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import all_docs, delete_analysis_and_related_calls, get_analysis_index


def connect_to_es():
    from dev_utils.elasticsearchdb import elastic_handler

    es = elastic_handler

    return es


def is_reporting_db_connected():
    try:
        if not webconf.web_reporting.enabled:
            return True
        if repconf.mongodb.enabled:
            results_db = connect_to_mongo()[mdb]
            # Database objects do not implement truth value testing or bool(). Please compare with None instead: database is not None
            if results_db is None:
                log.info("Can't connect to mongo")
                return False
            return True
        elif repconf.elasticsearchdb.enabled:
            connect_to_es()
            return True
    except Exception as e:
        log.error(f"Can't connect to reporting db {e}")
        return False


def delete_bulk_tasks_n_folders(tids: list, delete_mongo: bool):
    ids = [tid["info.id"] for tid in tids]
    for i in range(0, len(ids), 10):
        ids_tmp = ids[i : i + 10]
        if delete_mongo:
            if mongo_is_cluster():
                response = input("You are deleting mongo data in cluster, are you sure you want to continue? y/n")
                if response.lower() in ("n", "not"):
                    sys.exit()
            mongo_delete_data(ids_tmp)

            for id in ids_tmp:
                if db.delete_task(id):
                    try:
                        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % str(id))
                        if path_is_dir(path):
                            delete_folder(path)
                    except Exception as e:
                        log.error(e)
        else:
            # If we don't remove from mongo we should keep in db to be able to show task in webgui
            for id in ids_tmp:
                try:
                    path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % str(id))
                    if path_is_dir(path):
                        delete_folder(path)
                except Exception as e:
                    log.error(e)


def fail_job(tid):
    if isinstance(tid, dict):
        if "info.id" in tid:
            tid = tid["info.id"]
        elif tid.get("info", {}).get("id", 0):
            tid = tid["info"]["id"]
        elif "id" in tid:
            tid = tid["id"]
    log.info("set %s job to failed" % (tid))

    db.set_status(tid, TASK_FAILED_ANALYSIS)


def delete_data(tid):
    if isinstance(tid, dict):
        if "info.id" in tid:
            tid = tid["info.id"]
        elif tid.get("info", {}).get("id", 0):
            tid = tid["info"]["id"]
        elif "id" in tid:
            tid = tid["id"]
    try:
        log.info("removing %s from analysis db" % (tid))
        if repconf.mongodb.enabled:
            mongo_delete_data(tid)
        elif repconf.elasticsearchdb.enabled:
            delete_analysis_and_related_calls(tid)
    except Exception as e:
        log.error("failed to remove analysis info (may not exist) %s due to %s" % (tid, e), exc_info=True)
    if db.delete_task(tid):
        delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % tid))
    else:
        log.info("failed to remove faile task %s from DB" % (tid))


def dist_delete_data(data, dist_db):
    for id, file in data:
        try:
            if path_exists(file):
                try:
                    path_delete(file)
                except Exception as e:
                    log.info(e)
            db.delete_task(id)
            # clean dist_db
            dist_task = dist_db.query(Task).filter(DTask.main_task.id == id).first()
            if dist_task:
                dist_db.delete(dist_task.id)
        except Exception as e:
            log.info(e)


def cuckoo_clean():
    """Clean up cuckoo setup.
    It deletes logs, all stored data from file system and configured databases (SQL
    and MongoDB.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    # Drop all tables.
    db.drop()

    if repconf.mongodb.enabled:
        try:
            mongo_drop_database(mdb)
        except Exception as e:
            log.error("Can't drop MongoDB. Error %s", str(e))

    elif repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
        analyses = all_docs(index=get_analysis_index(), query={"query": {"match_all": {}}}, _source=["info.id"])
        if analyses:
            for analysis in analyses:
                delete_analysis_and_related_calls(analysis["_source"]["info"]["id"])

    # Paths to clean.
    paths = [
        os.path.join(CUCKOO_ROOT, "db"),
        os.path.join(CUCKOO_ROOT, "log"),
        os.path.join(CUCKOO_ROOT, "storage"),
    ]

    # Delete various directories.
    for path in paths:
        if path_is_dir(path):
            try:
                shutil.rmtree(path)
            except (IOError, OSError) as e:
                log.warning("Error removing directory %s: %s", path, e)

    # Delete all compiled Python objects ("*.pyc").
    for dirpath, dirnames, filenames in os.walk(CUCKOO_ROOT):
        for fname in filenames:
            if not fname.endswith(".pyc"):
                continue

            path = os.path.join(CUCKOO_ROOT, dirpath, fname)

            try:
                path_delete(path)
            except (IOError, OSError) as e:
                log.warning("Error removing file %s: %s", path, e)


def cuckoo_clean_failed_tasks():
    """Clean up failed tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    failed_tasks_a = db.list_tasks(status=TASK_FAILED_ANALYSIS)
    failed_tasks_p = db.list_tasks(status=TASK_FAILED_PROCESSING)
    failed_tasks_r = db.list_tasks(status=TASK_FAILED_REPORTING)
    failed_tasks_rc = db.list_tasks(status=TASK_RECOVERED)
    resolver_pool.map(lambda tid: delete_data(tid.to_dict()["id"]), failed_tasks_a)
    resolver_pool.map(lambda tid: delete_data(tid.to_dict()["id"]), failed_tasks_p)
    resolver_pool.map(lambda tid: delete_data(tid.to_dict()["id"]), failed_tasks_r)
    resolver_pool.map(lambda tid: delete_data(tid.to_dict()["id"]), failed_tasks_rc)


def cuckoo_clean_bson_suri_logs():
    """Clean up raw suri log files probably not needed if storing in mongo. Does not remove extracted files"""
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()
    from glob import glob

    failed_tasks_a = db.list_tasks(status=TASK_FAILED_ANALYSIS)
    failed_tasks_p = db.list_tasks(status=TASK_FAILED_PROCESSING)
    failed_tasks_r = db.list_tasks(status=TASK_FAILED_REPORTING)
    failed_tasks_rc = db.list_tasks(status=TASK_RECOVERED)
    tasks_rp = db.list_tasks(status=TASK_REPORTED)
    for e in failed_tasks_a, failed_tasks_p, failed_tasks_r, failed_tasks_rc, tasks_rp:
        for el2 in e:
            new = el2.to_dict()
            id = new["id"]
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % id)
            if path_exists(path):
                jsonlogs = glob("%s/logs/*json*" % (path))
                bsondata = glob("%s/logs/*.bson" % (path))
                filesmeta = glob("%s/logs/files/*.meta" % (path))
                for f in jsonlogs, bsondata, filesmeta:
                    for fe in f:
                        try:
                            log.info(("removing %s" % (fe)))
                            path_delete(fe)
                        except Exception as Err:
                            log.info(("failed to remove sorted_pcap from disk %s" % (Err)))


def cuckoo_clean_failed_url_tasks():
    """Clean up failed tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()
    if not is_reporting_db_connected():
        return

    if repconf.mongodb.enabled:
        query = {"info.category": "url", "network.http.0": {"$exists": False}}
        rtmp = mongo_find("analysis", query, projection={"info.id": 1}, sort=[("_id", -1)], limit=100)
    elif repconf.elasticsearchdb.enabled:
        rtmp = [
            d["_source"]
            for d in all_docs(
                index=get_analysis_index(),
                query={"query": {"bool": {"must": [{"exists": {"field": "network.http"}}, {"match": {"info.category": "url"}}]}}},
                _source=["info.id"],
            )
        ]
    else:
        rtmp = []

    if rtmp and len(rtmp) > 0:
        resolver_pool.map(lambda tid: delete_data(tid), rtmp)


def cuckoo_clean_lower_score(args):
    """Clean up tasks with score <= X
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    if not args.malscore:
        log.info("No malscore argument provided bailing")
        return

    create_structure()
    init_console_logging()
    id_arr = []
    if not is_reporting_db_connected():
        return

    if repconf.mongodb.enabled:
        result = list(mongo_find("analysis", {"malscore": {"$lte": args.malscore}}))
        id_arr = [entry["info"]["id"] for entry in result]
    elif repconf.elasticsearchdb.enabled:
        id_arr = [
            d["_source"]["info"]["id"]
            for d in all_docs(
                index=get_analysis_index(), query={"query": {"range": {"malscore": {"lte": args.malscore}}}}, _source=["info.id"]
            )
        ]
    log.info(("number of matching records %s" % len(id_arr)))
    resolver_pool.map(lambda tid: delete_data(tid), id_arr)


def tmp_clean_before_day(args):
    """Clean up tmp folder
    It deletes all items in tmp folder before now - days.
    """
    if not args.delete_tmp_items_older_than_days:
        log.info("Must provide argument delete_tmp_items_older_than_days")
        return

    days = args.delete_tmp_items_older_than_days
    init_console_logging()

    today = datetime.today()
    tmp_folder_path = cuckoo.cuckoo.get("tmppath")

    for root, directories, files in os.walk(tmp_folder_path, topdown=True):
        for name in files + directories:
            path = os.path.join(root, name)
            last_modified_time_in_seconds = os.stat(os.path.join(root, path)).st_mtime
            file_time = today - datetime.fromtimestamp(last_modified_time_in_seconds)

            if file_time.days > days:
                try:
                    if path_is_dir(path):
                        log.info("Delete folder: %s", path)
                        delete_folder(path)
                    elif path_exists(path):
                        log.info("Delete file: %s", path)
                        path_delete(path)
                except Exception as e:
                    log.error(e)


def cuckoo_clean_before_day(args):
    """Clean up failed tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for tasks completed before now - days.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    if not args.delete_older_than_days:
        log.info("No days argument provided bailing")
        return
    else:
        days = args.delete_older_than_days
    create_structure()
    init_console_logging()
    id_arr = []

    if not is_reporting_db_connected():
        return

    added_before = datetime.now() - timedelta(days=int(days))
    if args.files_only_filter:
        log.info("file filter applied")
        old_tasks = db.list_tasks(added_before=added_before, category="file")
    elif args.urls_only_filter:
        log.info("url filter applied")
        old_tasks = db.list_tasks(added_before=added_before, category="url")
    else:
        old_tasks = db.list_tasks(added_before=added_before)

    for e in old_tasks:
        id_arr.append({"info.id": (int(e.to_dict()["id"]))})

    log.info(("number of matching records %s before suri/custom filter " % len(id_arr)))
    if id_arr and args.suricata_zero_alert_filter:
        result = list(
            mongo_find("analysis", {"suricata.alerts.alert": {"$exists": False}, "$or": id_arr}, {"info.id": 1, "_id": 0})
        )
        id_arr = [entry["info"]["id"] for entry in result]
    if id_arr and args.custom_include_filter:
        result = list(
            mongo_find("analysis", {"info.custom": {"$regex": args.custom_include_filter}, "$or": id_arr}, {"info.id": 1, "_id": 0})
        )
        id_arr = [entry["info"]["id"] for entry in result]
    log.info("number of matching records %s" % len(id_arr))
    delete_bulk_tasks_n_folders(id_arr, args.delete_mongo)
    # resolver_pool.map(lambda tid: delete_data(tid), id_arr)


def cuckoo_clean_sorted_pcap_dump():
    """Clean up failed tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    if not is_reporting_db_connected():
        return

    if repconf.elasticsearchdb.enabled:
        es = connect_to_es()

    done = False

    while not done:
        if repconf.mongodb.enabled:
            query = {"network.sorted_pcap_id": {"$exists": True}}
            rtmp = mongo_find("analysis", query, projection={"info.id": 1}, sort=[("_id", -1)], limit=100)
        elif repconf.elasticsearchdb.enabled:
            rtmp = [
                d["_source"]
                for d in all_docs(
                    index=get_analysis_index(),
                    query={"query": {"exists": {"field": "network.sorted_pcap_id"}}},
                    _source=["info.id"],
                )
            ]
        else:
            rtmp = 0

        if rtmp and len(rtmp) > 0:
            for e in rtmp:
                if e["info"]["id"]:
                    log.info((e["info"]["id"]))
                    try:
                        if repconf.mongodb.enabled:
                            mongo_update_one(
                                "analysis", {"info.id": int(e["info"]["id"])}, {"$unset": {"network.sorted_pcap_id": ""}}
                            )
                        elif repconf.elasticsearchdb.enabled:
                            es.update(index=e["index"], id=e["info"]["id"], body={"network.sorted_pcap_id": ""})
                    except Exception:
                        log.info(("failed to remove sorted pcap from db for id %s" % (e["info"]["id"])))
                    try:
                        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % (e["info"]["id"]), "dump_sorted.pcap")
                        path_delete(path)
                    except Exception as e:
                        log.info(("failed to remove sorted_pcap from disk %s" % (e)))
                else:
                    done = True
        else:
            done = True


def cuckoo_clean_pending_tasks(before_time: int = None, delete: bool = False):
    """Clean up pending tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for pending tasks.
    """

    from datetime import timedelta

    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    if not is_reporting_db_connected():
        return
    if before_time:
        before_time = datetime.now() - timedelta(hours=before_time)

    pending_tasks = db.list_tasks(status=TASK_PENDING, added_before=before_time)
    clean_handler = delete_data if delete else fail_job
    resolver_pool.map(lambda tid: clean_handler(tid.to_dict()["id"]), pending_tasks)


def cuckoo_clean_range_tasks(start, end):
    """Clean up tasks between start and end
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for selected tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()
    pending_tasks = db.list_tasks(id_after=start - 1, id_before=end + 1)
    resolver_pool.map(lambda tid: delete_data(tid.to_dict()["id"]), pending_tasks)


def delete_unused_file_data_in_mongo():
    """Cleans the entries in the 'files' collection that no longer have any analysis
    tasks associated with them.
    """
    init_console_logging()
    log.info("Removing file entries in Mongo that are no longer referenced.")
    result = delete_unused_file_docs()
    log.info("Removed %s file %s.", result.deleted_count, "entry" if result.deleted_count == 1 else "entries")


def cuckoo_dedup_cluster_queue():
    """
    Cleans duplicated pending tasks from cluster queue
    """

    session = db.Session()
    dist_session = create_session(repconf.distributed.db, echo=False)
    dist_db = dist_session()
    hash_dict = {}
    duplicated = (
        session.query(Sample, Task).join(Task).filter(Sample.id == Task.sample_id, Task.status == "pending").order_by(Sample.sha256)
    )

    for sample, task in duplicated:
        with suppress(UnicodeDecodeError):
            # hash -> [[id, file]]
            hash_dict.setdefault(sample.sha256, []).append((task.id, task.target))

    resolver_pool.map(lambda sha256: dist_delete_data(hash_dict[sha256][1:], dist_db), hash_dict)


def cape_clean_tlp():
    create_structure()
    init_console_logging()

    if not is_reporting_db_connected():
        return

    tlp_tasks = db.get_tlp_tasks()
    resolver_pool.map(lambda tid: delete_data(tid), tlp_tasks)


def binaries_clean_before_day(args):
    # In case if "delete_bin_copy = off" we might need to clean binaries
    # find storage/binaries/ -name "*" -type f -mtime 5 -delete

    days = args.delete_binaries_items_older_than_days
    today = datetime.today()
    binaries_folder = os.path.join(CUCKOO_ROOT, "storage", "binaries")
    if not path_exists(binaries_folder):
        log.error("Binaries folder doesn't exist")
        return

    for _, _, filenames in os.walk(binaries_folder):
        for sha256 in filenames:
            bin_path = os.path.join(binaries_folder, sha256)
            st_ctime = path_get_date(bin_path)
            file_time = today - datetime.fromtimestamp(st_ctime)
            if file_time.days > days:
                # ToDo check database here to ensure that file is not used
                if path_exists(bin_path) and not db.sample_still_used(sha256, 0):
                    path_delete(bin_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--clean", help="Remove all tasks and samples and their associated data", action="store_true", required=False
    )
    parser.add_argument("--failed-clean", help="Remove all tasks marked as failed", action="store_true", required=False)
    parser.add_argument(
        "--failed-url-clean",
        help="Remove all tasks that are url tasks but we don't have any HTTP traffic",
        action="store_true",
        required=False,
    )
    parser.add_argument("--delete-older-than-days", help="Remove all tasks older than X number of days", type=int, required=False)
    parser.add_argument("--pcap-sorted-clean", help="remove sorted pcap from jobs", action="store_true", required=False)
    parser.add_argument(
        "--suricata-zero-alert-filter",
        help="only remove events with zero suri alerts DELETE AFTER ONLY",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--urls-only-filter", help="only remove url events filter DELETE AFTER ONLY", action="store_true", required=False
    )
    parser.add_argument(
        "--files-only-filter", help="only remove files events filter DELETE AFTER ONLY", action="store_true", required=False
    )
    parser.add_argument(
        "--custom-include-filter", help="Only include jobs that match the custom field DELETE AFTER ONLY", required=False
    )
    parser.add_argument(
        "--bson-suri-logs-clean", help="clean bson and suri logs from analysis dirs", required=False, action="store_true"
    )
    parser.add_argument("--pending-clean", help="Remove all tasks marked as pending", required=False, action="store_true")
    parser.add_argument("--malscore", help="Remove all tasks with malscore <= X", required=False, action="store", type=int)
    parser.add_argument("--tlp", help="Remove all tasks with TLP", required=False, default=False, action="store_true")
    parser.add_argument(
        "--delete-tmp-items-older-than-days",
        help="Remove all items in tmp folder older than X days",
        type=int,
        required=False,
    )
    parser.add_argument(
        "--delete-binaries-items-older-than-days",
        help="Remove all items in binaries folder older than X days",
        type=int,
        required=False,
    )
    parser.add_argument(
        "-dm", "--delete-mongo", help="Delete data in mongo. By default keep", required=False, default=False, action="store_true"
    )
    parser.add_argument(
        "-duf",
        "--delete-unused-file-data-in-mongo",
        help="Delete data from the 'files' collection in mongo that is no longer needed.",
        action="store_true",
    )
    parser.add_argument(
        "-drs",
        "--delete-range-start",
        help="First job in range to delete, should be used with --delete-range-end",
        action="store",
        type=int,
        required=False,
    )
    parser.add_argument(
        "-dre",
        "--delete-range-end",
        help="Last job in range to delete, should be used with --delete-range-start",
        action="store",
        type=int,
        required=False,
    )
    parser.add_argument(
        "-ddc",
        "--deduplicated-cluster-queue",
        help="Remove all pending duplicated jobs for our cluster, leave only 1 copy of task",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "-bt", "--before-time", help="Manage all pending jobs before N hours.", action="store", required=False, type=int
    )
    args = parser.parse_args()

    if args.clean:
        cuckoo_clean()
        sys.exit(0)

    if args.tlp:
        cape_clean_tlp()
        sys.exit()

    if args.failed_clean:
        cuckoo_clean_failed_tasks()
        sys.exit(0)

    if args.failed_url_clean:
        cuckoo_clean_failed_url_tasks()
        sys.exit(0)

    if args.delete_older_than_days:
        cuckoo_clean_before_day(args)
        sys.exit(0)

    if args.pcap_sorted_clean:
        cuckoo_clean_sorted_pcap_dump()
        sys.exit(0)

    if args.bson_suri_logs_clean:
        cuckoo_clean_bson_suri_logs()
        sys.exit(0)

    if args.pending_clean:
        cuckoo_clean_pending_tasks(args.before_time)
        sys.exit(0)

    if args.malscore:
        cuckoo_clean_lower_score(args)
        sys.exit(0)

    if args.delete_range_start and args.delete_range_end:
        cuckoo_clean_range_tasks(args.delete_range_start, args.delete_range_end)
        sys.exit(0)

    if args.deduplicated_cluster_queue:
        cuckoo_dedup_cluster_queue()
        sys.exit(0)

    if args.delete_tmp_items_older_than_days:
        tmp_clean_before_day(args)
        sys.exit(0)

    if args.delete_binaries_items_older_than_days:
        binaries_clean_before_day(args)
        sys.exit(0)

    if args.delete_unused_file_data_in_mongo:
        delete_unused_file_data_in_mongo()
        sys.exit(0)
