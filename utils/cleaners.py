# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function

import os
import sys
import shutil
import argparse
import logging
from datetime import datetime, timedelta
from multiprocessing.pool import ThreadPool

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from bson.objectid import ObjectId
from sqlalchemy import desc
from lib.cuckoo.common.dist_db import create_session
from lib.cuckoo.common.dist_db import Task as DTask
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import delete_folder
from lib.cuckoo.core.startup import create_structure, init_console_logging
from lib.cuckoo.core.database import (
    Database,
    Task,
    Sample,
    TASK_RUNNING,
    TASK_PENDING,
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_RECOVERED,
    TASK_REPORTED,
)


log = logging.getLogger()

cuckoo = Config()
repconf = Config("reporting")
resolver_pool = ThreadPool(50)

# Initialize the database connection.
db = Database()
mdb = repconf.mongodb.get("db", "cuckoo")


def connect_to_mongo():
    conn = False
    # Check if MongoDB reporting is enabled and drop that if it is.
    if repconf.mongodb and repconf.mongodb.enabled:
        from pymongo import MongoClient
        try:
            conn = MongoClient(
                host = repconf.mongodb.get("host", "127.0.0.1"),
                port = repconf.mongodb.get("port", 27017),
                username = repconf.mongodb.get("username", None),
                password = repconf.mongodb.get("password", None),
                authSource = repconf.mongodb.get("authsource", "cuckoo")
            )
        except Exception as e:
            log.warning("Unable to connect to MongoDB database: {}, {}".format(mdb, e))

    return conn


def connect_to_es():
    es = None
    delidx = None
    # Check if ElasticSearch is enabled and delete that data if it is.
    from elasticsearch import Elasticsearch

    delidx = repconf.elasticsearchdb.index + "-*"
    try:
        es = Elasticsearch(hosts=[{"host": repconf.elasticsearchdb.host, "port": repconf.elasticsearchdb.port,}], timeout=60)
    except:
        log.warning("Unable to connect to ElasticSearch")

    return es, delidx

def delete_bulk_tasks_n_folders(tids: list, delete_mongo: bool):
    results_db = connect_to_mongo()[mdb]
    ids = [tid["info.id"] for tid in tids]
    for i in range(0, len(ids), 10):
        ids_tmp = ids[i:i+10]
        if delete_mongo is True:
            try:
                analyses_tmp = list()
                log.info("Deleting MongoDB data for Tasks #{0}".format(",".join([str(id) for id in ids_tmp])))
                analyses = results_db.analysis.find({"info.id": {"$in": [id for id in ids_tmp]}}, {"behavior.processes": 1, "_id": 1})
                if analyses:
                    for analysis in analyses:
                        calls = list()
                        for process in analysis.get("behavior", {}).get("processes", []):
                            calls = list()
                            for call in process["calls"]:
                                #results_db.calls.delete_one({"_id": ObjectId(call)})
                                calls.append(ObjectId(call))
                        if calls:
                            results_db.analysis.delete_many({"_id": {"$in": calls}})
                        #results_db.analysis.delete_one({"_id": ObjectId(analysis["_id"])})
                        analyses_tmp.append(ObjectId(analysis["_id"]))
                if analyses_tmp:
                    results_db.analysis.delete_many({"_id": {"$in": analyses_tmp}})
            except Exception as e:
                log.info(e)

            if db.delete_tasks(ids_tmp):
                for id in ids_tmp:
                    try:
                        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % str(id))
                        if os.path.isdir(path):
                            delete_folder(path)
                    except Exception as e:
                        log.error(e)
        else:
            # If we don't remove from mongo we should keep in db to be able to show task in webgui
            for id in ids_tmp:
                try:
                    path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % str(id))
                    if os.path.isdir(path):
                        delete_folder(path)
                except Exception as e:
                    log.error(e)

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
        delete_mongo_data(tid)
    except:
        log.info("failed to remove analysis info (may not exist) %s" % (tid))
    if db.delete_task(tid):
        delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % tid))
    else:
        log.info("failed to remove faile task %s from DB" % (tid))

def delete_mongo_data(tid):
    try:
        results_db = connect_to_mongo()[mdb]
        analyses = results_db.analysis.find({"info.id": int(tid)}, {"behavior.processes": 1, "_id": 1})
        if analyses.count() > 0:
            for analysis in analyses:
                calls = list()
                log.info("deleting MongoDB data for Task #{0}".format(tid))
                for process in analysis.get("behavior", {}).get("processes", []):
                    calls = list()
                    for call in process["calls"]:
                        #results_db.calls.delete_one({"_id": ObjectId(call)})
                        calls.append(ObjectId(call))

                if calls:
                    results_db.analysis.delete_many({"_id": {"$in": calls}})
                results_db.analysis.delete_one({"_id": ObjectId(analysis["_id"])})
    except Exception as e:
        log.info(e)


def dist_delete_data(data, dist_db):
    for id, file in data:
        try:
            if os.path.exists(file):
                try:
                    os.remove(file)
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

    conn = connect_to_mongo()
    if not conn:
        log.info("Can't connect to mongo")
        return
    try:
        conn.drop_database(mdb)
        conn.close()
    except:
        log.warning("Unable to drop MongoDB database: %s", mdb)

    if repconf.elasticsearchdb and repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
        es = False
        es, delidx = connect_to_es()
        if not es:
            return
        analyses = es.search(index=delidx, doc_type="analysis", q="*")["hits"]["hits"]
        if analyses:
            for analysis in analyses:
                esidx = analysis["_index"]
                esid = analysis["_id"]
                # Check if behavior exists
                if analysis["_source"]["behavior"]:
                    for process in analysis["_source"]["behavior"]["processes"]:
                        for call in process["calls"]:
                            es.delete(
                                index=esidx, doc_type="calls", id=call,
                            )
                # Delete the analysis results
                es.delete(
                    index=esidx, doc_type="analysis", id=esid,
                )

    # Paths to clean.
    paths = [
        os.path.join(CUCKOO_ROOT, "db"),
        os.path.join(CUCKOO_ROOT, "log"),
        os.path.join(CUCKOO_ROOT, "storage"),
    ]

    # Delete various directories.
    for path in paths:
        if os.path.isdir(path):
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
                os.unlink(path)
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
    """Clean up raw suri log files probably not needed if storing in mongo. Does not remove extracted files
    """
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
            if os.path.exists(path):
                jsonlogs = glob("%s/logs/*json*" % (path))
                bsondata = glob("%s/logs/*.bson" % (path))
                filesmeta = glob("%s/logs/files/*.meta" % (path))
                for f in jsonlogs, bsondata, filesmeta:
                    for fe in f:
                        try:
                            log.info(("removing %s" % (fe)))
                            os.remove(fe)
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
    results_db = connect_to_mongo()[mdb]
    if not results_db:
        log.info("Can't connect to mongo")
        return

    rtmp = results_db.analysis.find({"info.category": "url", "network.http.0": {"$exists": False}}, {"info.id": 1}, sort=[("_id", -1)]).limit(
        100
    )
    if rtmp and rtmp.count() > 0:
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
    results_db = connect_to_mongo()[mdb]
    if not results_db:
        log.info("Can't connect to mongo")
        return

    result = list(results_db.analysis.find({"malscore": {"$lte": args.malscore}}))
    id_arr = [entry["info"]["id"] for entry in result]
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
                    if os.path.isdir(path):
                        log.info("Delete folder: {0}".format(path))
                        delete_folder(path)
                    else:
                        if os.path.exists(path):
                            log.info("Delete file: {0}".format(path))
                            os.remove(path)
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

    results_db = connect_to_mongo()[mdb]
    if not results_db:
        log.info("Can't connect to mongo")
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
        result = list(results_db.analysis.find({"suricata.alerts.alert": {"$exists": False}, "$or": id_arr}, {"info.id": 1, "_id": 0}))
        id_arr = [entry["info"]["id"] for entry in result]
    if id_arr and args.custom_include_filter:
        result = list(results_db.analysis.find({"info.custom": {"$regex": args.custom_include_filter}, "$or": id_arr}, {"info.id": 1, "_id": 0}))
        id_arr = [entry["info"]["id"] for entry in result]
    log.info("number of matching records %s" % len(id_arr))
    delete_bulk_tasks_n_folders(id_arr, args.delete_mongo)
    #resolver_pool.map(lambda tid: delete_data(tid), id_arr)


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
    results_db = connect_to_mongo()[mdb]
    if not results_db:
        log.info("Can't connect to mongo")
        return

    done = False
    while not done:
        rtmp = results_db.analysis.find({"network.sorted_pcap_id": {"$exists": True}}, {"info.id": 1}, sort=[("_id", -1)]).limit(100)
        if rtmp and rtmp.count() > 0:
            for e in rtmp:
                if e["info"]["id"]:
                    log.info((e["info"]["id"]))
                    try:
                        results_db.analysis.update({"info.id": int(e["info"]["id"])}, {"$unset": {"network.sorted_pcap_id": ""}})
                    except:
                        log.info(("failed to remove sorted pcap from db for id %s" % (e["info"]["id"])))
                    try:
                        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % (e["info"]["id"]), "dump_sorted.pcap")
                        os.remove(path)
                    except Exception as e:
                        log.info(("failed to remove sorted_pcap from disk %s" % (e)))
                else:
                    done = True
        else:
            done = True


def cuckoo_clean_pending_tasks():
    """Clean up pending tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for pending tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()

    results_db = connect_to_mongo()[mdb]
    if not results_db:
        log.info("Can't connect to mongo")
        return

    pending_tasks = db.list_tasks(status=TASK_PENDING)
    resolver_pool.map(lambda tid: delete_data(tid.to_dict()["id"]), pending_tasks)


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


def cuckoo_dedup_cluster_queue():

    """
    Cleans duplicated pending tasks from cluster queue
    """

    session = db.Session()
    dist_session = create_session(repconf.distributed.db, echo=False)
    dist_db = dist_session()
    hash_dict = dict()
    duplicated = session.query(Sample, Task).join(Task).filter(Sample.id == Task.sample_id, Task.status == "pending").order_by(Sample.sha256)

    for sample, task in duplicated:
        try:
            # hash -> [[id, file]]
            hash_dict.setdefault(sample.sha256, list())
            hash_dict[sample.sha256].append((task.id, task.target))
        except UnicodeDecodeError:
            pass

    resolver_pool.map(lambda sha256: dist_delete_data(hash_dict[sha256][1:], dist_db), hash_dict)


def cape_clean_tlp():

    create_structure()
    init_console_logging()

    results_db = connect_to_mongo()[mdb]
    if not results_db:
        log.info("Can't connect to mongo")
        return

    tlp_tasks = db.get_tlp_tasks()
    resolver_pool.map(lambda tid: delete_data(tid), tlp_tasks)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean", help="Remove all tasks and samples and their associated data", action="store_true", required=False)
    parser.add_argument("--failed-clean", help="Remove all tasks marked as failed", action="store_true", required=False)
    parser.add_argument("--failed-url-clean", help="Remove all tasks that are url tasks but we don't have any HTTP traffic", action="store_true", required=False)
    parser.add_argument("--delete-older-than-days", help="Remove all tasks older than X number of days", type=int, required=False)
    parser.add_argument("--pcap-sorted-clean", help="remove sorted pcap from jobs", action="store_true", required=False)
    parser.add_argument("--suricata-zero-alert-filter", help="only remove events with zero suri alerts DELETE AFTER ONLY", action="store_true", required=False)
    parser.add_argument("--urls-only-filter", help="only remove url events filter DELETE AFTER ONLY", action="store_true", required=False)
    parser.add_argument("--files-only-filter", help="only remove files events filter DELETE AFTER ONLY", action="store_true", required=False)
    parser.add_argument("--custom-include-filter", help="Only include jobs that match the custom field DELETE AFTER ONLY", required=False)
    parser.add_argument("--bson-suri-logs-clean", help="clean bson and suri logs from analysis dirs", required=False, action="store_true")
    parser.add_argument("--pending-clean", help="Remove all tasks marked as pending", required=False, action="store_true")
    parser.add_argument("--malscore", help="Remove all tasks with malscore <= X", required=False, action="store", type=int)
    parser.add_argument("--tlp", help="Remove all tasks with TLP", required=False, default=False, action="store_true")
    parser.add_argument("--delete-tmp-items-older-than-days", help="Remove all items in tmp folder older than X number of days", type=int, required=False)
    parser.add_argument("-dm", "--delete-mongo", help="Delete data in mongo", required=False, default=False, action="store_true")
    parser.add_argument("-drs", "--delete-range-start", help="First job in range to delete, should be used with --delete-range-end", action="store", type=int, required=False,)
    parser.add_argument("-dre", "--delete-range-end", help="Last job in range to delete, should be used with --delete-range-start", action="store", type=int, required=False )
    parser.add_argument("-ddc", "--deduplicated-cluster-queue", help="Remove all pending duplicated jobs for our cluster, leave only 1 copy of task", action="store_true", required=False )
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
        cuckoo_clean_pending_tasks()
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
