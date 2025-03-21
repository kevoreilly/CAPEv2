import atexit
import logging
import os
import shutil
import sys
import time
from contextlib import suppress
from datetime import datetime, timedelta
from multiprocessing.pool import ThreadPool

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.dist_db import Task as DTask
from lib.cuckoo.common.dist_db import create_session
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_get_date, path_is_dir, path_mkdir
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
    _Database,
)
from lib.cuckoo.core.startup import create_structure, init_console_logging

log = logging.getLogger(__name__)

config = Config()
repconf = Config("reporting")
webconf = Config("web")
resolver_pool = ThreadPool(50)
atexit.register(resolver_pool.close)

HAVE_TMPFS = False
if hasattr(config, "tmpfs"):
    tmpfs = config.tmpfs
    HAVE_TMPFS = True

# Initialize the database connection.
db: _Database = Database()
if repconf.mongodb.enabled:
    # mdb = repconf.mongodb.get("db", "cuckoo")
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


def free_space_monitor(path=False, return_value=False, processing=False, analysis=False):
    """
    @param path: path to check
    @param return_value: return available size
    @param processing: size from cuckoo.conf -> freespace_processing.
    @param analysis: check the main storage size
    """

    cleanup_dict = {
        "delete_mongo": config.cleaner.mongo,
    }
    if config.cleaner.binaries_days:
        cleanup_dict["delete_binaries_items_older_than_days"] = int(config.cleaner.binaries_days)
    if config.cleaner.tmp_days:
        cleanup_dict["delete_tmp_items_older_than_days"] = int(config.cleaner.tmp_days)
    if config.cleaner.analysis_days:
        cleanup_dict["delete_older_than_days"] = int(config.cleaner.analysis_days)
    if config.cleaner.unused_files_in_mongodb:
        cleanup_dict["delete_unused_file_data_in_mongo"] = 1

    need_space, space_available = False, 0
    # Calculate the free disk space in megabytes.
    # Check main FS if processing
    if processing:
        free_space = config.cuckoo.freespace_processing
    elif not analysis and HAVE_TMPFS and tmpfs.enabled:
        path = tmpfs.path
        free_space = tmpfs.freespace
    else:
        free_space = config.cuckoo.freespace

    if path and not path_exists(path):
        sys.exit("Restart daemon/process, happens after full cleanup")

    printed_error = False
    while True:
        try:
            space_available = shutil.disk_usage(path).free >> 20
            need_space = space_available < free_space
        except FileNotFoundError:
            log.error("Folder doesn't exist, maybe due to clean")
            path_mkdir(path)
            continue

        if return_value:
            return need_space, space_available

        if need_space:
            if not printed_error:
                log.error(
                    "Not enough free disk space! (Only %d MB!). You can change limits it in cuckoo.conf -> freespace",
                    space_available,
                )
                printed_error = True

            # Invoke cleaups here if enabled
            if config.cleaner.enabled:
                # prepare dict on startup
                execute_cleanup(cleanup_dict)

                # rest 1 day
                if config.cleaner.binaries_days and cleanup_dict["delete_binaries_items_older_than_days"]:
                    cleanup_dict["delete_binaries_items_older_than_days"] -= 1
                if config.cleaner.tmp_days and cleanup_dict["delete_tmp_items_older_than_days"]:
                    cleanup_dict["delete_tmp_items_older_than_days"] -= 1
                if config.cleaner.analysis_days and cleanup_dict["delete_older_than_days"]:
                    cleanup_dict["delete_older_than_days"] -= 1

            time.sleep(5)
        else:
            break


def delete_folder(folder):
    """Delete a folder and all its subdirectories.
    @param folder: path to delete.
    @raise CuckooOperationalError: if fails to delete folder.
    """
    if path_exists(folder):
        try:
            shutil.rmtree(folder)
        except OSError as e:
            raise CuckooOperationalError(f"Unable to delete folder: {folder}") from e


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
        log.error("Can't connect to reporting db %s", str(e))
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
                try:
                    path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(id))
                    if path_is_dir(path):
                        delete_folder(path)
                except Exception as e:
                    log.error(e)
            db.delete_tasks(ids_tmp)
        else:
            # If we don't remove from mongo we should keep in db to be able to show task in webgui
            for id in ids_tmp:
                try:
                    path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(id))
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
    log.info("set %s job to failed", tid)

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
        log.info("removing %s from analysis db", tid)
        if repconf.mongodb.enabled:
            mongo_delete_data(tid)
        elif repconf.elasticsearchdb.enabled:
            delete_analysis_and_related_calls(tid)
    except Exception as e:
        log.exception("failed to remove analysis info (may not exist) %s due to %s", tid, e)
    with db.session.begin():
        if db.delete_task(tid):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", str(tid)))
        else:
            log.info("failed to remove faile task %s from DB", tid)


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
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(id))
            if path_exists(path):
                jsonlogs = glob(f"{path}/logs/*json*")
                bsondata = glob(f"{path}/logs/*.bson")
                filesmeta = glob(f"{path}/logs/files/*.meta")
                for f in jsonlogs, bsondata, filesmeta:
                    for fe in f:
                        try:
                            log.info("removing %s", fe)
                            path_delete(fe)
                        except Exception as Err:
                            log.info("failed to remove sorted_pcap from disk %s", Err)


def cuckoo_clean_failed_url_tasks():
    """Clean up failed tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for failed tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
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


def cuckoo_clean_lower_score(malscore: int):
    """Clean up tasks with score <= X
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.

    create_structure()
    id_arr = []
    if not is_reporting_db_connected():
        return

    if repconf.mongodb.enabled:
        result = list(mongo_find("analysis", {"malscore": {"$lte": malscore}}))
        id_arr = [entry["info"]["id"] for entry in result]
    elif repconf.elasticsearchdb.enabled:
        id_arr = [
            d["_source"]["info"]["id"]
            for d in all_docs(
                index=get_analysis_index(), query={"query": {"range": {"malscore": {"lte": malscore}}}}, _source=["info.id"]
            )
        ]
    log.info("number of matching records %s", len(id_arr))
    resolver_pool.map(lambda tid: delete_data(tid), id_arr)


def tmp_clean_before_day(days: int):
    """Clean up tmp folder
    It deletes all items in tmp folder before now - days.
    """

    today = datetime.today()
    tmp_folder_path = config.cuckoo.get("tmppath")

    for folder in ("cuckoo-tmp", "cape-external", "cuckoo-sflock"):
        for root, directories, files in os.walk(os.path.join(tmp_folder_path, folder), topdown=True):
            for name in files + directories:
                path = os.path.join(root, name)
                path_ctime = path_get_date(os.path.join(root, path))
                file_time = today - datetime.fromtimestamp(path_ctime)
                # ToDo add check for hours, as 1 day and 23h is still just 1 day
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


def cuckoo_clean_before_day(args: dict):
    """Clean up failed tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for tasks completed before now - days.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.

    create_structure()
    id_arr = []

    if not is_reporting_db_connected():
        return

    days = args.get("delete_older_than_days")
    if not days:
        log.info("No days argument provided bailing")
        return

    added_before = datetime.now() - timedelta(days=int(days))
    if args.get("files_only_filter"):
        log.info("file filter applied")
        old_tasks = db.list_tasks(added_before=added_before, category="file")
    elif args.get("urls_only_filter"):
        log.info("url filter applied")
        old_tasks = db.list_tasks(added_before=added_before, category="url")
    else:
        old_tasks = db.list_tasks(added_before=added_before)

    for e in old_tasks:
        id_arr.append({"info.id": (int(e.to_dict()["id"]))})

    log.info("number of matching records %s before suri/custom filter", len(id_arr))
    if id_arr and args.get("suricata_zero_alert_filter"):
        result = list(
            mongo_find("analysis", {"suricata.alerts.alert": {"$exists": False}, "$or": id_arr}, {"info.id": 1, "_id": 0})
        )
        id_arr = [entry["info"]["id"] for entry in result]
    if id_arr and args.get("custom_include_filter"):
        result = list(
            mongo_find(
                "analysis", {"info.custom": {"$regex": args.get("custom_include_filter")}, "$or": id_arr}, {"info.id": 1, "_id": 0}
            )
        )
        id_arr = [entry["info"]["id"] for entry in result]
    log.info("number of matching records %s", len(id_arr))
    delete_bulk_tasks_n_folders(id_arr, args.get("delete_mongo"))
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
                        log.info(("failed to remove sorted pcap from db for id %s", e["info"]["id"]))
                    try:
                        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(e["info"]["id"]), "dump_sorted.pcap")
                        path_delete(path)
                    except Exception as e:
                        log.info(("failed to remove sorted_pcap from disk %s", e))
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
    pending_tasks = db.list_tasks(id_after=start - 1, id_before=end + 1)
    resolver_pool.map(lambda tid: delete_data(tid.to_dict()["id"]), pending_tasks)


def delete_unused_file_data_in_mongo():
    """Cleans the entries in the 'files' collection that no longer have any analysis
    tasks associated with them.
    """
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

    if not is_reporting_db_connected():
        return

    tlp_tasks = db.get_tlp_tasks()
    resolver_pool.map(lambda tid: delete_data(tid), tlp_tasks)


def binaries_clean_before_day(days: int):
    # In case if "delete_bin_copy = off" we might need to clean binaries
    # find storage/binaries/ -name "*" -type f -mtime 5 -delete

    today = datetime.today()
    binaries_folder = os.path.join(CUCKOO_ROOT, "storage", "binaries")
    if not path_exists(binaries_folder):
        log.error("Binaries folder doesn't exist")
        return

    for _, _, filenames in os.walk(binaries_folder):
        for sha256 in filenames:
            bin_path = os.path.join(binaries_folder, sha256)
            if not os.path.exists(bin_path):
                continue
            st_ctime = path_get_date(bin_path)
            file_time = today - datetime.fromtimestamp(st_ctime)
            if file_time.days > days:
                # ToDo check database here to ensure that file is not used
                if path_exists(bin_path) and not db.sample_still_used(sha256, 0):
                    path_delete(bin_path)


def execute_cleanup(args: dict, init_log=True):
    if init_log:
        init_console_logging()

    if args.get("clean"):
        cuckoo_clean()

    if args.get("tlp"):
        cape_clean_tlp()

    if args.get("failed_clean"):
        cuckoo_clean_failed_tasks()

    if args.get("failed_url_clean"):
        cuckoo_clean_failed_url_tasks()

    if args.get("delete_older_than_days"):
        cuckoo_clean_before_day(args)

    if args.get("pcap_sorted_clean"):
        cuckoo_clean_sorted_pcap_dump()

    if args.get("bson_suri_logs_clean"):
        cuckoo_clean_bson_suri_logs()

    if args.get("pending_clean"):
        cuckoo_clean_pending_tasks(args["before_time"])

    if args.get("malscore"):
        cuckoo_clean_lower_score(args["malscore"])

    if args.get("delete_range_start") and args.get("delete_range_end"):
        cuckoo_clean_range_tasks(args["delete_range_start"], args["delete_range_end"])

    if args.get("deduplicated_cluster_queue"):
        cuckoo_dedup_cluster_queue()

    if args.get("delete_tmp_items_older_than_days"):
        tmp_clean_before_day(args["delete_tmp_items_older_than_days"])

    if args.get("delete_binaries_items_older_than_days"):
        binaries_clean_before_day(args["delete_binaries_items_older_than_days"])

    if args.get("delete_unused_file_data_in_mongo"):
        delete_unused_file_data_in_mongo()
