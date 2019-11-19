# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import shutil
import sys
import copy
import logging
import logging.handlers
from datetime import datetime

import modules.auxiliary
import modules.processing
import modules.signatures
import modules.reporting
import modules.feeds

from lib.cuckoo.common.colors import red, green, yellow, cyan
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooStartupError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.utils import create_folders, store_temp_file, delete_folder
from lib.cuckoo.core.database import Database, Task, TASK_RUNNING, TASK_PENDING, TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING, TASK_RECOVERED, TASK_REPORTED
from lib.cuckoo.core.plugins import import_plugin, import_package, list_plugins
import socket
from lib.cuckoo.core.rooter import rooter, vpns, socks5s

log = logging.getLogger()

cuckoo = Config()
vpn = Config("vpn")

rep_config = Config("reporting")

def check_python_version():
    """Checks if Python version is supported by Cuckoo.
    @raise CuckooStartupError: if version is not supported.
    """
    if sys.version_info[:2] != (2, 7):
        raise CuckooStartupError("You are running an incompatible version "
                                 "of Python, please use 2.7")


def check_working_directory():
    """Checks if working directories are ready.
    @raise CuckooStartupError: if directories are not properly configured.
    """
    if not os.path.exists(CUCKOO_ROOT):
        raise CuckooStartupError("You specified a non-existing root "
                                 "directory: {0}".format(CUCKOO_ROOT))

    cwd = os.path.join(os.getcwd(), "cuckoo.py")
    if not os.path.exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's "
                                 "root directory")


def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = [os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"),
               os.path.join(CUCKOO_ROOT, "conf", "reporting.conf"),
               os.path.join(CUCKOO_ROOT, "conf", "auxiliary.conf")]

    for config in configs:
        if not os.path.exists(config):
            raise CuckooStartupError("Config file does not exist at "
                                     "path: {0}".format(config))

    return True


def create_structure():
    """Creates Cuckoo directories."""
    folders = [
        "log",
        "storage",
        os.path.join("storage", "analyses"),
        os.path.join("storage", "binaries"),
        os.path.join("data", "feeds"),
    ]

    try:
        create_folders(root=CUCKOO_ROOT, folders=folders)
    except CuckooOperationalError as e:
        raise CuckooStartupError(e)

class DatabaseHandler(logging.Handler):
    """Logging to database handler.
    Used to log errors related to tasks in database.
    """

    def emit(self, record):
        if hasattr(record, "task_id"):
            db = Database()
            db.add_error(record.msg, int(record.task_id))

class ConsoleHandler(logging.StreamHandler):
    """Logging to console handler."""

    def emit(self, record):
        colored = copy.copy(record)

        if record.levelname == "WARNING":
            colored.msg = yellow(record.msg)
        elif record.levelname == "ERROR" or record.levelname == "CRITICAL":
            colored.msg = red(record.msg)
        else:
            if "analysis procedure completed" in record.msg:
                colored.msg = cyan(record.msg)
            else:
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)

def init_logging():
    """Initializes logging."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    if cuckoo.logging.enabled:
        days = cuckoo.logging.backupCount
        fh = logging.handlers.TimedRotatingFileHandler(os.path.join(CUCKOO_ROOT, "log", "cuckoo.log"), when="midnight", backupCount=days)
    else:
        fh = logging.handlers.WatchedFileHandler(os.path.join(CUCKOO_ROOT, "log", "cuckoo.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    dh = DatabaseHandler()
    dh.setLevel(logging.ERROR)
    log.addHandler(dh)

    log.setLevel(logging.INFO)

    logging.getLogger("urllib3").setLevel(logging.WARNING)

def init_console_logging():
    """Initializes logging only to console."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    ch = ConsoleHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    log.setLevel(logging.INFO)

def init_tasks():
    """Check tasks and reschedule uncompleted ones."""
    db = Database()

    log.debug("Checking for locked tasks...")
    tasks = db.list_tasks(status=TASK_RUNNING)

    for task in tasks:
        if cuckoo.cuckoo.reschedule:
            db.reschedule(task.id)
            log.info("Rescheduled task with ID {0} and "
                     "target {1}".format(task.id, task.target))
        else:
            db.set_status(task.id, TASK_FAILED_ANALYSIS)
            log.info("Updated running task ID {0} status to failed_analysis".format(task.id))

def init_modules():
    """Initializes plugins."""
    log.debug("Importing modules...")

    # Import all auxiliary modules.
    import_package(modules.auxiliary)
    # Import all processing modules.
    import_package(modules.processing)
    # Import all signatures.
    import_package(modules.signatures)
    # Import all reporting modules.
    import_package(modules.reporting)
    # Import all feeds modules.
    import_package(modules.feeds)

    # Import machine manager.
    import_plugin("modules.machinery." + cuckoo.cuckoo.machinery)

    for category, entries in list_plugins().items():
        log.debug("Imported \"%s\" modules:", category)

        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)

def init_yara():
    """Generates index for yara signatures."""

    def find_signatures(root):
        signatures = []
        for entry in os.listdir(root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(root, entry))

        return signatures

    log.debug("Initializing Yara...")

    # Generate root directory for yara rules.
    yara_root = os.path.join(CUCKOO_ROOT, "data", "yara")

    # We divide yara rules in three categories.
    # CAPE adds a fourth
    categories = ["binaries", "urls", "memory", "CAPE"]
    generated = []
    # Loop through all categories.
    for category in categories:
        # Check if there is a directory for the given category.
        category_root = os.path.join(yara_root, category)
        if not os.path.exists(category_root):
            continue

        # Check if the directory contains any rules.
        signatures = []
        for entry in os.listdir(category_root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(category_root, entry))

        if not signatures:
            continue

        # Generate path for the category's index file.
        index_name = "index_{0}.yar".format(category)
        index_path = os.path.join(yara_root, index_name)

        # Create index file and populate it.
        with open(index_path, "w") as index_handle:
            for signature in signatures:
                index_handle.write("include \"{0}\"\n".format(signature))

        generated.append(index_name)

    for entry in generated:
        if entry == generated[-1]:
            log.debug("\t `-- %s", entry)
        else:
            log.debug("\t |-- %s", entry)



def connect_to_mongo():
    conn = False
    mdb = ""
    # Check if MongoDB reporting is enabled and drop that if it is.
    if rep_config.mongodb and rep_config.mongodb.enabled:
        from pymongo import MongoClient
        host = rep_config.mongodb.get("host", "127.0.0.1")
        port = rep_config.mongodb.get("port", 27017)
        mdb = rep_config.mongodb.get("db", "cuckoo")
        user = rep_config.mongodb.get("username", None)
        password = rep_config.mongodb.get("password", None)
        try:
            conn = MongoClient(
                host=host,
                port=port,
                username=user,
                password=password,
                authSource=mdb
            )
        except Exception as e:
            log.warning("Unable to connect to MongoDB database: {}, {}".format(mdb, e))

    return conn, mdb

def connect_to_es():
    es = None
    delidx = None
    # Check if ElasticSearch is enabled and delete that data if it is.
    from elasticsearch import Elasticsearch
    delidx = rep_config.elasticsearchdb.index + "-*"
    try:
        es = Elasticsearch(
                    hosts = [{
                        "host": rep_config.elasticsearchdb.host,
                        "port": rep_config.elasticsearchdb.port,
                    }],
                    timeout = 60
                )
    except:
        log.warning("Unable to connect to ElasticSearch")

    return es, delidx

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

    # Initialize the database connection.
    db = Database()

    # Drop all tables.
    db.drop()

    conn, mdb = connect_to_mongo()
    if not conn:
        print("Can't connect to mongo")
        return
    try:
        conn.drop_database(mdb)
        conn.close()
    except:
        log.warning("Unable to drop MongoDB database: %s", mdb)

    if rep_config.elasticsearchdb and rep_config.elasticsearchdb.enabled and not rep_config.elasticsearchdb.searchonly:
        es = False
        es, delidx = connect_to_es()
        if not es:
            return
        analyses = es.search(
            index=delidx,
            doc_type="analysis",
            q="*"
            )["hits"]["hits"]
        if analyses:
            for analysis in analyses:
                esidx = analysis["_index"]
                esid = analysis["_id"]
                # Check if behavior exists
                if analysis["_source"]["behavior"]:
                    for process in analysis["_source"]["behavior"]["processes"]:
                        for call in process["calls"]:
                            es.delete(
                                index=esidx,
                                doc_type="calls",
                                id=call,
                            )
                # Delete the analysis results
                es.delete(
                    index=esidx,
                    doc_type="analysis",
                    id=esid,
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

    # Initialize the database connection.
    db = Database()

    results_db, mdb = connect_to_mongo()

    failed_tasks_a = db.list_tasks(status=TASK_FAILED_ANALYSIS)
    failed_tasks_p = db.list_tasks(status=TASK_FAILED_PROCESSING)
    failed_tasks_r = db.list_tasks(status=TASK_FAILED_REPORTING)
    failed_tasks_rc = db.list_tasks(status=TASK_RECOVERED)
    for e in failed_tasks_a, failed_tasks_p, failed_tasks_r, failed_tasks_rc:
        for el2 in e:
            new = el2.to_dict()
            print((int(new["id"])))
            try:
                results_db.analysis.remove({"info.id": int(new["id"])})
            except:
                print(("failed to remove analysis info (may not exist) %s" % (int(new["id"]))))
            if db.delete_task(new["id"]):
                delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % int(new["id"])))
            else:
                print(("failed to remove failed task %s from DB" % (int(new["id"]))))

def cuckoo_clean_bson_suri_logs():
    """Clean up raw suri log files probably not needed if storing in mongo. Does not remove extracted files
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    init_console_logging()
    from glob import glob
    # Initialize the database connection.
    db = Database()
    failed_tasks_a = db.list_tasks(status=TASK_FAILED_ANALYSIS)
    failed_tasks_p = db.list_tasks(status=TASK_FAILED_PROCESSING)
    failed_tasks_r = db.list_tasks(status=TASK_FAILED_REPORTING)
    failed_tasks_rc = db.list_tasks(status=TASK_RECOVERED)
    tasks_rp = db.list_tasks(status=TASK_REPORTED)
    for e in failed_tasks_a,failed_tasks_p,failed_tasks_r,failed_tasks_rc,tasks_rp:
        for el2 in e:
            new = el2.to_dict()
            id = new["id"]
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % id)
            if os.path.exists(path):
                jsonlogs=glob("%s/logs/*json*" % (path))
                bsondata=glob("%s/logs/*.bson" % (path))
                filesmeta=glob("%s/logs/files/*.meta" % (path))
                for f in jsonlogs, bsondata, filesmeta:
                    for fe in f:
                        try:
                            print(("removing %s" % (fe)))
                            os.remove(fe)
                        except Exception as Err:
                            print(("failed to remove sorted_pcap from disk %s" % (Err)))

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

    # Initialize the database connection.
    db = Database()

    results_db, mdb = connect_to_mongo()
    if not results_db:
        log.info("Can't connect to mongo")
        return

    done = False
    while not done:
        rtmp = results_db.analysis.find({"info.category": "url", "network.http.0": {"$exists": False}},{"info.id": 1},sort=[("_id", -1)]).limit( 100 )
        if rtmp and rtmp.count() > 0:
            for e in rtmp:
                if e["info"]["id"]:
                    print((e["info"]["id"]))
                    if db.delete_task(e["info"]["id"]):
                        delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                    "%s" % e["info"]["id"]))
                    else:
                        print(("failed to remove %s" % (e["info"]["id"])))
                    try:
                        results_db.analysis.remove({"info.id": int(e["info"]["id"])})
                    except:
                        print(("failed to remove %s" % (e["info"]["id"])))
                else:
                    done = True
        else:
            done = True

def cuckoo_clean_before_day(args):
    """Clean up failed tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for tasks completed before now - days.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    if not args.delete_older_than_days:
        print("No days argument provided bailing")
        return
    else:
        days = args.delete_older_than_days
    create_structure()
    init_console_logging()
    id_arr = []

    # Initialize the database connection.
    db = Database()

    results_db, mdb = connect_to_mongo()
    if not results_db:
        log.info("Can't connect to mongo")
        return

    added_before = datetime.now() - timedelta(days=int(days))
    if args.files_only_filter:
        print("file filter applied")
        old_tasks = db.list_tasks(added_before=added_before,category="file")
    elif args.urls_only_filter:
        print("url filter applied")
        old_tasks = db.list_tasks(added_before=added_before,category="url")
    else:
        old_tasks = db.list_tasks(added_before=added_before)

    for e in old_tasks:
        new = e.to_dict()
        print((int(new["id"])))
        id_arr.append({"info.id": (int(new["id"]))})

    print(("number of matching records %s before suri/custom filter " % len(id_arr)))
    if id_arr and args.suricata_zero_alert_filter:
        result = list(results_db.analysis.find({"suricata.alerts.alert": {"$exists": False}, "$or": id_arr},{"info.id":1}))
        tmp_arr = []
        for entry in result:
            tmp_arr.append(entry["info"]["id"])
        id_arr = tmp_arr
    if id_arr and args.custom_include_filter:
        result = list(results_db.analysis.find({"info.custom": {"$regex": args.custom_include_filter},"$or": id_arr},{"info.id":1}))
        tmp_arr = []
        for entry in result:
            tmp_arr.append(entry["info"]["id"])
        id_arr = tmp_arr
    print(("number of matching records %s" % len(id_arr)))
    for e in id_arr:
        try:
            print(("removing %s from analysis db" % (e)))
            results_db.analysis.remove({"info.id": e})
        except:
            print(("failed to remove analysis info (may not exist) %s" % (e)))
        if db.delete_task(e):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % e))
        else:
            print(("failed to remove faile task %s from DB" % (e)))

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

    results_db, mdb = connect_to_mongo()
    if not results_db:
        log.info("Can't connect to mongo")
        return

    done = False
    while not done:
        rtmp = results_db.analysis.find({"network.sorted_pcap_id": {"$exists": True}},{"info.id": 1},sort=[("_id", -1)]).limit( 100 )
        if rtmp and rtmp.count() > 0:
            for e in rtmp:
                if e["info"]["id"]:
                    print((e["info"]["id"]))
                    try:
                        results_db.analysis.update({"info.id": int(e["info"]["id"])},{ "$unset": { "network.sorted_pcap_id": ""}})
                    except:
                        print(("failed to remove sorted pcap from db for id %s" % (e["info"]["id"])))
                    try:
                        path = os.path.join(CUCKOO_ROOT, "storage", "analyses","%s" % (e["info"]["id"]), "dump_sorted.pcap")
                        os.remove(path)
                    except Exception as e:
                        print(("failed to remove sorted_pcap from disk %s" % (e)))
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

    # Initialize the database connection.
    db = Database()

    results_db, mdb = connect_to_mongo()
    if not results_db:
        log.info("Can't connect to mongo")
        return

    pending_tasks = db.list_tasks(status=TASK_PENDING)
    for e in pending_tasks:
        new = e.to_dict()
        print((int(new["id"])))
        try:
            results_db.analysis.remove({"info.id": int(new["id"])})
        except:
            print(("failed to remove analysis info (may not exist) %s" % (int(new["id"]))))
        if db.delete_task(new["id"]):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % int(new["id"])))
        else:
            print(("failed to remove pending task %s from DB" % (int(new["id"]))))

def init_rooter():
    """If required, check whether the rooter is running and whether we can
    connect to it."""

    # The default configuration doesn't require the rooter to be ran.
    if not vpn.vpn.enabled and cuckoo.routing.route == "none":
        return

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        s.connect(cuckoo.cuckoo.rooter)
    except socket.error as e:
        if e.strerror == "No such file or directory":
            raise CuckooStartupError(
                "The rooter is required but it is either not running or it "
                "has been configured to a different Unix socket path. "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in cuckoo.conf and enabled to no in "
                "vpn.conf)."
            )

        if e.strerror == "Connection refused":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it as the "
                "rooter is not actually running. "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in cuckoo.conf and enabled to no in "
                "vpn.conf)."
            )

        if e.strerror == "Permission denied":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it due to "
                "incorrect permissions. Did you assign it the correct group? "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in cuckoo.conf and enabled to no in "
                "vpn.conf)."
            )

        raise CuckooStartupError("Unknown rooter error: %s" % e)

    # Do not forward any packets unless we have explicitly stated so.
    rooter("forward_drop")

def init_routing():
    """Initialize and check whether the routing information is correct."""

    # Check whether all VPNs exist if configured and make their configuration
    # available through the vpns variable. Also enable NAT on each interface.
    if vpn.vpn.enabled:
        for name in vpn.vpn.vpns.split(","):
            name = name.strip()
            if not name:
                continue

            if not hasattr(vpn, name):
                raise CuckooStartupError(
                    "Could not find VPN configuration for %s" % name
                )

            entry = vpn.get(name)
            #add = 1
            #if not rooter("nic_available", entry.interface):
                #raise CuckooStartupError(
                #   "The network interface that has been configured for "
                #    "VPN %s is not available." % entry.name
                #)
            #    add = 0
            if not rooter("rt_available", entry.rt_table):
                raise CuckooStartupError(
                    "The routing table that has been configured for "
                    "VPN %s is not available." % entry.name
                )
            vpns[entry.name] = entry

            # Disable & enable NAT on this network interface. Disable it just
            # in case we still had the same rule from a previous run.
            rooter("disable_nat", entry.interface)
            rooter("enable_nat", entry.interface)

            # Populate routing table with entries from main routing table.
            if cuckoo.routing.auto_rt:
                rooter("flush_rttable", entry.rt_table)
                rooter("init_rttable", entry.rt_table, entry.interface)

    # Check whether the default VPN exists if specified.
    if cuckoo.routing.route not in ("none", "internet", "tor", "inetsim"):
        if not vpn.vpn.enabled:
            raise CuckooStartupError(
                "A VPN has been configured as default routing interface for "
                "VMs, but VPNs have not been enabled in vpn.conf"
            )

        if cuckoo.routing.route not in vpns:
            raise CuckooStartupError(
                "The VPN defined as default routing target has not been "
                "configured in vpn.conf."
            )

    # Check whether the dirty line exists if it has been defined.
    if cuckoo.routing.internet != "none":
        if not rooter("nic_available", cuckoo.routing.internet):
            raise CuckooStartupError(
                "The network interface that has been configured as dirty "
                "line is not available."
            )

        if not rooter("rt_available", cuckoo.routing.rt_table):
            raise CuckooStartupError(
                "The routing table that has been configured for dirty "
                "line interface is not available."
            )

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", cuckoo.routing.internet)
        rooter("enable_nat", cuckoo.routing.internet)

        # Populate routing table with entries from main routing table.
        if cuckoo.routing.auto_rt:
            rooter("flush_rttable", cuckoo.routing.rt_table)
            rooter("init_rttable", cuckoo.routing.rt_table,
                   cuckoo.routing.internet)

    # Check if tor interface exists, if yes then enable nat
    if cuckoo.routing.tor and cuckoo.routing.tor_interface:
        if not rooter("nic_available", cuckoo.routing.tor_interface):
            raise CuckooStartupError(
                "The network interface that has been configured as tor "
                "line is not available."
            )

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", cuckoo.routing.tor_interface)
        rooter("enable_nat", cuckoo.routing.tor_interface)

        # Populate routing table with entries from main routing table.
        if cuckoo.routing.auto_rt:
            rooter("flush_rttable", cuckoo.routing.rt_table)
            rooter("init_rttable", cuckoo.routing.rt_table,
                   cuckoo.routing.internet)


    # Check if inetsim interface exists, if yes then enable nat, if interface is not the same as tor
    #if cuckoo.routing.inetsim_interface and cuckoo.routing.inetsim_interface !=  cuckoo.routing.tor_interface:
    # Check if inetsim interface exists, if yes then enable nat
    if cuckoo.routing.inetsim and cuckoo.routing.inetsim_interface:
        if not rooter("nic_available", cuckoo.routing.inetsim_interface):
            raise CuckooStartupError(
                "The network interface that has been configured as inetsim "
                "line is not available."
            )

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", cuckoo.routing.inetsim_interface)
        rooter("enable_nat", cuckoo.routing.inetsim_interface)

        # Populate routing table with entries from main routing table.
        if cuckoo.routing.auto_rt:
            rooter("flush_rttable", cuckoo.routing.rt_table)
            rooter("init_rttable", cuckoo.routing.rt_table,
                   cuckoo.routing.internet)
