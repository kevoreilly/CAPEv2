# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import shutil
import copy
import socket
import logging
import logging.handlers

try:
    import yara
    if not int(yara.__version__[0]) >= 4:
        raise ImportError("Missed library: pip3 install yara-python>=4.0.0 -U")
except ImportError:
    print("Missed library: pip3 install yara-python>=4.0.0 -U")
import modules.auxiliary
import modules.processing
import modules.signatures
import modules.reporting
import modules.feeds

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.colors import red, green, yellow, cyan
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooStartupError
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.utils import create_folders, store_temp_file, delete_folder
from lib.cuckoo.core.database import Database, Task, TASK_RUNNING, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.plugins import import_plugin, import_package, list_plugins
from lib.cuckoo.core.rooter import rooter, vpns, socks5s

log = logging.getLogger()

cuckoo = Config()
routing = Config("routing")
repconf = Config("reporting")


def check_python_version():
    """Checks if Python version is supported by Cuckoo.
    @raise CuckooStartupError: if version is not supported.
    """
    if sys.version_info[:2] < (3, 5):
        raise CuckooStartupError("You are running an incompatible version " "of Python, please use >= 3.5")


def check_working_directory():
    """Checks if working directories are ready.
    @raise CuckooStartupError: if directories are not properly configured.
    """
    if not os.path.exists(CUCKOO_ROOT):
        raise CuckooStartupError("You specified a non-existing root " "directory: {0}".format(CUCKOO_ROOT))

    cwd = os.path.join(os.getcwd(), "cuckoo.py")
    if not os.path.exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's " "root directory")


def check_webgui_mongo():
    if repconf.mongodb.enabled:
        import pymongo

        bad = False
        try:
            conn = pymongo.MongoClient(
                repconf.mongodb.host,
                port=repconf.mongodb.port,
                username=repconf.mongodb.get("username", None),
                password=repconf.mongodb.get("password", None),
                authSource=repconf.mongodb.db,
            )
            conn.server_info()
        except pymongo.errors.ServerSelectionTimeoutError:
            log.warning("You have enabled webgui but mongo isn't working, see mongodb manual for correct installation and configuration")
            bad = True
        finally:
            conn.close()
            if bad:
                sys.exit(1)


def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = [
        os.path.join(CUCKOO_ROOT, "conf", "cuckoo.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "reporting.conf"),
        os.path.join(CUCKOO_ROOT, "conf", "auxiliary.conf"),
    ]

    for config in configs:
        if not os.path.exists(config):
            raise CuckooStartupError("Config file does not exist at " "path: {0}".format(config))

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
        days = cuckoo.logging.backup_count
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
            log.info("Rescheduled task with ID {0} and " "target {1}".format(task.id, task.target))
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
    if len(os.listdir(os.path.join(CUCKOO_ROOT, "modules", "signatures"))) < 5:
        log.warning("Suggestion: looks like you didn't install community, execute: python3 utils/community.py -h")
    # Import all reporting modules.
    import_package(modules.reporting)
    # Import all feeds modules.
    import_package(modules.feeds)

    # Import machine manager.
    import_plugin("modules.machinery." + cuckoo.cuckoo.machinery)

    for category, entries in list_plugins().items():
        log.debug('Imported "%s" modules:', category)

        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)


def init_yara():
    """Generates index for yara signatures."""

    categories = ("binaries", "urls", "memory", "CAPE", "macro", "monitor")

    log.debug("Initializing Yara...")

    # Generate root directory for yara rules.
    yara_root = os.path.join(CUCKOO_ROOT, "data", "yara")

    # Loop through all categories.
    for category in categories:
        # Check if there is a directory for the given category.
        category_root = os.path.join(yara_root, category)
        if not os.path.exists(category_root):
            log.warning("Missing Yara directory: %s?", category_root)
            continue

        rules, indexed = {}, []
        for category_root, _, filenames in os.walk(category_root, followlinks=True):
            for filename in filenames:
                if not filename.endswith((".yar", ".yara")):
                    continue

                filepath = os.path.join(category_root, filename)

                try:
                    # TODO Once Yara obtains proper Unicode filepath support we
                    # can remove this check. See also this Github issue:
                    # https://github.com/VirusTotal/yara-python/issues/48
                    assert len(str(filepath)) == len(filepath)
                except (UnicodeEncodeError, AssertionError):
                    log.warning("Can't load Yara rules at %r as Unicode filepaths are " "currently not supported in combination with Yara!", filepath)
                    continue

                rules["rule_%s_%d" % (category, len(rules))] = filepath
                indexed.append(filename)

            # Need to define each external variable that will be used in the
        # future. Otherwise Yara will complain.
        externals = {"filename": ""}

        while True:
            try:
                File.yara_rules[category] = yara.compile(filepaths=rules, externals=externals)
                break
            except yara.SyntaxError as e:
                bad_rule = str(e).split(".yar")[0]+".yar"
                if bad_rule in indexed:
                    for k,v in rules.items():
                        if v == bad_rule:
                            del rules[k]
                            indexed.remove(os.path.basename(bad_rule))
                            print("Deleted broken yara rule: {}".format(bad_rule))
                else:
                    break
            except yara.Error as e:
                print(e, sys.exc_info())
                log.error("There was a syntax error in one or more Yara rules: %s" % e)
                break

        if category == "memory":
            with open(os.path.join(yara_root, "index_memory.yar"), "w") as f:
                for filename in sorted(indexed):
                    f.write('include "%s"\n' % os.path.join(category_root, filename))

        indexed = sorted(indexed)
        for entry in indexed:
            if (category, entry) == indexed[-1]:
                log.debug("\t `-- %s %s", category, entry)
            else:
                log.debug("\t |-- %s %s", category, entry)

def init_rooter():
    """If required, check whether the rooter is running and whether we can
    connect to it."""

    # The default configuration doesn't require the rooter to be ran.
    if (
        not routing.vpn.enabled
        and not routing.tor.enabled
        and not routing.inetsim.enabled
        and not routing.socks5.enabled
        and routing.routing.route == "none"
    ):
        return

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        s.connect(cuckoo.cuckoo.rooter)
    except socket.error as e:
        if e.strerror == "No such file or directory":
            raise CuckooStartupError(
                "The rooter is required but it is either not running or it "
                "has been configured to a different Unix socket path. "
                "python3 utils/rooter.py -h or systemctl status cape-rooter"
            )

        if e.strerror == "Connection refused":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it as the "
                "rooter is not actually running. "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in routing.conf)."
            )

        if e.strerror == "Permission denied":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it due to "
                "incorrect permissions. Did you assign it the correct group? "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in routing.conf)."
            )

        raise CuckooStartupError("Unknown rooter error: %s" % e)

    rooter("cleanup_rooter")

    # Do not forward any packets unless we have explicitly stated so.
    rooter("forward_drop")
    rooter("state_disable")
    rooter("state_enable")


def init_routing():
    """Initialize and check whether the routing information is correct."""

    # Check whether all VPNs exist if configured and make their configuration
    # available through the vpns variable. Also enable NAT on each interface.

    if routing.socks5.enabled:
        for name in routing.socks5.proxies.split(","):
            name = name.strip()
            if not name:
                continue

            if not hasattr(routing, name):
                raise CuckooStartupError("Could not find socks5 configuration for %s" % name)

            entry = routing.get(name)
            socks5s[entry.name] = entry

    if routing.vpn.enabled:
        for name in routing.vpn.vpns.split(","):
            name = name.strip()
            if not name:
                continue

            if not hasattr(routing, name):
                raise CuckooStartupError("Could not find VPN configuration for %s" % name)

            entry = routing.get(name)
            # add = 1
            # if not rooter("nic_available", entry.interface):
            # raise CuckooStartupError(
            #   "The network interface that has been configured for "
            #    "VPN %s is not available." % entry.name
            # )
            #    add = 0
            if not rooter("rt_available", entry.rt_table):
                raise CuckooStartupError("The routing table that has been configured for VPN %s is not available." % entry.name)
            vpns[entry.name] = entry

            # Disable & enable NAT on this network interface. Disable it just
            # in case we still had the same rule from a previous run.
            rooter("disable_nat", entry.interface)
            rooter("enable_nat", entry.interface)

            # Populate routing table with entries from main routing table.
            if routing.routing.auto_rt:
                rooter("flush_rttable", entry.rt_table)
                rooter("init_rttable", entry.rt_table, entry.interface)

    # Check whether the default VPN exists if specified.
    if routing.routing.route not in ("none", "internet", "tor", "inetsim"):
        if not routing.vpn.enabled:
            raise CuckooStartupError("A VPN has been configured as default routing interface for VMs, but VPNs have not been enabled in vpn.conf")

        if routing.routing.route not in vpns and routing.routing.route not in socks5s:
            raise CuckooStartupError("The VPN/Socks5 defined as default routing target has not been configured in routing.conf. You should use name field")

    # Check whether the dirty line exists if it has been defined.
    if routing.routing.internet != "none":
        if not rooter("nic_available", routing.routing.internet):
            raise CuckooStartupError("The network interface that has been configured as dirty line is not available.")

        if not rooter("rt_available", routing.routing.rt_table):
            raise CuckooStartupError("The routing table that has been configured for dirty line interface is not available.")

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", routing.routing.internet)
        rooter("enable_nat", routing.routing.internet)

        # Populate routing table with entries from main routing table.
        if routing.routing.auto_rt:
            rooter("flush_rttable", routing.routing.rt_table)
            rooter("init_rttable", routing.routing.rt_table, routing.routing.internet)

    # Check if tor interface exists, if yes then enable nat
    if routing.tor.enabled and routing.tor.interface:
        if not rooter("nic_available", routing.tor.interface):
            raise CuckooStartupError("The network interface that has been configured as tor " "line is not available.")

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", routing.tor.interface)
        rooter("enable_nat", routing.tor.interface)

        # Populate routing table with entries from main routing table.
        if routing.routing.auto_rt:
            rooter("flush_rttable", routing.routing.rt_table)
            rooter("init_rttable", routing.routing.rt_table, routing.routing.internet)

    # Check if inetsim interface exists, if yes then enable nat, if interface is not the same as tor
    # if routing.inetsim.interface and cuckoo.routing.inetsim_interface !=  routing.tor.interface:
    # Check if inetsim interface exists, if yes then enable nat
    if routing.inetsim.enabled and routing.inetsim.interface:
        if not rooter("nic_available", routing.inetsim.interface):
            raise CuckooStartupError("The network interface that has been configured as inetsim " "line is not available.")

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", routing.inetsim.interface)
        rooter("enable_nat", routing.inetsim.interface)

        # Populate routing table with entries from main routing table.
        if routing.routing.auto_rt:
            rooter("flush_rttable", routing.routing.rt_table)
            rooter("init_rttable", routing.routing.rt_table, routing.routing.internet)
