# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import getpass as gt
import grp
import logging
import logging.handlers
import os
import platform
import socket
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

# Private
import custom.signatures
import modules.auxiliary
import modules.feeds
import modules.processing
import modules.reporting
import modules.signatures
from lib.cuckoo.common.colors import cyan, red, yellow
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError, CuckooStartupError
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import create_folders
from lib.cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_RUNNING, Database
from lib.cuckoo.core.log import init_logger
from lib.cuckoo.core.plugins import import_package, import_plugin, list_plugins
from lib.cuckoo.core.rooter import rooter, socks5s, vpns

log = logging.getLogger()

cuckoo = Config()
logconf = Config("logging")
routing = Config("routing")
repconf = Config("reporting")
auxconf = Config("auxiliary")
dist_conf = Config("distributed")


def check_python_version():
    """Checks if Python version is supported by Cuckoo.
    @raise CuckooStartupError: if version is not supported.
    """
    if sys.version_info[:2] < (3, 8):
        raise CuckooStartupError("You are running an incompatible version of Python, please use >= 3.8")


def check_user_permissions(as_root: bool = False):
    if as_root:
        log.warning("You running part of CAPE as non 'cape' user! That breaks permissions on temp folder and log folder.")
        return
    if gt.getuser() != cuckoo.cuckoo.get("username", "cape"):
        raise CuckooStartupError(
            f"Running as not 'cape' user breaks permissions! Run with cape user! Current user: {gt.getuser()} - Cape config user: {cuckoo.cuckoo.get('username', 'cape')}. Also fix permission on tmppath path: chown cape:cape {cuckoo.cuckoo.tmppath}\n log folder: chown cape:cape {os.path.join(CUCKOO_ROOT, 'logs')}"
        )

    # Check permission for tmp folder
    if cuckoo.cuckoo.tmppath and not os.access(cuckoo.cuckoo.tmppath, os.W_OK):
        raise CuckooStartupError(
            f"Fix permission on\n tmppath path: chown cape:cape {cuckoo.cuckoo.tmppath}\n log folder: chown cape:cape {os.path.join(CUCKOO_ROOT, 'logs')}"
        )


def check_working_directory():
    """Checks if working directories are ready.
    @raise CuckooStartupError: if directories are not properly configured.
    """
    if not path_exists(CUCKOO_ROOT):
        raise CuckooStartupError(f"You specified a non-existing root directory: {CUCKOO_ROOT}")

    cwd = Path.cwd() / "cuckoo.py"
    if not path_exists(cwd):
        raise CuckooStartupError("You are not running Cuckoo from it's root directory")

    # Check permission for tmpfs if enabled
    if cuckoo.tmpfs.enabled and not os.access(cuckoo.tmpfs.path, os.W_OK):
        raise CuckooStartupError(f"Fix permission on tmpfs path: chown cape:cape {cuckoo.tmpfs.path}")


def check_webgui_mongo():
    if repconf.mongodb.enabled:
        from dev_utils.mongodb import connect_to_mongo, mongo_create_index

        client = connect_to_mongo()
        if not client:
            sys.exit(
                "You have enabled webgui but mongo isn't working, see mongodb manual for correct installation and configuration\nrun `systemctl status mongodb` for more info"
            )

        # Create an index based on the info.id dict key. Increases overall scalability
        # with large amounts of data.
        # Note: Silently ignores the creation if the index already exists.
        mongo_create_index("analysis", "info.id", name="info.id_1")
        # mongo_create_index([("target.file.sha256", TEXT)], name="target_sha256")
        # We performs a lot of SHA256 hash lookup so we need this index
        # mongo_create_index(
        #     "analysis",
        #     [("target.file.sha256", TEXT), ("dropped.sha256", TEXT), ("procdump.sha256", TEXT), ("CAPE.payloads.sha256", TEXT)],
        #     name="ALL_SHA256",
        # )
        mongo_create_index("files", [("_task_ids", 1)])

    elif repconf.elasticsearchdb.enabled:
        # ToDo add check
        pass


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
        if not path_exists(config):
            raise CuckooStartupError(f"Config file does not exist at path: {config}")

    if cuckoo.resultserver.ip in ("127.0.0.1", "localhost"):
        log.error("Bad resultserver address. You need to listen on virtual machines range. Ex: 10.0.0.1 not 127.0.0.1")

    return True


def create_structure():
    """Creates Cuckoo directories."""
    folders = [
        "log",
        "storage",
        os.path.join("storage", "analyses"),
        os.path.join("storage", "binaries"),
        os.path.join("data", "feeds"),
        os.path.join("storage", "guacrecordings"),
    ]

    try:
        create_folders(root=CUCKOO_ROOT, folders=folders)
    except CuckooOperationalError as e:
        raise CuckooStartupError(
            "Can't create folders. Ensure that you executed CAPE with proper USER! Maybe should be cape user?. %s", str(e)
        )


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
        elif record.levelname in ("ERROR", "CRITICAL"):
            colored.msg = red(record.msg)
        else:
            if "analysis procedure completed" in record.msg:
                colored.msg = cyan(record.msg)
            else:
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)


def check_linux_dist():
    ubuntu_versions = ("20.04", "22.04")
    with suppress(AttributeError):
        platform_details = platform.dist()
        if platform_details[0] != "Ubuntu" and platform_details[1] not in ubuntu_versions:
            log.info(
                f"[!] You are using NOT supported Linux distribution by devs! Any issue report is invalid! We only support Ubuntu LTS {ubuntu_versions}"
            )


def init_logging(level: int):
    """Initializes logging.
    @param level: The logging level for the console logs
    """

    # Pyattck creates root logger which we don't want. So we must use this dirty hack to remove it
    # If basicConfig was already called by something and had a StreamHandler added,
    # replace it with a ConsoleHandler.
    for h in log.handlers[:]:
        if isinstance(h, logging.StreamHandler) and h.stream == sys.stderr:
            log.removeHandler(h)
            h.close()

    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    init_logger("console", level)
    init_logger("database")

    if logconf.logger.syslog_cape:
        fh = logging.handlers.SysLogHandler(address=logconf.logger.syslog_dev)
        fh.setFormatter(formatter)
        log.addHandler(fh)

    path = os.path.join(CUCKOO_ROOT, "log", "cuckoo.log")
    if logconf.log_rotation.enabled:
        days = logconf.log_rotation.backup_count or 7
        fh = logging.handlers.TimedRotatingFileHandler(path, when="midnight", backupCount=int(days))
    else:
        fh = logging.handlers.WatchedFileHandler(path)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    init_logger("task")

    logging.getLogger("urllib3").setLevel(logging.WARNING)


def init_console_logging():
    """Initializes logging only to console."""
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    # Pyattck creates root logger which we don't want. So we must use this dirty hack to remove it
    # If basicConfig was already called by something and had a StreamHandler added,
    # replace it with a ConsoleHandler.
    for h in log.handlers[:]:
        if isinstance(h, logging.StreamHandler) and h.stream == sys.stderr:
            log.removeHandler(h)
            h.close()

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
            log.info("Rescheduled task with ID %s and target %s", task.id, task.target)
        else:
            # ToDo here?
            db.set_status(task.id, TASK_FAILED_ANALYSIS)
            log.info("Updated running task ID %s status to failed_analysis", task.id)


def init_modules():
    """Initializes plugins."""
    log.debug("Importing modules...")

    # Import all auxiliary modules.
    import_package(modules.auxiliary)
    # Import all processing modules.
    import_package(modules.processing)
    # Import all signatures.
    import_package(modules.signatures)
    # Import all private signatures
    import_package(custom.signatures)
    if len(os.listdir(os.path.join(CUCKOO_ROOT, "modules", "signatures"))) < 5:
        log.warning("Suggestion: looks like you didn't install community, execute: poetry run python utils/community.py -h")
    # Import all reporting modules.
    import_package(modules.reporting)
    # Import all feeds modules.
    import_package(modules.feeds)

    # Import machine manager.
    import_plugin(f"modules.machinery.{cuckoo.cuckoo.machinery}")

    for category, entries in list_plugins().items():
        log.debug('Imported "%s" modules:', category)

        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)


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
                "poetry run python utils/rooter.py -h or systemctl status cape-rooter"
            )

        if e.strerror == "Connection refused":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it as the "
                "rooter is not actually running. "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in routing.conf)"
            )

        if e.strerror == "Permission denied":
            extra_msg = ""
            if gt.getuser() != cuckoo.cuckoo.get("username", "cape"):
                extra_msg = 'You have executed this process with WRONG user! Run with "cape" user\n'

            raise CuckooStartupError(
                f"{extra_msg} "
                "The rooter is required but we can't connect to it due to "
                "incorrect permissions. Did you assign it the correct group? "
                "(In order to disable the use of rooter, please set route "
                "and internet to none in routing.conf)"
            )

        raise CuckooStartupError(f"Unknown rooter error: {e}")

    rooter("cleanup_rooter")

    # Do not forward any packets unless we have explicitly stated so.
    rooter("forward_drop")
    rooter("state_disable")
    rooter("state_enable")

    # ToDo check if ip_forward is on


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
                raise CuckooStartupError(f"Could not find socks5 configuration for {name}")

            entry = routing.get(name)
            socks5s[entry.name] = entry

    if routing.vpn.enabled:
        for name in routing.vpn.vpns.split(","):
            name = name.strip()
            if not name:
                continue

            if not hasattr(routing, name):
                raise CuckooStartupError(f"Could not find VPN configuration for {name}")

            entry = routing.get(name)
            if routing.routing.verify_rt_table:
                is_rt_available = rooter("rt_available", entry.rt_table)["output"]
                if not is_rt_available:
                    raise CuckooStartupError(f"The routing table that has been configured for VPN {entry.name} is not available")
            vpns[entry.name] = entry

            # Disable & enable NAT on this network interface. Disable it just
            # in case we still had the same rule from a previous run.
            rooter("disable_nat", entry.interface)
            rooter("enable_nat", entry.interface)

            # Populate routing table with entries from main routing table.
            if routing.routing.auto_rt:
                rooter("flush_rttable", entry.rt_table)
                rooter("init_rttable", entry.rt_table, entry.interface)

    # If we are storage and webgui only but using as default route one of the workers exitnodes
    if dist_conf.distributed.master_storage_only:
        return

    # Check whether the default VPN exists if specified.
    if routing.routing.route not in ("none", "internet", "tor", "inetsim"):
        if not routing.vpn.enabled:
            raise CuckooStartupError(
                "A VPN has been configured as default routing interface for VMs, but VPNs have not been enabled in routing.conf"
            )

        if routing.routing.route not in vpns and routing.routing.route not in socks5s:
            raise CuckooStartupError(
                "The VPN/Socks5 defined as default routing target has not been configured in routing.conf. You should use name field"
            )

    # Check whether the dirty line exists if it has been defined.
    if routing.routing.internet != "none":
        is_nic_available = rooter("nic_available", routing.routing.internet)["output"]
        if not is_nic_available:
            raise CuckooStartupError("The network interface that has been configured as dirty line is not available")

        if routing.routing.verify_rt_table:
            is_rt_available = rooter("rt_available", routing.routing.rt_table)["output"]
            if not is_rt_available:
                raise CuckooStartupError(
                    f"The routing table that has been configured ({routing.routing.rt_table}) for dirty line interface is not available"
                )

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
        is_nic_available = rooter("nic_available", routing.tor.interface)["output"]
        if not is_nic_available:
            raise CuckooStartupError("The network interface that has been configured as tor line is not available")

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
        is_nic_available = rooter("nic_available", routing.inetsim.interface)["output"]
        if not is_nic_available:
            raise CuckooStartupError("The network interface that has been configured as inetsim line is not available")

        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", routing.inetsim.interface)
        rooter("enable_nat", routing.inetsim.interface)

        # Populate routing table with entries from main routing table.
        if routing.routing.auto_rt:
            rooter("flush_rttable", routing.routing.rt_table)
            rooter("init_rttable", routing.routing.rt_table, routing.routing.internet)


def check_tcpdump_permissions():
    tcpdump = auxconf.sniffer.get("tcpdump", "/usr/bin/tcpdump")

    user = False
    with suppress(Exception):
        user = gt.getuser()

    pcap_permissions_error = False
    if user:
        try:
            subprocess.check_call(["/usr/bin/sudo", "--list", "--non-interactive", tcpdump], stderr=subprocess.DEVNULL)
        except (FileNotFoundError, subprocess.CalledProcessError):
            try:
                if user not in grp.getgrnam("pcap").gr_mem:
                    pcap_permissions_error = True
            except KeyError:
                log.error("Group pcap does not exist.")
                pcap_permissions_error = True

    if pcap_permissions_error:
        print(
            f"""\nPcap generation wan't work till you fix the permission problems. Please run following command to fix it!

            groupadd pcap
            usermod -a -G pcap {user}
            chgrp pcap {tcpdump}
            setcap cap_net_raw,cap_net_admin=eip {tcpdump}

            OR add the following line to /etc/sudoers.d/tcpdump:

            {user} ALL=NOPASSWD: {tcpdump}
            """
        )
