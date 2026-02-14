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

try:
    # Private
    import custom.signatures
    HAS_CUSTOM_SIGNATURES = True
except ModuleNotFoundError:
    HAS_CUSTOM_SIGNATURES = False
try:
    import custom.signatures.all
except ImportError:
    HAS_CUSTOM_SIGNATURES_ALL = False
else:
    HAS_CUSTOM_SIGNATURES_ALL = True
try:
    import custom.signatures.linux
except ImportError:
    HAS_CUSTOM_SIGNATURES_LINUX = False
else:
    HAS_CUSTOM_SIGNATURES_LINUX = True
try:
    import custom.signatures.windows
except ImportError:
    HAS_CUSTOM_SIGNATURES_WINDOWS = False
else:
    HAS_CUSTOM_SIGNATURES_WINDOWS = True
import modules.auxiliary
import modules.feeds
import modules.processing
import modules.reporting
import modules.signatures.all
import modules.signatures.linux
import modules.signatures.windows
from lib.cuckoo.common.colors import cyan, red, yellow
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooOperationalError, CuckooStartupError
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import create_folders
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.data.task import TASK_FAILED_ANALYSIS, TASK_RUNNING
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
        # Some indexes that can be useful for some users
        mongo_create_index("files", "md5", name="file_md5")
        mongo_create_index("files", [("_task_ids", 1)])

        # side indexes as ideas
        """
            mongo_create_index("analysis", "detections", name="detections_1")
            mongo_create_index("analysis", "target.file.name", name="name_1")
        """

    elif repconf.elasticsearchdb.enabled:
        # ToDo add check
        pass


def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = [
        os.path.join(CUCKOO_ROOT, "conf", "default", "cuckoo.conf.default"),
        os.path.join(CUCKOO_ROOT, "conf", "default", "reporting.conf.default"),
        os.path.join(CUCKOO_ROOT, "conf", "default", "auxiliary.conf.default"),
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


class ConsoleHandler(logging.StreamHandler):
    """Logging to console handler."""

    def emit(self, record):
        colored = copy.copy(record)

        if record.levelname == "WARNING":
            colored.msg = yellow(record.msg)
        elif record.levelname in ("ERROR", "CRITICAL"):
            colored.msg = red(record.msg)
        else:
            # Hack for pymongo.logger.LogMessage
            if not isinstance(record.msg, str):
                record.msg = str(record.msg)

            if "analysis procedure completed" in record.msg:
                colored.msg = cyan(record.msg)
            else:
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)


def check_linux_dist():
    ubuntu_versions = ("20.04", "22.04", "24.04")
    with suppress(AttributeError):
        platform_details = platform.dist()
        if platform_details[0] != "Ubuntu" and platform_details[1] not in ubuntu_versions:
            log.info("[!] You are using NOT supported Linux distribution by devs! Any issue report is invalid! We only support Ubuntu LTS %s", ubuntu_versions)


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
    import_package(modules.signatures.all)
    import_package(modules.signatures.windows)
    import_package(modules.signatures.linux)
    # Import all private signatures
    if HAS_CUSTOM_SIGNATURES:
        import_package(custom.signatures)
    if HAS_CUSTOM_SIGNATURES_ALL:
        import_package(custom.signatures.all)
    if HAS_CUSTOM_SIGNATURES_LINUX:
        import_package(custom.signatures.linux)
    if HAS_CUSTOM_SIGNATURES_WINDOWS:
        import_package(custom.signatures.windows)
    if len(os.listdir(os.path.join(CUCKOO_ROOT, "modules", "signatures"))) < 5:
        log.warning("Suggestion: looks like you didn't install community, execute: poetry run python utils/community.py -h")
    # Import all reporting modules.
    import_package(modules.reporting)
    # Import all feeds modules.
    import_package(modules.feeds)

    # Import machine manager.
    import_plugin(f"modules.machinery.{cuckoo.cuckoo.machinery}")
    check_snapshot_state()

    for category, entries in list_plugins().items():
        log.debug('Imported "%s" modules:', category)

        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)


def check_snapshot_state():
    """Checks the state of snapshots and machine architecture for KVM/QEMU machinery."""
    if cuckoo.cuckoo.machinery not in ("kvm", "qemu"):
        return

    try:
        import libvirt
        from xml.etree import ElementTree
    except ImportError:
        raise CuckooStartupError(
            "The 'libvirt-python' library is required for KVM/QEMU machinery but could not be imported. "
            "Please ensure the python interpreter being used to execute cape is the same one configured by the install script."
        )

    machinery_config = Config(cuckoo.cuckoo.machinery)
    dsn = machinery_config.get(cuckoo.cuckoo.machinery).get("dsn")
    conn = None

    try:
        conn = libvirt.open(dsn)
    except libvirt.libvirtError as e:
        raise CuckooStartupError(f"Failed to connect to libvirt with DSN '{dsn}'. Error: {e}")

    if conn is None:
        raise CuckooStartupError(f"Failed to connect to libvirt with DSN '{dsn}'. Please check your configuration and libvirt service.")

    try:
        for machine_name in machinery_config.get(cuckoo.cuckoo.machinery).machines.split(","):
            machine_name = machine_name.strip()
            if not machine_name:
                continue

            snapshot_name = ""
            try:
                machine_config = machinery_config.get(machine_name)
                machine_name = machine_config.get("label")
                domain = conn.lookupByName(machine_name)
                # Check for valid architecture configuration.
                arch = machine_config.get("arch")
                if not arch:
                    raise CuckooStartupError(f"Missing 'arch' configuration for VM '{machine_name}'. Please specify a valid architecture (e.g., x86, x64).")

                if arch == "x86_64":
                    raise CuckooStartupError(
                        f"Invalid architecture '{arch}' for VM '{machine_name}'. Please use 'x64' instead of 'x86_64'."
                    )

                if arch != arch.lower():
                    raise CuckooStartupError(
                        f"Invalid architecture '{arch}' for VM '{machine_name}'. Architecture must be all lowercase."
                    )

                # Check snapshot state.
                snapshot_name = machine_config.get("snapshot")
                snapshot = None

                if snapshot_name:
                    snapshot = domain.snapshotLookupByName(snapshot_name)
                else:
                    if domain.hasCurrentSnapshot(0):
                        snapshot = domain.snapshotCurrent(0)
                        snapshot_name = snapshot.getName()
                        log.info("No snapshot name configured for VM '%s', checking latest: '%s'", machine_name, snapshot_name)
                    else:
                        log.warning("No snapshot configured or found for VM '%s'. Skipping check.", machine_name)
                        continue

                xml_desc = snapshot.getXMLDesc(0)
                root = ElementTree.fromstring(xml_desc)
                state_element = root.find("state")

                if state_element is None or state_element.text != "running":
                    state = state_element.text if state_element is not None else "unknown"
                    raise CuckooStartupError(
                        f"Snapshot '{snapshot_name}' for VM '{machine_name}' is not in a 'running' state (current state: '{state}'). "
                        "Please ensure you take snapshots of running VMs."
                    )

            except libvirt.libvirtError as e:
                # It's possible a snapshot name is provided but doesn't exist, which is a config error.
                snapshot_identifier = f"with snapshot '{snapshot_name}'" if snapshot_name else ""
                raise CuckooStartupError(
                    f"Error checking snapshot state for VM '{machine_name}' {snapshot_identifier}. Libvirt error: {e}"
                )
    finally:
        if conn:
            conn.close()


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
    rooter("cleanup_vrf", routing.routing.internet)

    # Do not forward any packets unless we have explicitly stated so.
    rooter("forward_drop")
    rooter("state_disable")
    rooter("state_enable")

    # ToDo check if ip_forward is on

    # Check if UFW is enabled. If it is, it could interfere with routing.
    # We use subprocess.run for better error handling and stdout capture.
    try:
        ufw_proc = subprocess.run(["ufw", "status"], capture_output=True, text=True, check=False)

        if ufw_proc.returncode == 0:
            if "Status: active" in ufw_proc.stdout:
                log.warning(
                    "UFW (Uncomplicated Firewall) is active. This might interfere with CAPEv2's network routing/analysis. "
                    "Please ensure UFW is configured to allow all necessary traffic for CAPEv2 or consider disabling it for analysis. "
                    "You can check UFW rules with 'sudo ufw status verbose'."
                )
            else:
                log.debug("UFW is not active, which is ideal for CAPEv2's routing setup.")
        else:
            log.debug(
                "Could not check UFW status (command exited with code %d). "
                "Output: %s. Error: %s", ufw_proc.returncode, ufw_proc.stdout, ufw_proc.stderr
            )
    except FileNotFoundError:
        log.debug("UFW command not found. Assuming UFW is not in use.")
    except Exception as e:
        log.debug("An unexpected error occurred while checking UFW status: %s", e)


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

        if routing.routing.nat:
            # Disable & enable NAT on this network interface. Disable it just
            # in case we still had the same rule from a previous run.
            rooter("disable_nat", routing.routing.internet)
            rooter("enable_nat", routing.routing.internet)
            # Populate routing table with entries from main routing table.
        else:
            rooter("disable_nat", routing.routing.internet)
            if routing.routing.no_local_routing:
                rooter("init_vrf", routing.routing.rt_table, routing.routing.internet)
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


def check_vms_n_resultserver_networking():
    vms = {}
    resultserver_block = cuckoo.resultserver.ip.rsplit(".", 2)[0]
    machinery = cuckoo.cuckoo.machinery
    if machinery == "multi":
        for mmachinery in Config(machinery).multi.get("machinery").split(","):
            vms.update(
                {
                    x.strip(): [getattr(Config(mmachinery), x).ip, getattr(getattr(Config(mmachinery), x), "resultserver", "")]
                    for x in getattr(Config(mmachinery), mmachinery).get("machines").split(",")
                    if x.strip()
                }
            )
    else:
        vms.update(
            {
                x.strip(): [
                    getattr(Config(machinery), x).ip.rsplit(".", 2)[0],
                    getattr(getattr(Config(machinery), x), "resultserver", "".rsplit(".", 2)[0]),
                ]
                for x in getattr(Config(machinery), machinery).get("machines").split(",")
                if x.strip()
            }
        )
    for vm, network in vms.items():
        vm_ip, vm_rs = network
        # is there are better way to check networkrange without range CIDR?
        if not resultserver_block.startswith(vm_ip) or (vm_rs and not vm_rs.startswith(vm_ip)):
            log.error("Your resultserver and VM: %s are in different nework ranges. This might give you: CuckooDeadMachine", vm)
