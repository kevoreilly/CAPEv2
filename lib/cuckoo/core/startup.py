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
from lib.cuckoo.core.rooter import gateways, rooter, socks5s, vpns

log = logging.getLogger()

cuckoo = Config()
logconf = Config("logging")
routing = Config("routing")
repconf = Config("reporting")
auxconf = Config("auxiliary")
dist_conf = Config("distributed")

# ---------------------------------------------------------------------------
# Next-hop egress primitive — constants used by loader + SIGTERM path
# ---------------------------------------------------------------------------
NEXTHOP_FAIL_TABLE = "250"
NEXTHOP_PRIORITY_LOW = "30000"
NEXTHOP_BAND_LO = "10000"
NEXTHOP_BAND_HI = "10255"
# Route keywords a [gwX] gateway id must never collide with. "nexthop" is the sentinel default
# route that maps to [nexthop] default_policy (pool selection), so a gateway named "nexthop"
# would be ambiguous — reserve it too (Copilot).
_RESERVED_ROUTE_NAMES = {"none", "internet", "tor", "inetsim", "drop", "false", "nexthop"}
# Pool-policy selector tokens: a task route of roundrobin/random means "pick from the live
# pool", so a [gwX] must not be *named* one of these (it could never be explicitly selected
# and would collide with the policy token in _resolve_nexthop/_select_gateway).
_POLICY_TOKENS = ("roundrobin", "random")
# Linux reserved/system routing tables. A [gwX] rt_table must never be one of these: it is fed
# straight into `ip route flush table <rt_table>` and, if it were `main`, the per-task rule would
# route the VM out the host's own default route (fail-OPEN) instead of the blackhole. Mirrors the
# defence-in-depth guard in utils.rooter nexthop_init/teardown. Kernel-fixed ids.
_RESERVED_RT_TABLES = ("local", "main", "default", "0", "253", "254", "255")


def load_nexthop_profiles(routing_cfg, apply_rooter_state=False):
    """Parse [nexthop]/[gwX] sections into the rooter.gateways global and validate them. When
    apply_rooter_state is True (ONLY the scheduler's init_routing passes this), ALSO sweep stale
    policy-routing state and build the gateway tables + arm fail-closed. Non-owning callers (the
    web/API process via web.settings, and vpncheck) leave it False: they must NOT issue the rooter
    sweep, which flushes the 10000-10255 per-task band and would tear down the egress/fail-closed of
    analyses currently running under the scheduler (codex P2). No-op when [nexthop] absent/disabled."""
    if not hasattr(routing_cfg, "nexthop") or not routing_cfg.nexthop.enabled:
        return
    # [nexthop] is enabled: it MUST define gateways + vm_net (gemini #14 MEDIUM). CAPE's config
    # Dictionary returns None (not AttributeError) for a missing key, so without this a missing
    # option slips through as None and misbehaves downstream — fail with a clear error instead.
    for opt in ("gateways", "vm_net"):
        if getattr(routing_cfg.nexthop, opt, None) is None:
            raise CuckooStartupError(f"[nexthop] is enabled but missing the required '{opt}' option in routing.conf")
    # Routing tables already OWNED by another primitive -- a [gwX] must not reuse one. nexthop_init
    # flush/replaces each gateway table, so a shared table silently clobbers (or is clobbered by) the
    # other primitive's route, misrouting its traffic with no error. Two sources, both knowable now:
    #   - VPN tables: init_routing builds vpns[*].rt_table BEFORE calling us, so nexthop_init would
    #     wipe a just-built VPN table and point its default out the gateway NIC (VPN-isolation break).
    #   - the [routing] dirty-line table (routing.routing.rt_table): its init_rttable runs AFTER us,
    #     so it would repopulate a gateway table with the dirty-line interface.
    # Coerce to str: a VPN rt_table (or the dirty-line one) may be an int or a name in config.
    owned_tables = {}
    for vname, ventry in vpns.items():
        vrt = getattr(ventry, "rt_table", None)
        if vrt is not None:
            owned_tables[str(vrt)] = f"VPN '{vname}'"
    dirty_rt = getattr(getattr(routing_cfg, "routing", None), "rt_table", None)
    dirty_internet = str(getattr(getattr(routing_cfg, "routing", None), "internet", "none") or "none")
    # Only reserve the [routing] dirty-line table when the dirty-line route is actually enabled (its
    # init_rttable runs only when internet != "none"). A nexthop-only node (internet = none) with a
    # preconfigured rt_table must not falsely reject a [gwX] reusing that id and fail to start (codex P2).
    if dirty_rt is not None and str(dirty_rt) and dirty_internet != "none":
        owned_tables.setdefault(str(dirty_rt), "the [routing] dirty-line table")
    # The fail-closed blackhole is installed into NEXTHOP_FAIL_TABLE; if a VPN or the (enabled)
    # dirty-line already owns that table, the blackhole would overwrite ITS default route and silently
    # drop its traffic. Reject at startup -- only relevant when fail_closed is on (codex P2).
    if routing_cfg.nexthop.fail_closed and str(NEXTHOP_FAIL_TABLE) in owned_tables:
        raise CuckooStartupError(
            f"[nexthop] fail_closed uses table '{NEXTHOP_FAIL_TABLE}' which collides with "
            f"{owned_tables[str(NEXTHOP_FAIL_TABLE)]}; the blackhole would overwrite its default route"
        )
    # Pass 1: parse + validate + register profiles (no rooter side effects yet).
    profiles = []
    claimed_tables = {}   # rt_table -> gateway id, to reject duplicates (each [gwX] needs its own)
    for name in routing_cfg.nexthop.gateways.split(","):
        name = name.strip()
        if not name:
            continue
        if name in _RESERVED_ROUTE_NAMES or name in _POLICY_TOKENS or name in vpns or name in socks5s or name[:3] == "tun":
            raise CuckooStartupError(f"nexthop gateway id '{name}' collides with a reserved/route/policy name")
        if not hasattr(routing_cfg, name):
            raise CuckooStartupError(f"nexthop gateway '{name}' has no [{name}] section in routing.conf")
        entry = routing_cfg.get(name)
        # A [gwX] section MUST define interface/next_hop/rt_table (gemini #14 MEDIUM). Config
        # Dictionary returns None for a missing key, so validate explicitly — otherwise None
        # (or str(None)=="None") would slip into the rooter commands below.
        for opt in ("interface", "next_hop", "rt_table"):
            if getattr(entry, opt, None) is None:
                raise CuckooStartupError(f"nexthop gateway '{name}' is missing the required '{opt}' option in [{name}]")
        entry.rt_table = str(entry.rt_table)   # coerce: config may produce int (review B3)
        # A reserved rt_table (main/local/default/...) must be rejected HERE, at load, not just
        # skipped in nexthop_init: an unbuilt custom table is empty so its per-task rule falls
        # through to the fail-closed blackhole, but `main` already holds the host default route,
        # so a per-task `from vm_ip lookup main priority 100xx` (below the 30000 blackhole) would
        # route the VM straight out the control-plane NIC -- an isolation bypass. Fail loudly.
        if entry.rt_table in _RESERVED_RT_TABLES:
            raise CuckooStartupError(
                f"nexthop gateway '{name}' uses reserved routing table '{entry.rt_table}' in [{name}]; "
                "pick a dedicated custom table id (e.g. 201)"
            )
        # rt_table must not be the fail-closed table: nexthop_init builds the gateway default there,
        # then nexthop_fail_closed_enable does `ip route replace blackhole default table <fail>`,
        # overwriting that default with a blackhole -> every task bound to the gateway silently drops.
        if entry.rt_table == NEXTHOP_FAIL_TABLE:
            raise CuckooStartupError(
                f"nexthop gateway '{name}' uses rt_table '{entry.rt_table}' in [{name}], which is the "
                "reserved fail-closed table; the blackhole would overwrite the gateway's default route. "
                "Pick a different custom table id."
            )
        # rt_table must not be owned by a VPN or the [routing] dirty-line (see owned_tables above):
        # nexthop_init would clobber that primitive's table and silently misroute its traffic. This
        # catches DIRECT string collisions; a name<->id alias (a VPN using the name "tun0" mapped to
        # id 201 in /etc/iproute2/rt_tables while a [gwX] uses 201) resolves to the same kernel table
        # but different config strings -- that stays the operator's "unique across the system"
        # responsibility, as documented for VPN rt_table in routing.conf.
        if entry.rt_table in owned_tables:
            raise CuckooStartupError(
                f"nexthop gateway '{name}' rt_table '{entry.rt_table}' in [{name}] collides with "
                f"{owned_tables[entry.rt_table]}; each routing primitive needs a unique table id"
            )
        # rt_table must be UNIQUE across [gwX]: nexthop_init flush/replaces a single table per profile,
        # so a shared table leaves the last gateway's default winning while the earlier gateway stays
        # selectable -> its per-task rule looks up a table pointing at the wrong egress interface.
        if entry.rt_table in claimed_tables:
            raise CuckooStartupError(
                f"nexthop gateways '{claimed_tables[entry.rt_table]}' and '{name}' both use rt_table "
                f"'{entry.rt_table}'; each [gwX] needs a unique routing table id"
            )
        claimed_tables[entry.rt_table] = name
        # [gwX] sections carry no `name =` field (unlike [vpnX]/[socks5]), so config
        # Dictionary.__getattr__ returns None for entry.name. Carry the section header as
        # the profile id: analysis_manager._resolve_nexthop reads profile.name into
        # self.nexthop_id, and a None id makes _dispatch_nexthop silently no-op (the
        # per-task rule never installs and every task fails closed). Verified live.
        entry.name = name
        gateways[name] = entry
        profiles.append(entry)
    # [nexthop] enabled but nothing usable parsed (e.g. gateways = "" or all-blank): without
    # this every analysis task would silently fall through to the fail-closed blackhole. Fail
    # loudly at startup instead (gemini medium).
    if not profiles:
        raise CuckooStartupError("[nexthop] is enabled but no gateways were configured in routing.conf")
    # default_policy must resolve: a pool selector (roundrobin/random) or one of the configured gateway
    # ids. Otherwise _select_gateway() returns None for every default/route=nexthop task and they all
    # silently drop; reject a typo'd/dangling policy at startup instead of shipping a dead pool (codex P2).
    default_policy = str(getattr(routing_cfg.nexthop, "default_policy", "") or "")
    gateway_ids = {p.name for p in profiles}
    if default_policy not in _POLICY_TOKENS and default_policy not in gateway_ids:
        raise CuckooStartupError(
            f"[nexthop] default_policy '{default_policy}' must be 'roundrobin', 'random', or a configured "
            f"gateway id ({', '.join(sorted(gateway_ids))})"
        )
    if not apply_rooter_state:
        # Parsed + validated + gateways populated; skip ALL rooter mutations. Only the scheduler
        # (cuckoo.py -> init_routing(apply_nexthop_state=True)) owns the sweep/build/arm -- doing it
        # from the web/API startup would flush the per-task band and drop live analyses (codex P2).
        return
    vm_net = str(routing_cfg.nexthop.vm_net)
    tables_csv = ",".join(p.rt_table for p in profiles)
    # Record sweep state for SIGTERM, then sweep any STALE state from a prior run
    # BEFORE building fresh tables. nexthop_teardown flushes the gateway tables, so it
    # MUST run before nexthop_init (which builds them) or it wipes the just-built routes.
    rooter("nexthop_configure", tables_csv, vm_net, NEXTHOP_FAIL_TABLE,
           NEXTHOP_PRIORITY_LOW, NEXTHOP_BAND_LO, NEXTHOP_BAND_HI)
    rooter("nexthop_teardown", tables_csv, vm_net, NEXTHOP_FAIL_TABLE,
           NEXTHOP_PRIORITY_LOW, NEXTHOP_BAND_LO, NEXTHOP_BAND_HI)
    # Pass 2: build fresh profile tables, then arm the intra-subnet exception + (optionally) fail-closed.
    for entry in profiles:
        rooter("nexthop_init", str(entry.rt_table), str(entry.interface), str(entry.next_hop))
    # The intra-subnet exception (keep guest<->host + guest<->guest vm_net traffic on main) is a
    # CONNECTIVITY guarantee, independent of the blackhole -- install it whenever nexthop is enabled.
    # Otherwise, with fail_closed=no, a bound VM's per-task rule would send its intra-vm_net traffic
    # (siblings / non-host-local services) out the gateway instead of the guest network (codex P2).
    rooter("nexthop_intra_exception_enable", vm_net, NEXTHOP_BAND_LO)
    if routing_cfg.nexthop.fail_closed:
        rooter("nexthop_fail_closed_enable", vm_net, NEXTHOP_FAIL_TABLE, NEXTHOP_PRIORITY_LOW)


def validate_default_route(routing_cfg):
    """Check that the configured default route is valid.  Accepts gateway ids
    (from gateways global) when nexthop is enabled, bypassing the vpn.enabled gate.
    Extracted from init_routing so it is independently unit-testable (review H3)."""
    route = routing_cfg.routing.route
    if route in ("none", "internet", "tor", "inetsim"):
        return
    nexthop_on = hasattr(routing_cfg, "nexthop") and routing_cfg.nexthop.enabled
    if nexthop_on and (route in gateways or route in _POLICY_TOKENS or route == "nexthop"):
        # A concrete gateway id, a pool-policy token (roundrobin/random), or the "nexthop" sentinel
        # is a valid default route when nexthop is on -- _resolve_nexthop maps the token/sentinel to
        # default_policy and picks from the live pool. Accept it here so the documented pool default
        # (route = nexthop) works without a VPN; otherwise startup wrongly raises the vpn-not-enabled
        # error and the default_policy fallback is unreachable in production (codex P2 / Copilot).
        return  # skip the vpn.enabled gate
    if not routing_cfg.vpn.enabled:
        raise CuckooStartupError(
            "A VPN has been configured as default routing interface for VMs, but VPNs have not been enabled in routing.conf"
        )
    if route not in vpns and route not in socks5s:
        raise CuckooStartupError(
            "The VPN/Socks5 defined as default routing target has not been configured in routing.conf. You should use name field"
        )


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
        index_configs = [
            ("analysis", [("info.id", -1)], {"name": "info_id_desc"}),
            ("files", [("_task_ids", 1)], {}),
        ]
        if repconf.mongodb.get("index_yara", False):
            index_configs.extend([
                ("files", "yara.name", {"name": "yara_name"}),
                ("files", "cape_yara.name", {"name": "cape_yara_name"}),
            ])
        if repconf.mongodb.get("index_clamav", False):
            index_configs.append(("files", "clamav", {"name": "clamav_index"}))
        if repconf.mongodb.get("index_hashes", False):
            index_configs.extend([
                ("files", "md5", {"name": "file_md5"}),
                ("files", "sha1", {"name": "file_sha1"}),
                ("files", "ssdeep", {"name": "file_ssdeep"}),
            ])
        if repconf.mongodb.get("index_detections", False):
            index_configs.append(("analysis", [("detections.family", 1), ("_id", -1)], {"name": "detections_family_id_desc"}))
        if repconf.mongodb.get("index_filenames", False):
            index_configs.append(("analysis", [("target.file.name", 1), ("_id", -1)], {"name": "target_file_name_id_desc"}))
        if repconf.mongodb.get("index_hunt", False):
            index_configs.extend([
                ("analysis", "network.domains.domain", {"name": "hunt_domains"}),
                ("analysis", "network.hosts.ip", {"name": "hunt_ips"}),
                ("analysis", "behavior.summary.mutexes", {"name": "hunt_mutexes"}),
                ("analysis", "dropped.filepath", {"name": "hunt_dropped_files"}),
                ("analysis", "behavior.summary.executed_commands", {"name": "hunt_commands"}),
                ("analysis", "behavior.summary.keys", {"name": "hunt_registry_keys"}),
                ("analysis", "dropped._id", {"name": "hunt_dropped_hashes"}),
                ("analysis", "procdump._id", {"name": "hunt_procdump_hashes"}),
                ("analysis", "CAPE.payloads._id", {"name": "hunt_extracted_hashes"}),
                ("analysis", "static.pe.imphash", {"name": "hunt_imphashes"}),
                ("analysis", "network.http.uri", {"name": "hunt_http_uris"}),
                ("analysis", "signatures.name", {"name": "hunt_signatures"}),
            ])

        # Obsolete indexes to drop
        obsolete_indexes = {
            "analysis": ["info.id_1", "detections_family", "name_1", "detections_family_1", "target_file_name_1"],
        }

        for coll, keys, kwargs in index_configs:
            try:
                mongo_create_index(coll, keys, **kwargs)
            except Exception as e:
                log.warning("Failed to create MongoDB index %s on %s: %s", kwargs.get("name", keys), coll, e)

        # Drop obsolete indexes
        from dev_utils.mongodb import results_db
        for coll, indexes in obsolete_indexes.items():
            for index_name in indexes:
                with suppress(Exception):
                    getattr(results_db, coll).drop_index(index_name)
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
            log.info(
                "[!] You are using NOT supported Linux distribution by devs! Any issue report is invalid! We only support Ubuntu LTS %s",
                ubuntu_versions,
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
            "Please ensure that CAPE is being launched by the same Python environment configured by the install script."
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


def init_rooter(apply_state=False):
    """If required, check whether the rooter is running and whether we can connect to it.

    apply_state: only the SCHEDULER (cuckoo.py) passes True, to RESET rooter state at its startup
    (cleanup_rooter / cleanup_vrf / forward_drop / state_*). The web/API process and vpncheck verify
    the rooter is reachable but must leave it False -- running cleanup_rooter cross-process would
    remove the live per-task nexthop (and VPN) iptables rules of analyses owned by the scheduler
    (codex P1). Reachability is still checked for all callers (fail-fast if the rooter is required)."""

    # The default configuration doesn't require the rooter to be ran.
    # A nexthop-only node still needs the rooter for forward_drop() + fail-closed arm.
    _nexthop_enabled = hasattr(routing, "nexthop") and routing.nexthop.enabled
    if (
        not routing.vpn.enabled
        and not routing.tor.enabled
        and not routing.inetsim.enabled
        and not routing.socks5.enabled
        and routing.routing.route == "none"
        and not _nexthop_enabled
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

    if not apply_state:
        # Reachability verified above; do NOT reset rooter state. cleanup_rooter/forward_drop/state_*
        # would tear down the scheduler's live per-task nexthop (and VPN) rules on a web/API/gunicorn
        # restart (codex P1). Only the scheduler (init_rooter(apply_state=True)) owns that reset.
        return

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



def init_routing(apply_nexthop_state=False):
    """Initialize and check whether the routing information is correct.

    apply_nexthop_state: only the SCHEDULER (cuckoo.py) passes True, to sweep+build+arm the nexthop
    rooter state. The web/API process and vpncheck call this to populate vpns/socks5s/gateways and
    validate config, but must leave it False so they don't tear down live analyses (codex P2)."""

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

    # Load [gwX] next-hop egress profiles; apply rooter state (sweep/build/arm) only for the scheduler
    # (no-op when [nexthop] absent/disabled).
    load_nexthop_profiles(routing, apply_rooter_state=apply_nexthop_state)

    # If we are storage and webgui only but using as default route one of the workers exitnodes
    if dist_conf.distributed.master_storage_only:
        return

    # Check whether the default VPN/gateway exists if specified.
    validate_default_route(routing)

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
