import atexit
import logging
import os
import shutil
import socket
import sys
import threading
import time
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from multiprocessing.pool import ThreadPool
from typing import Callable, Optional, Union

from sqlalchemy import delete, select

from lib.cuckoo.common.config import Config, _BaseConfig
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.dist_db import Task as DTask
from lib.cuckoo.common.dist_db import create_session
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_get_date, path_is_dir, path_mkdir
from lib.cuckoo.core.database import Database, _Database
from lib.cuckoo.core.data.samples import Sample
from lib.cuckoo.core.data.task import (
    TASK_BANNED,
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_PENDING,
    TASK_RECOVERED,
    TASK_REPORTED,
    Task
)
from lib.cuckoo.core.startup import create_structure, init_console_logging

log = logging.getLogger(__name__)

config = Config()
repconf = Config("reporting")
webconf = Config("web")
class _LazyThreadPool:
    """Defers ThreadPool(50) creation until the first .map()/attribute use.

    Importing this module used to eagerly spawn 53 threads (50 workers + 3
    handler threads) in *every* process that imports it -- including
    utils/process.py, which only needs free_space_monitor() and never touches
    the resolver pool. Those live threads sat in the processor before it forked
    its workers, and forking a heavily-multithreaded process deadlocks the
    forked children in multiprocessing bootstrap/atexit (_exit_function -> join
    -> waitpid), and trips the prefork single-threaded-before-fork invariant.
    Only the cleaner/deletion paths actually call resolver_pool.map(), so the
    pool is now created on demand by those callers and the processor forks clean.
    """

    _pool = None
    _lock = threading.Lock()

    def _get(self):
        if self._pool is None:
            with self._lock:
                if self._pool is None:
                    self._pool = ThreadPool(50)
        return self._pool

    def __getattr__(self, name):
        return getattr(self._get(), name)


resolver_pool = _LazyThreadPool()


@atexit.register
def _close_resolver_pool():
    if resolver_pool._pool is not None:
        resolver_pool._pool.close()

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
        mongo_update_many,
        mongo_delete_calls_by_task_id_in_range,
    )
elif repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import all_docs, delete_analysis_and_related_calls, get_analysis_index


DB_BATCH_SIZE = 1000
CLEANED_TMP_SUBDIRS = ("cuckoo-tmp", "cape-external", "cuckoo-sflock", "cape-pubsub")


def _resolve_tmppath() -> str:
    """Resolve `[cuckoo] tmppath` safely as str, defaulting to `/tmp`."""
    cfg_obj = Config() if isinstance(config, _BaseConfig) else config
    raw = cfg_obj.cuckoo.get("tmppath")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    elif raw is not None:
        raw = os.fspath(raw)
    return (raw or "/tmp").strip() or "/tmp"


def _scan_dir_bounded(
    root_path: str,
    max_items: int,
    max_entries: int,
    deadline: float,
    skip_names: Optional[set] = None,
) -> dict:
    """Scan a directory tree up to strict entry and wall-clock budgets."""
    top_n = max(0, int(max_items))
    result = {
        "path": root_path,
        "exists": os.path.isdir(root_path),
        "bytes": 0,
        "mb": 0.0,
        "files": 0,
        "dirs": 0,
        "truncated": False,
        "top_items": [],
        "entries_scanned": 0,
    }
    if not result["exists"]:
        return result
    if max_entries <= 0 or time.monotonic() >= deadline:
        result["truncated"] = True
        return result

    total_bytes = 0
    file_count = 0
    dir_count = 0
    entries_scanned = 0
    direct_count = 0
    truncated = False
    items = []

    try:
        top_iter = os.scandir(root_path)
    except OSError:
        return result

    with top_iter:
        for top_entry in top_iter:
            if skip_names and top_entry.name in skip_names:
                continue
            if entries_scanned >= max_entries or time.monotonic() >= deadline:
                truncated = True
                break
            entries_scanned += 1
            direct_count += 1
            try:
                if top_entry.is_dir(follow_symlinks=False):
                    dir_count += 1
                    sub_bytes = 0
                    sub_stack = [top_entry.path]
                    while sub_stack:
                        if entries_scanned >= max_entries or time.monotonic() >= deadline:
                            truncated = True
                            break
                        curr_dir = sub_stack.pop()
                        try:
                            with os.scandir(curr_dir) as sub_it:
                                for entry in sub_it:
                                    if entries_scanned >= max_entries or time.monotonic() >= deadline:
                                        truncated = True
                                        break
                                    entries_scanned += 1
                                    try:
                                        if entry.is_dir(follow_symlinks=False):
                                            dir_count += 1
                                            sub_stack.append(entry.path)
                                        elif entry.is_file(follow_symlinks=False):
                                            sz = entry.stat(follow_symlinks=False).st_size
                                            file_count += 1
                                            sub_bytes += sz
                                    except OSError:
                                        continue
                        except OSError:
                            continue
                        if truncated:
                            break
                    total_bytes += sub_bytes
                    items.append(
                        {
                            "name": top_entry.name,
                            "path": top_entry.path,
                            "is_dir": True,
                            "bytes": sub_bytes,
                            "mb": round(sub_bytes / (1024 * 1024), 2),
                        }
                    )
                    if truncated:
                        break
                elif top_entry.is_file(follow_symlinks=False) or top_entry.is_symlink():
                    sz = top_entry.stat(follow_symlinks=False).st_size
                    file_count += 1
                    total_bytes += sz
                    items.append(
                        {
                            "name": top_entry.name,
                            "path": top_entry.path,
                            "is_dir": False,
                            "bytes": sz,
                            "mb": round(sz / (1024 * 1024), 2),
                        }
                    )
            except OSError:
                continue

    items.sort(key=lambda item: item["bytes"], reverse=True)
    result.update(
        {
            "bytes": total_bytes,
            "mb": round(total_bytes / (1024 * 1024), 2),
            "files": file_count,
            "dirs": dir_count,
            "entry_count": direct_count,
            "truncated": truncated,
            "top_items": items[:top_n],
            "entries_scanned": entries_scanned,
        }
    )
    return result


def collect_disk_usage_report(
    monitored_path: Optional[str] = None,
    max_items: int = 10,
    max_entries: int = 50000,
    max_seconds: float = 10.0,
) -> dict:
    """Collect bounded disk-usage telemetry, log summary, and upload JSON to GCS if enabled."""
    tmppath = _resolve_tmppath()
    storage_root = os.path.join(CUCKOO_ROOT, "storage")
    deadline = time.monotonic() + max(0.0, float(max_seconds))
    budget_left = max(0, int(max_entries))
    total_scanned = 0
    any_truncated = False

    # Collect unique mounts (st_dev)
    mounts = []
    seen_devs = set()
    mount_candidates = []
    if monitored_path:
        mount_candidates.append(str(monitored_path))
    mount_candidates.extend([storage_root, tmppath])

    for cand in mount_candidates:
        check = cand
        while check and not os.path.exists(check):
            parent = os.path.dirname(check)
            if parent == check:
                break
            check = parent
        if not check or not os.path.exists(check):
            continue
        try:
            st_dev = os.stat(check).st_dev
            if st_dev in seen_devs:
                continue
            seen_devs.add(st_dev)
            usage = shutil.disk_usage(check)
            mounts.append(
                {
                    "path": cand,
                    "resolved_path": check,
                    "st_dev": st_dev,
                    "total_mb": usage.total >> 20,
                    "used_mb": usage.used >> 20,
                    "free_mb": usage.free >> 20,
                    "free_pct": round((usage.free / usage.total) * 100.0, 2) if usage.total else 0.0,
                }
            )
        except OSError:
            continue

    # 1. Scan uncleaned tmppath root entries first (primary leak vector)
    uncleaned_tmp_root = _scan_dir_bounded(
        tmppath,
        max_items=max_items,
        max_entries=budget_left,
        deadline=deadline,
        skip_names=set(CLEANED_TMP_SUBDIRS),
    )
    uncleaned_tmp_root["cleaned_by_cape"] = False
    scanned = uncleaned_tmp_root.pop("entries_scanned", 0)
    total_scanned += scanned
    budget_left = max(0, budget_left - scanned)
    any_truncated = any_truncated or uncleaned_tmp_root["truncated"]

    # 2. Scan cleaned tmp subdirectories and log dir
    tmppath_cleaned = {}
    for folder in CLEANED_TMP_SUBDIRS:
        sub_path = os.path.join(tmppath, folder)
        sub_res = _scan_dir_bounded(sub_path, max_items=max_items, max_entries=budget_left, deadline=deadline)
        scanned = sub_res.pop("entries_scanned", 0)
        total_scanned += scanned
        budget_left = max(0, budget_left - scanned)
        any_truncated = any_truncated or sub_res["truncated"]
        tmppath_cleaned[folder] = sub_res

    log_dir = os.path.join(CUCKOO_ROOT, "log")
    log_summary = _scan_dir_bounded(log_dir, max_items=max_items, max_entries=budget_left, deadline=deadline)
    scanned = log_summary.pop("entries_scanned", 0)
    total_scanned += scanned
    budget_left = max(0, budget_left - scanned)
    any_truncated = any_truncated or log_summary["truncated"]

    # 3. Scan storage subdirs fairly so large analyses don't starve binaries/files/baseline
    storage_dirs = ("analyses", "binaries", "files", "baseline")
    existing_storage = [name for name in storage_dirs if os.path.isdir(os.path.join(storage_root, name))]
    storage_summary = {}
    remaining_existing = len(existing_storage)
    for name in storage_dirs:
        sub_path = os.path.join(storage_root, name)
        if name in existing_storage and remaining_existing > 0:
            per_dir_budget = max(1, budget_left // remaining_existing) if budget_left >= remaining_existing else budget_left
            sub_res = _scan_dir_bounded(sub_path, max_items=max_items, max_entries=per_dir_budget, deadline=deadline)
            remaining_existing -= 1
        else:
            sub_res = _scan_dir_bounded(sub_path, max_items=max_items, max_entries=0, deadline=deadline)
        scanned = sub_res.pop("entries_scanned", 0)
        total_scanned += scanned
        budget_left = max(0, budget_left - scanned)
        any_truncated = any_truncated or sub_res["truncated"]
        storage_summary[name] = sub_res

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname() or "unknown",
        "monitored_path": str(monitored_path) if monitored_path else None,
        "tmppath": tmppath,
        "mounts": mounts,
        "storage": storage_summary,
        "log": log_summary,
        "tmppath_cleaned": tmppath_cleaned,
        "uncleaned_tmp_root": uncleaned_tmp_root,
        "truncated": any_truncated,
        "entries_scanned": total_scanned,
    }

    mount_desc = ", ".join(f"{m['path']}: {m['free_mb']}/{m['total_mb']} MB free" for m in mounts) or "none"
    storage_desc = ", ".join(f"{k}={v['mb']} MB" for k, v in storage_summary.items())
    cleaned_tmp_desc = ", ".join(f"{k}={v['mb']} MB" for k, v in tmppath_cleaned.items())
    uncleaned_top = ", ".join(
        f"{item['name']}={item['mb']} MB" for item in uncleaned_tmp_root.get("top_items", [])[:5]
    ) or "none"
    log.error(
        "Disk usage breakdown (truncated=%s, entries=%d): mounts=[%s] | storage=[%s] | log=%s MB | "
        "tmppath_cleaned=[%s] | uncleaned_tmp_root(cleaned_by_cape=False)=%s MB (top: %s)",
        any_truncated,
        total_scanned,
        mount_desc,
        storage_desc,
        log_summary["mb"],
        cleaned_tmp_desc,
        uncleaned_tmp_root["mb"],
        uncleaned_top,
    )

    try:
        from lib.cuckoo.common.gcp import gcs_upload_disk_report

        gcs_upload_disk_report(report)
    except Exception as e:
        log.error("Failed to upload disk usage report to GCS: %s", e)

    return report


def convert_into_time(time_range: Union[str, int]) -> datetime:
    """
    Converts a time range (e.g., '12h', '1d', '5m', or positive int days)
    into a datetime object representing the time in the past.

    Args:
        time_range: A string in the format of a number followed by a unit
                    ('d' for days, 'h' for hours, 'm' for minutes, 's' for seconds),
                    or a positive integer number of days.

    Returns:
        A datetime object representing the time in the past based on the
        provided time range.

    Raises:
        ValueError: If the input is invalid or non-positive.
    """
    if isinstance(time_range, bool):
        raise ValueError("Invalid time range format.")
    if isinstance(time_range, int):
        if time_range <= 0:
            raise ValueError("Invalid numeric value.")
        time_range = f"{time_range}d"

    if not isinstance(time_range, str) or len(time_range) < 2:
        raise ValueError("Invalid time range format.")

    unit = time_range[-1].lower()
    value_str = time_range[:-1]

    if not value_str.isdigit():
        raise ValueError("Invalid numeric value.")

    value = int(value_str)
    now = datetime.now()

    time_units = {
        "d": "days",
        "h": "hours",
        "m": "minutes",
        "s": "seconds",
    }

    if unit in time_units:
        kwargs = {time_units[unit]: value}
        return now - timedelta(**kwargs)
    else:
        raise ValueError(f"Invalid time unit '{unit}'.")


# todo rewrite for time range
def free_space_monitor(
    path=False,
    return_value=False,
    processing=False,
    analysis=False,
    on_state_change: Optional[Callable[[bool, int], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    _sleep_fn: Optional[Callable[[float], None]] = None,
):
    """
    @param path: path to check
    @param return_value: return available size
    @param processing: size from cuckoo.conf -> freespace_processing.
    @param analysis: check the main storage size
    @param on_state_change: optional callback `(need_space: bool, space_available_mb: int)`
    @param should_stop: optional predicate returning True when caller requests shutdown
    @param _sleep_fn: optional sleep function override for testing
    """

    cleanup_dict = {
        "delete_mongo": config.cleaner.mongo,
    }
    if config.cleaner.binaries:
        cleanup_dict["delete_binaries_items_older_than"] = config.cleaner.binaries
    if config.cleaner.get("files"):
        cleanup_dict["delete_files_items_older_than"] = config.cleaner.get("files")
    if config.cleaner.tmp:
        cleanup_dict["delete_tmp_items_older_than"] = config.cleaner.tmp
    if config.cleaner.analysis:
        cleanup_dict["delete_older_than"] = config.cleaner.analysis
    if config.cleaner.unused_files_in_mongodb:
        cleanup_dict["delete_unused_file_data_in_mongo"] = 1

    need_space, space_available = False, 0
    # Calculate the free disk space in megabytes.
    # Check main FS if processing
    if processing:
        raw_free_space = config.cuckoo.freespace_processing
    elif not analysis and HAVE_TMPFS and tmpfs.enabled:
        path = tmpfs.path
        raw_free_space = tmpfs.freespace
    else:
        raw_free_space = config.cuckoo.freespace

    if not path or isinstance(path, bool):
        path = CUCKOO_ROOT

    if isinstance(raw_free_space, bool):
        log.warning("Invalid non-numeric freespace setting %r; skipping disk space check", raw_free_space)
        return (False, 0) if return_value else None
    try:
        free_space = int(raw_free_space)
    except (TypeError, ValueError):
        log.warning("Invalid freespace setting %r; skipping disk space check", raw_free_space)
        return (False, 0) if return_value else None

    if free_space <= 0:
        if return_value:
            try:
                space_available = shutil.disk_usage(path).free >> 20
            except OSError:
                space_available = 0
            return False, space_available
        return

    if path and not path_exists(path):
        try:
            path_mkdir(path, parent=True, exist_ok=True)
        except OSError as e:
            log.error("Failed to create monitored directory %s: %s", path, e)
            return (False, 0) if return_value else None

    sleep_fn = _sleep_fn if _sleep_fn is not None else time.sleep
    in_low_space = False
    recovered = False
    last_error_log: Optional[float] = None
    last_report_ts: Optional[float] = None

    try:
        while True:
            if should_stop is not None and should_stop():
                break
            try:
                space_available = shutil.disk_usage(path).free >> 20
                need_space = space_available < free_space
            except FileNotFoundError:
                log.error("Folder doesn't exist, maybe due to clean")
                try:
                    path_mkdir(path, parent=True, exist_ok=True)
                except OSError as e:
                    log.error("Failed to recreate monitored directory %s: %s", path, e)
                    break
                continue

            if return_value:
                return need_space, space_available

            if need_space:
                now = time.monotonic()
                if not in_low_space:
                    in_low_space = True
                    if on_state_change is not None:
                        try:
                            on_state_change(True, space_available)
                        except Exception as e:
                            log.warning("on_state_change(True) callback failed: %s", e)

                if last_error_log is None or (now - last_error_log) >= 300:
                    log.error(
                        "Not enough free disk space! (Only %d MB!). You can change limits it in cuckoo.conf -> freespace",
                        space_available,
                    )
                    last_error_log = now

                if last_report_ts is None or (now - last_report_ts) >= 1800:
                    try:
                        collect_disk_usage_report(path if path else None)
                    except Exception as e:
                        log.error("Failed to collect disk usage report: %s", e)
                    last_report_ts = now

                # Invoke cleaups here if enabled
                if config.cleaner.enabled:
                    execute_cleanup(cleanup_dict, init_log=False, isolate_errors=True)
                    try:
                        new_space = shutil.disk_usage(path).free >> 20
                    except OSError:
                        new_space = space_available
                    delay = 30 if new_space <= space_available else 5
                else:
                    delay = 30

                if should_stop is not None and should_stop():
                    break
                sleep_fn(delay)
            else:
                recovered = True
                break
    finally:
        if in_low_space and recovered and on_state_change is not None:
            try:
                on_state_change(False, space_available)
            except Exception as e:
                log.warning("on_state_change(False) callback failed: %s", e)


def delete_folder(folder):
    """Delete a folder and all its subdirectories.
    @param folder: path to delete.
    @raise CuckooOperationalError: if fails to delete folder.
    """
    import os
    import stat

    def remove_readonly(func, path, excinfo):
        try:
            # Attempt to heal permissions of the file/dir to make it writable and deletable
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            func(path)
        except Exception:
            try:
                # Log detailed ownership and permission information to make debugging easy for the admin
                st = os.stat(path)
                import pwd
                import grp
                owner = pwd.getpwuid(st.st_uid).pw_name
                group = grp.getgrgid(st.st_gid).gr_name
                mode = stat.filemode(st.st_mode)
                log.error("Failed to delete %s (Mode: %s, Owner: %s, Group: %s)", path, mode, owner, group)
            except Exception:
                log.error("Failed to delete %s and failed to fetch ownership details", path)

    if path_exists(folder):
        try:
            shutil.rmtree(folder, onerror=remove_readonly)
            if path_exists(folder):
                raise OSError(f"Directory {folder} was not completely removed due to permission errors on child files.")
        except OSError as e:
            log.error("Unable to delete folder %s: %s", folder, e)
            raise CuckooOperationalError(f"Unable to delete folder: {folder}. System error: {e}") from e


def connect_to_es():
    from dev_utils.elasticsearchdb import elastic_handler

    es = elastic_handler

    return es


def is_reporting_db_connected():
    try:
        if not webconf.web_reporting.enabled:
            return True
        if repconf.mongodb.enabled:
            client = connect_to_mongo()
            if client is None:
                log.info("Can't connect to mongo")
                return False
            results_db = client[mdb]
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


def is_contiguous_range(ids: list) -> bool:
    """Helper to check if a list of IDs is contiguous (has no gaps)."""
    if not ids:
        return False
    sorted_ids = sorted(ids)
    return (sorted_ids[-1] - sorted_ids[0] + 1) == len(ids)


def delete_bulk_tasks_n_folders(ids: list, delete_mongo: bool, delete_db_tasks=False, db_batch_size=None, force=False):
    if db_batch_size is None:
        db_batch_size = DB_BATCH_SIZE

    # 1. Delete folders sequentially in small batches of 10 to yield disk I/O
    for i in range(0, len(ids), 10):
        ids_tmp = ids[i : i + 10]
        for id in ids_tmp:
            try:
                path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(id))
                if path_is_dir(path):
                    delete_folder(path)
            except Exception as e:
                log.error(e)

    # 2. Delete from MongoDB in larger, highly-efficient batches or range
    if delete_mongo and ids:
        if mongo_is_cluster() and not force:
            response = input("You are deleting mongo data in cluster, are you sure you want to continue? y/n")
            if response.lower() in ("n", "not"):
                sys.exit()

        # Check for fast range deletion
        if is_contiguous_range(ids) and len(ids) > 100:
            range_start = min(ids)
            range_end = max(ids) + 1
            log.info("Contiguous range detected. Deleting MongoDB calls/analyses in range: %d to %d", range_start, range_end)
            from dev_utils.mongodb import mongo_delete_data_range
            mongo_delete_data_range(range_start=range_start, range_end=range_end)
        else:
            # Otherwise delete in larger batches
            for i in range(0, len(ids), db_batch_size):
                ids_batch = ids[i : i + db_batch_size]
                mongo_delete_data(ids_batch)

    # 3. Delete from SQL database in larger, highly-efficient batches
    if delete_db_tasks and ids:
        for i in range(0, len(ids), db_batch_size):
            ids_batch = ids[i : i + db_batch_size]
            # One transaction per batch: a failed batch is rolled back and logged without
            # poisoning the remaining batches.
            try:
                with db.transaction():
                    db.delete_tasks(task_ids=ids_batch)
            except Exception as e:
                log.error("Failed to delete tasks from DB: %s", str(e))


def fail_job(tid):
    log.info("set %s job to failed", tid)
    try:
        with db.transaction():
            db.set_status(tid, TASK_FAILED_ANALYSIS)
    except Exception as e:
        log.error("failed to set task %s as failed: %s", tid, e)
    finally:
        # Called from resolver_pool worker threads: drop this thread's scoped session.
        db.session.remove()


def delete_data(tid):
    try:
        log.info("removing %s from analysis db", tid)
        if repconf.mongodb.enabled:
            mongo_delete_data(tid)
        elif repconf.elasticsearchdb.enabled:
            delete_analysis_and_related_calls(tid)
    except Exception as e:
        log.exception("failed to remove analysis info (may not exist) %s due to %s", tid, e)
    _sql_deleted = False
    try:
        with db.transaction():
            _sql_deleted = db.delete_task(tid)
        if not _sql_deleted:
            log.info("task %s not found in DB", tid)
    except Exception as e:
        log.error("failed to remove task %s from DB: %s", tid, e)
    finally:
        # Called from resolver_pool worker threads: drop this thread's scoped session.
        db.session.remove()
    # delete_folder OUTSIDE the begin() block: an rmtree failure mid-delete must NOT roll back the (committed)
    # SQL delete and resurrect a task pointing at a half-deleted tree, re-broken every nightly run. A folder
    # failure is a disk orphan-by-path (logged).
    # NOTE: unlike the apiv2/remove() paths (SQL commit -> THEN Mongo), the report delete above runs FIRST and
    # mongo_delete_data() swallows its own exceptions (returns None; the elif arm is Elasticsearch-only), so a
    # surviving report + committed SQL delete (an unreapable doc) is still reachable here and is NOT detected.
    # Closing that needs a status-returning Mongo delete so the commit can be conditioned on it.
    if _sql_deleted:
        try:
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", str(tid)))
        except Exception as e:
            log.error("delete_data: folder delete failed for task %s (disk orphan-by-path): %s", tid, e)


def dist_delete_data(data, dist_session_maker):
    """Delete duplicated pending tasks (and their dist rows) given [(task_id, target_path), ...]."""
    id_list = []
    for id, file in data:
        try:
            if path_exists(file):
                try:
                    path_delete(file)
                except Exception as e:
                    log.info(e)
            # clean dist_db
            with dist_session_maker() as dist_db, dist_db.begin():
                dist_db.execute(delete(DTask).where(DTask.main_task_id == id))
            id_list.append(id)
        except Exception as e:
            log.info(e)

    try:
        if id_list:
            with db.transaction():
                db.delete_tasks(task_ids=id_list)
    except Exception as e:
        log.error("Failed to delete tasks %s from DB: %s", id_list, e)
    finally:
        # Called from resolver_pool worker threads: drop this thread's scoped session.
        db.session.remove()


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
        # ToDo temp cleanup
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

    # ToDo multi status
    failed_statuses = f"{TASK_FAILED_ANALYSIS}|{TASK_FAILED_PROCESSING}|{TASK_FAILED_REPORTING}|{TASK_RECOVERED}"
    with db.transaction():
        ids = [task.id for task in db.list_tasks(status=failed_statuses)]
    # Filesystem/Mongo cleanup runs outside any SQL transaction.
    delete_bulk_tasks_n_folders(ids, delete_mongo=True)
    with db.transaction():
        db.delete_tasks(status=failed_statuses)


def cuckoo_clean_banned_tasks():
    """Clean up banned tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB) for banned tasks.
    """
    create_structure()

    with db.transaction():
        ids = [task.id for task in db.list_tasks(status=TASK_BANNED)]
    if ids:
        delete_bulk_tasks_n_folders(ids, delete_mongo=True, delete_db_tasks=False, force=True)

    with db.transaction():
        db.delete_tasks(status=TASK_BANNED)


def cuckoo_clean_bson_suri_logs():
    """Clean up raw suri log files probably not needed if storing in mongo. Does not remove extracted files"""
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    from glob import glob

    with db.transaction():
        task_ids = [
            task.id
            for task in db.list_tasks(
                status=f"{TASK_FAILED_ANALYSIS}|{TASK_FAILED_PROCESSING}|{TASK_FAILED_REPORTING}|{TASK_RECOVERED}|{TASK_REPORTED}"
            )
        ]
    for task_id in task_ids:
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        if path_exists(path):
            jsonlogs = glob(f"{path}/logs/*json*")
            bsondata = glob(f"{path}/logs/*.bson")
            filesmeta = glob(f"{path}/logs/files/*.meta")
            for f in jsonlogs, bsondata, filesmeta:
                for fe in f:
                    try:
                        # log.info("removing %s", fe)
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
        ids = [task["info"]["id"] for task in rtmp]
        delete_bulk_tasks_n_folders(ids, delete_mongo=True, delete_db_tasks=True)
    elif repconf.elasticsearchdb.enabled:
        rtmp = [
            d["_source"]
            for d in all_docs(
                index=get_analysis_index(),
                query={"query": {"bool": {"must": [{"exists": {"field": "network.http"}}, {"match": {"info.category": "url"}}]}}},
                _source=["info.id"],
            )
        ]
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
    # resolver_pool.map(lambda tid: delete_data(tid), id_arr)
    if id_arr:
        delete_bulk_tasks_n_folders(id_arr, delete_mongo=True, delete_db_tasks=True)


def tmp_clean_before(timerange: Union[str, int]):
    """Clean up tmp folder
    It deletes all items in tmp folder before now - timerange.
    """
    older_than = convert_into_time(timerange)
    older_than_utc = older_than.astimezone(timezone.utc)
    tmp_folder_path = _resolve_tmppath()
    # 3rd party?
    for folder in CLEANED_TMP_SUBDIRS:
        target_dir = os.path.join(tmp_folder_path, folder)
        if not path_exists(target_dir):
            continue
        for root, directories, files in os.walk(target_dir, topdown=True):
            to_prune = []
            for name in directories + files:
                path = os.path.join(root, name)
                is_symlink = os.path.islink(path)
                if not is_symlink and not path_exists(path):
                    continue
                try:
                    path_ctime = os.lstat(path).st_ctime if is_symlink else path_get_date(path)
                except OSError:
                    continue
                if datetime.fromtimestamp(path_ctime, tz=timezone.utc) < older_than_utc:
                    try:
                        if is_symlink:
                            log.info("Delete symlink: %s", path)
                            os.unlink(path)
                            if name in directories:
                                to_prune.append(name)
                        elif path_is_dir(path):
                            log.info("Delete folder: %s", path)
                            delete_folder(path)
                            if name in directories:
                                to_prune.append(name)
                        elif path_exists(path):
                            log.info("Delete file: %s", path)
                            path_delete(path)
                    except Exception as e:
                        log.error(e)
            if to_prune:
                directories[:] = [d for d in directories if d not in to_prune]


def cuckoo_clean_before(args: dict):
    """Clean up old tasks
    It deletes all stored data from file system and configured databases (SQL
    and optionally MongoDB) for tasks completed before now - time range.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.

    create_structure()
    id_arr = []

    if not is_reporting_db_connected():
        return

    timerange = args.get("delete_older_than")
    if not timerange:
        log.info("No days argument provided bailing")
        return

    category = None
    added_before = convert_into_time(timerange)
    if args.get("files_only_filter"):
        log.info("file filter applied")
        category = "file"
    elif args.get("urls_only_filter"):
        log.info("url filter applied")
        category = "url"

    tags_tasks_like = args.get("tags_tasks_filter", False)
    delete_pending = args.get("delete_pending", False)

    with db.transaction():
        old_tasks = db.list_tasks(
            added_before=added_before,
            category=category,
            not_status=False if delete_pending else TASK_PENDING,
            tags_tasks_like=tags_tasks_like
        )
        # We need this to cleanup file system and MongoDB calls collection
        id_arr = [e.id for e in old_tasks]
    log.info("number of matching records %s before suri/custom filter", len(id_arr))
    if id_arr and args.get("suricata_zero_alert_filter"):
        result = list(
            mongo_find("analysis", {"suricata.alerts.alert": {"$exists": False}, "info.id": {"$in": id_arr}}, {"info.id": 1, "_id": 0})
        )
        id_arr = [entry["info"]["id"] for entry in result]
    if id_arr and args.get("custom_include_filter"):
        result = list(
            mongo_find(
                "analysis", {"info.custom": {"$regex": args.get("custom_include_filter")}, "info.id": {"$in": id_arr}}, {"info.id": 1, "_id": 0}
            )
        )
        id_arr = [entry["info"]["id"] for entry in result]
    highest_id = max(id_arr, default=0)
    log.info("number of matching records %s. Highest id: %d", len(id_arr), highest_id)
    # delete_bulk_tasks_n_folders(id_arr, args.get("delete_mongo"), db_delete_before=1)
    # resolver_pool.map(lambda tid: delete_data(tid), id_arr)
    # ids = [tid["info.id"] for tid in tids]
    for i in range(0, len(id_arr), 100):
        ids_tmp = id_arr[i : i + 100]
        for id in ids_tmp:
            try:
                path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(id))
                if path_is_dir(path):
                    delete_folder(path)
            except Exception as e:
                log.error(e)

    if args.get("delete_mongo"):
        if mongo_is_cluster():
            response = input("You are deleting mongo data in cluster, are you sure you want to continue? y/n")
            if response.lower() in ("n", "not"):
                sys.exit()
        mongo_delete_data(id_arr)

    if args.get("suricata_zero_alert_filter") or args.get("custom_include_filter"):
        if id_arr:
            with db.transaction():
                db.delete_tasks(task_ids=id_arr)
    else:
        with db.transaction():
            db.delete_tasks(added_before=added_before, category=category, tags_tasks_like=tags_tasks_like)


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
                    try:
                        # ToDo replace to $in
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


def cuckoo_clean_pending_tasks(timerange: str = None, delete: bool = False):
    """Clean up pending tasks
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for pending tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()

    if not is_reporting_db_connected():
        return

    before_time = convert_into_time(timerange) if timerange else None

    with db.transaction():
        pending_tasks = [task.id for task in db.list_tasks(status=TASK_PENDING, added_before=before_time)]
    if delete:
        with db.transaction():
            db.delete_tasks(status=TASK_PENDING, added_before=before_time)
    else:
        resolver_pool.map(fail_job, pending_tasks)


def cuckoo_clean_range_tasks(range_: str):
    """Clean up tasks between range: 1-5
    It deletes all stored data from file system and configured databases (SQL
    and MongoDB for selected tasks.
    """
    # Init logging.
    # This need to init a console logger handler, because the standard
    # logger (init_logging()) logs to a file which will be deleted.
    create_structure()
    start_str, end_str = range_.split("-")
    start = int(start_str.strip())
    end = int(end_str.strip())
    with db.transaction():
        ids: list[int] = [task.id for task in db.list_tasks(id_after=(start - 1), id_before=(end + 1))]
    delete_bulk_tasks_n_folders(ids, delete_mongo=False)
    mongo_delete_data(ids)
    with db.transaction():
        db.delete_tasks(id_after=(start - 1), id_before=(end + 1))


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

    dist_session_maker = create_session(repconf.distributed.db, echo=False)
    hash_dict = {}
    stmt = (
        select(Sample.sha256, Task.id, Task.target)
        .join(Task, Sample.id == Task.sample_id)
        .where(Task.status == TASK_PENDING)
        .order_by(Sample.sha256)
    )
    with db.transaction():
        rows = db.session.execute(stmt).all()

    for sha256, task_id, target in rows:
        with suppress(UnicodeDecodeError):
            # hash -> [[id, file]]
            hash_dict.setdefault(sha256, []).append((task_id, target))

    resolver_pool.map(lambda sha256: dist_delete_data(hash_dict[sha256][1:], dist_session_maker), hash_dict)


def cape_clean_tlp():
    create_structure()

    if not is_reporting_db_connected():
        return

    with db.transaction():
        tlp_tasks = db.get_tlp_tasks()
    delete_bulk_tasks_n_folders(tlp_tasks, False)


def binaries_clean_before(timerange: str):
    # In case if "delete_bin_copy = off" we might need to clean binaries
    # find storage/binaries/ -name "*" -type f -mtime 5 -delete

    olden_than = convert_into_time(timerange)
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
            if datetime.fromtimestamp(st_ctime) < olden_than:
                # ToDo check database here to ensure that file is not used
                if not path_exists(bin_path):
                    continue
                with db.transaction():
                    still_used = db.sample_still_used(sha256, 0)
                if not still_used:
                    path_delete(bin_path)


def files_clean_before(timerange: str):
    """Remove unreferenced files in storage/files older than timerange and prune empty shard directories."""
    older_than = convert_into_time(timerange)
    files_folder = os.path.join(CUCKOO_ROOT, "storage", "files")
    if not path_exists(files_folder):
        log.error("Files folder doesn't exist")
        return

    files_folder_real = os.path.realpath(files_folder)
    referenced = set()
    if repconf.mongodb.enabled and is_reporting_db_connected():
        try:
            docs = mongo_find("files", {}, {"_id": 1, "sha256": 1})
            if docs:
                for doc in docs:
                    for key in ("sha256", "_id"):
                        val = doc.get(key)
                        if isinstance(val, str) and len(val) == 64:
                            referenced.add(val.lower())
        except Exception as e:
            log.error("Failed to fetch referenced files from MongoDB: %s", e)

    analyses_folder = os.path.join(CUCKOO_ROOT, "storage", "analyses")
    if path_exists(analyses_folder):
        for root, _, filenames in os.walk(analyses_folder):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                if not os.path.islink(fpath):
                    continue
                try:
                    target_real = os.path.realpath(fpath)
                    if os.path.commonpath([files_folder_real, target_real]) == files_folder_real:
                        referenced.add(os.path.basename(target_real).lower())
                except (OSError, ValueError):
                    continue

    deleted_count = 0
    for root, _, filenames in os.walk(files_folder, topdown=False):
        for sha256 in filenames:
            if sha256.startswith("."):
                continue
            file_path = os.path.join(root, sha256)
            if not os.path.exists(file_path):
                continue
            if sha256.lower() in referenced:
                continue
            try:
                latest_ts = max(path_get_date(file_path, "st_ctime"), path_get_date(file_path, "st_mtime"))
            except OSError:
                continue
            if datetime.fromtimestamp(latest_ts) < older_than:
                try:
                    path_delete(file_path)
                    deleted_count += 1
                except OSError as e:
                    log.error("Failed to delete file %s: %s", file_path, e)

        if root != files_folder:
            with suppress(OSError):
                os.rmdir(root)

    log.info("Cleaned %d unreferenced files from storage/files older than %s", deleted_count, timerange)


def cleanup_mongodb_calls_collection(args: dict):
    if not is_reporting_db_connected():
        return

    timerange = args.get("cleanup_mongo_calls")
    if not timerange:
        log.info("No time range argument provided bailing")
        return

    added_before = convert_into_time(timerange)
    with db.transaction():
        highest = db.list_tasks(added_before=added_before, limit=1)
        highest_id = highest[0].id if highest else None
    if highest_id:
        mongo_delete_calls_by_task_id_in_range(range_end=highest_id)


def cleanup_files_collection_by_id(task_id: int):
    """
    This function scans and pull out task_ids lower than task_id argument.
    It useful when admin had to do emergency cleanup directly using postgres/mongodb without cleaner
    """
    if not is_reporting_db_connected():
        return
    """
        db.files.updateMany({},{$pull: {"_task_ids": {$lt: 1280759}}})
        {
            acknowledged: true,
            insertedId: null,
            matchedCount: 1212950,
            modifiedCount: 1177791,
            upsertedCount: 0
        }
        db.runCommand({ compact: "files"})
        { bytesFreed: Long('107198922752'), ok: 1 }

    """
    mongo_update_many({"_task_ids": {"$lt": task_id}}, {"$pull": {"_task_ids": {"$lt": task_id}}})


def execute_cleanup(args: dict, init_log=True, isolate_errors: bool = False):
    global DB_BATCH_SIZE
    if args.get("db_batch_size"):
        DB_BATCH_SIZE = args["db_batch_size"]

    if init_log:
        init_console_logging()

    def _run_step(step_name: str, func, *step_args, **step_kwargs):
        if not isolate_errors:
            return func(*step_args, **step_kwargs)
        try:
            return func(*step_args, **step_kwargs)
        except Exception as e:
            log.error("Cleanup step '%s' failed: %s", step_name, e)
            return None

    # Run filesystem-only tmp cleanup first so low-space recovery does not stall on DB failures.
    if args.get("delete_tmp_items_older_than"):
        _run_step("tmp_clean_before", tmp_clean_before, args["delete_tmp_items_older_than"])

    if args.get("clean"):
        _run_step("cuckoo_clean", cuckoo_clean)

    if args.get("tlp"):
        _run_step("cape_clean_tlp", cape_clean_tlp)

    if args.get("failed_clean"):
        _run_step("cuckoo_clean_failed_tasks", cuckoo_clean_failed_tasks)

    if args.get("banned_clean"):
        _run_step("cuckoo_clean_banned_tasks", cuckoo_clean_banned_tasks)

    if args.get("failed_url_clean"):
        _run_step("cuckoo_clean_failed_url_tasks", cuckoo_clean_failed_url_tasks)

    if args.get("delete_older_than"):
        _run_step("cuckoo_clean_before", cuckoo_clean_before, args)

    if args.get("pcap_sorted_clean"):
        _run_step("cuckoo_clean_sorted_pcap_dump", cuckoo_clean_sorted_pcap_dump)

    if args.get("bson_suri_logs_clean"):
        _run_step("cuckoo_clean_bson_suri_logs", cuckoo_clean_bson_suri_logs)

    if args.get("pending_clean"):
        _run_step("cuckoo_clean_pending_tasks", cuckoo_clean_pending_tasks, args["time_range"])

    if args.get("malscore"):
        _run_step("cuckoo_clean_lower_score", cuckoo_clean_lower_score, args["malscore"])

    if args.get("delete_range"):
        _run_step("cuckoo_clean_range_tasks", cuckoo_clean_range_tasks, args["delete_range"])

    if args.get("deduplicated_cluster_queue"):
        _run_step("cuckoo_dedup_cluster_queue", cuckoo_dedup_cluster_queue)

    if args.get("delete_binaries_items_older_than"):
        _run_step("binaries_clean_before", binaries_clean_before, args["delete_binaries_items_older_than"])

    if args.get("delete_unused_file_data_in_mongo"):
        _run_step("delete_unused_file_data_in_mongo", delete_unused_file_data_in_mongo)

    if args.get("delete_files_items_older_than"):
        if repconf.mongodb.enabled and not args.get("delete_unused_file_data_in_mongo"):
            _run_step("delete_unused_file_data_in_mongo", delete_unused_file_data_in_mongo)
        _run_step("files_clean_before", files_clean_before, args["delete_files_items_older_than"])

    if args.get("cleanup_files_collection_by_id"):
        _run_step("cleanup_files_collection_by_id", cleanup_files_collection_by_id, args["cleanup_files_collection_by_id"])

    if args.get("cleanup_mongo_calls"):
        _run_step("cleanup_mongodb_calls_collection", cleanup_mongodb_calls_collection, args)


# Example Usage:
if __name__ == "__main__":
    try:
        past_time_1 = convert_into_time("12h")
        print(f"12 hours ago: {past_time_1}")

        past_time_2 = convert_into_time("1d")
        print(f"1 day ago: {past_time_2}")

        past_time_3 = convert_into_time("5m")
        print(f"5 minutes ago: {past_time_3}")

        past_time_4 = convert_into_time("30s")
        print(f"30 seconds ago: {past_time_4}")

        # Example of invalid input
        convert_into_time("invalid")
    except ValueError as e:
        print(f"Error: {e}")
