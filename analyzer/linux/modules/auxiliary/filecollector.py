import ctypes
import errno
import hashlib
import logging
import os
import select
import struct
import sys
import time
from threading import Event, Thread

from lib.common.abstracts import Auxiliary
from lib.common.constants import ROOT
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)
DELAY = 1
BUFSIZE = 1024 * 1024

# Linux <sys/inotify.h> event masks
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_IGNORED = 0x00008000
IN_DONT_FOLLOW = 0x02000000
IN_ISDIR = 0x40000000

_WATCH_MASK = IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DONT_FOLLOW
_EVENT_HEADER = struct.Struct("=iIII")
_POLL_TIMEOUT_SEC = 0.5
_STOP_DELAY_SEC = 2
_READ_BUF_SIZE = 65536

_DEFAULT_IGNORED_ROOT_DIRS = frozenset(
    {
        "proc",
        "sys",
        "usr",  # just too many dirs here
        "dev",
        "var",  # we don't want to collect log files
        "lib",
        "lib64",
        # "sbin",
        # "etc",
        "run",  # lots of spurious files
        # "bin",
        # "boot",
        # "media",
        # "srv"
    }
)
_NOISY_CONTENT = ("sysmon", "gvfs-metadata")


def _load_inotify_libc():
    """Load libc inotify functions on Linux without requiring third-party packages."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        init1 = libc.inotify_init1
        init1.argtypes = [ctypes.c_int]
        init1.restype = ctypes.c_int
        add_watch = libc.inotify_add_watch
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add_watch.restype = ctypes.c_int
        return libc
    except (AttributeError, OSError) as err:
        log.warning("Unable to initialize Linux inotify via libc: %s", err)
        return None


_LIBC = _load_inotify_libc()
HAVE_INOTIFY = _LIBC is not None


class NativeInotifyWatcher:
    """Minimal stdlib-only Linux inotify watcher (Python 3.10–3.14+ compatible)."""

    def __init__(self):
        if _LIBC is None:
            raise OSError(errno.ENOSYS, "Linux inotify is unavailable on this platform")
        flags = getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = _LIBC.inotify_init1(flags)
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        self._fd = fd
        self._wd_to_path = {}
        self._path_to_wd = {}

    def add_watch(self, path, mask=_WATCH_MASK, rec=False):
        """Watch a directory (and optionally its existing subdirectories)."""
        if self._fd < 0:
            return
        abs_path = os.path.abspath(path)
        if os.path.islink(abs_path):
            return
        self._add_single_watch(abs_path, mask)
        if not rec:
            return
        for dirpath, dirnames, _ in os.walk(abs_path, followlinks=False):
            for dirname in list(dirnames):
                subpath = os.path.join(dirpath, dirname)
                if os.path.islink(subpath) or not self._add_single_watch(subpath, mask):
                    dirnames.remove(dirname)

    def _add_single_watch(self, abs_path, mask):
        if os.path.islink(abs_path):
            return False
        if abs_path in self._path_to_wd:
            return True
        wd = _LIBC.inotify_add_watch(self._fd, os.fsencode(abs_path), mask | IN_DONT_FOLLOW)
        if wd < 0:
            err = ctypes.get_errno()
            if err not in (errno.ENOENT, errno.ENOTDIR, errno.EACCES, errno.ELOOP):
                log.debug("inotify_add_watch failed for %s: %s", abs_path, os.strerror(err))
            return False
        old_path = self._wd_to_path.get(wd)
        if old_path is not None and old_path != abs_path:
            self._path_to_wd.pop(old_path, None)
        self._wd_to_path[wd] = abs_path
        self._path_to_wd[abs_path] = wd
        return True

    def read_events(self, timeout=_POLL_TIMEOUT_SEC, mask=_WATCH_MASK):
        """Poll for pending inotify events and return (mask, pathname) pairs."""
        if self._fd < 0:
            return []
        try:
            ready, _, _ = select.select([self._fd], [], [], timeout)
        except (OSError, ValueError):
            return []
        if not ready:
            return []

        try:
            data = os.read(self._fd, _READ_BUF_SIZE)
        except (BlockingIOError, InterruptedError):
            return []
        except OSError as err:
            if err.errno not in (errno.EAGAIN, errno.EINTR, errno.EBADF):
                log.debug("Error reading inotify fd: %s", err)
            return []

        events = []
        offset = 0
        total = len(data)
        while offset + _EVENT_HEADER.size <= total:
            wd, ev_mask, _cookie, name_len = _EVENT_HEADER.unpack_from(data, offset)
            offset += _EVENT_HEADER.size
            raw_name = data[offset : offset + name_len].split(b"\x00", 1)[0]
            offset += name_len

            base_path = self._wd_to_path.get(wd)
            if ev_mask & IN_IGNORED:
                removed = self._wd_to_path.pop(wd, None)
                if removed is not None:
                    self._path_to_wd.pop(removed, None)
                continue

            if base_path is None:
                continue

            if raw_name:
                pathname = os.path.join(base_path, os.fsdecode(raw_name))
            else:
                pathname = base_path

            if (ev_mask & IN_ISDIR) and (ev_mask & (IN_CREATE | IN_MOVED_TO)) and not os.path.islink(pathname):
                self.add_watch(pathname, mask=mask, rec=True)
                # Catch files created inside the new directory before its watch attached.
                for dirpath, dirnames, filenames in os.walk(pathname, followlinks=False):
                    dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
                    self._add_single_watch(dirpath, mask)
                    for filename in filenames:
                        events.append((IN_CREATE, os.path.join(dirpath, filename)))

            events.append((ev_mask, pathname))
        return events

    def close(self):
        fd = self._fd
        self._fd = -1
        self._wd_to_path.clear()
        self._path_to_wd.clear()
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


class FileCollector(Auxiliary):
    """Gets files."""

    def start(self):
        if not self.enabled:
            return False

        self.do_collect = True

    def stop(self):
        if not self.enabled:
            return False

        if _STOP_DELAY_SEC > 0:
            time.sleep(_STOP_DELAY_SEC)  # wait a while to process stuff in the queue
        self.do_run = False
        if self.thread is not None:
            self.thread.join(timeout=5)

    def __init__(self, options, config, watch_roots=None):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.filecollector
        self.do_run = bool(self.enabled and HAVE_INOTIFY)
        self.do_collect = False
        self.uploaded_hashes = set()
        self._watch_roots = watch_roots
        self._init_event = Event()
        self.initComplete = False
        self.thread = None
        if self.enabled:
            self.thread = Thread(target=self.run, daemon=True)
            self.thread.start()
            while not self._init_event.wait(0.5):
                if not self.thread.is_alive():
                    break
            self.initComplete = True

    def _setup_watches(self, watcher):
        if self._watch_roots is not None:
            for root_dir in self._watch_roots:
                watcher.add_watch(root_dir, _WATCH_MASK, rec=True)
            return

        watch_this = os.path.abspath("/")
        watcher.add_watch(watch_this, _WATCH_MASK, rec=False)

        for filename in os.listdir("/"):
            root_entry = f"/{filename}"
            if os.path.isdir(root_entry) and not os.path.islink(root_entry) and filename not in _DEFAULT_IGNORED_ROOT_DIRS:
                log.info("FileCollector trying to watch dir %s", filename)
                watch_this = os.path.abspath(root_entry)
                watcher.add_watch(watch_this, _WATCH_MASK, rec=True)

    def _process_path(self, pathname):
        try:
            if not self.do_collect:
                return

            if pathname.startswith(ROOT):
                return

            if pathname.startswith("/tmp/#"):
                return

            if not os.path.isfile(pathname):
                return

            if "strace.log" in os.path.basename(pathname):
                return

            if any(noisy in pathname for noisy in _NOISY_CONTENT):
                return

            try:
                sha256 = hash_file(hashlib.sha256, pathname)
                if sha256 in self.uploaded_hashes:
                    return
                upload_path = os.path.join("files", sha256)
                upload_to_host(pathname, upload_path)
                self.uploaded_hashes.add(sha256)
                return
            except Exception as e:
                log.info('Error dumping file from path "%s": %s', pathname, e)

            time.sleep(1)
        except Exception as e:
            log.error("Exception processing event %s", e)

    def run(self):
        watcher = None
        try:
            if not HAVE_INOTIFY:
                log.warning("Linux inotify is unavailable; FileCollector is disabled")
                return False

            log.info("FileCollector run started")
            watcher = NativeInotifyWatcher()
            self._setup_watches(watcher)
            log.info("FileCollector setup complete")
        except Exception as e:
            log.error("FileCollector setup failed: %s", e)
            if watcher is not None:
                watcher.close()
            return False
        finally:
            self.initComplete = True
            self._init_event.set()

        try:
            while self.do_run:
                for ev_mask, pathname in watcher.read_events(timeout=_POLL_TIMEOUT_SEC):
                    if ev_mask & IN_ISDIR:
                        continue
                    self._process_path(pathname)
        except Exception as e:
            log.error("Exception in loop %s", e)
        finally:
            watcher.close()

        log.info("FileCollector run completed")
        return True
