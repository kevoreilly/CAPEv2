# Copyright (C) 2023 doomedraven

import contextlib
import os
import threading
from pathlib import Path, PureWindowsPath

from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH

try:
    import magic

    HAVE_MAGIC = True
except ImportError:
    magic = None
    HAVE_MAGIC = False

_MAGIC_LOCK = threading.Lock()
_FILE_MAGIC_HANDLE = None
_FILE_MAGIC_MIME_HANDLE = None


def _preload_magic():
    global _FILE_MAGIC_HANDLE, _FILE_MAGIC_MIME_HANDLE
    if not HAVE_MAGIC:
        return
    if hasattr(magic, "_get_magic_type"):
        with contextlib.suppress(Exception):
            magic._get_magic_type(False)
            magic._get_magic_type(True)
    elif hasattr(magic, "open"):
        with contextlib.suppress(Exception):
            ms = magic.open(getattr(magic, "MAGIC_SYMLINK", 0))
            ms.load()
            _FILE_MAGIC_HANDLE = ms
        with contextlib.suppress(Exception):
            ms_mime = magic.open(getattr(magic, "MAGIC_MIME", 0) | getattr(magic, "MAGIC_SYMLINK", 0))
            ms_mime.load()
            _FILE_MAGIC_MIME_HANDLE = ms_mime


_preload_magic()


def _magic_descriptor_fallback(data: bytes, mime: bool = False, magic_mod=None, ms_handle=None):
    if not hasattr(os, "memfd_create"):
        return None
    fd = -1
    try:
        fd = os.memfd_create("cape_magic", 0)
        os.write(fd, data)
        os.lseek(fd, 0, os.SEEK_SET)
        if ms_handle is not None and hasattr(ms_handle, "descriptor"):
            with _MAGIC_LOCK:
                return ms_handle.descriptor(fd)
        if magic_mod is not None and hasattr(magic_mod, "from_descriptor"):
            return magic_mod.from_descriptor(fd, mime=mime) if mime else magic_mod.from_descriptor(fd)
    except Exception:
        return None
    finally:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)
    return None


def magic_from_buffer(data: bytes, mime: bool = False, magic_module=None):
    mod = magic if magic_module is None else magic_module
    if mod is None or not data:
        return None

    file_type = None
    if hasattr(mod, "from_buffer"):
        try:
            file_type = mod.from_buffer(data, mime=mime) if mime else mod.from_buffer(data)
        except Exception:
            file_type = None
        if file_type in (None, "", "data", "application/octet-stream"):
            fd_res = _magic_descriptor_fallback(data, mime=mime, magic_mod=mod)
            if fd_res:
                file_type = fd_res
        if file_type:
            return file_type

    if hasattr(mod, "open"):
        ms = (_FILE_MAGIC_MIME_HANDLE if mime else _FILE_MAGIC_HANDLE) if mod is magic else None
        own_ms = False
        try:
            if ms is None:
                flags = getattr(mod, "MAGIC_SYMLINK", 0)
                if mime:
                    flags |= getattr(mod, "MAGIC_MIME", 0)
                ms = mod.open(flags)
                ms.load()
                own_ms = True
            with _MAGIC_LOCK:
                file_type = ms.buffer(data)
            if file_type in (None, "", "data", "application/octet-stream"):
                fd_res = _magic_descriptor_fallback(data, mime=mime, ms_handle=ms)
                if fd_res:
                    file_type = fd_res
        except Exception:
            file_type = None
        finally:
            if own_ms and ms is not None:
                with contextlib.suppress(Exception):
                    ms.close()
    return file_type


def magic_from_file(filepath, mime: bool = False, magic_module=None):
    mod = magic if magic_module is None else magic_module
    if mod is None or not filepath:
        return None

    if hasattr(mod, "from_file"):
        try:
            file_type = mod.from_file(filepath, mime=mime) if mime else mod.from_file(filepath)
            if file_type:
                return file_type
        except Exception:
            pass

    if hasattr(mod, "open"):
        ms = (_FILE_MAGIC_MIME_HANDLE if mime else _FILE_MAGIC_HANDLE) if mod is magic else None
        own_ms = False
        try:
            if ms is None:
                flags = getattr(mod, "MAGIC_SYMLINK", 0)
                if mime:
                    flags |= getattr(mod, "MAGIC_MIME", 0)
                ms = mod.open(flags)
                ms.load()
                own_ms = True
            path_str = filepath.decode("utf-8", "replace") if isinstance(filepath, bytes) else filepath
            with _MAGIC_LOCK:
                return ms.file(path_str)
        except Exception:
            return None
        finally:
            if own_ms and ms is not None:
                with contextlib.suppress(Exception):
                    ms.close()
    return None


def path_to_ascii(path: bytes):
    return path.decode() if isinstance(path, bytes) else path


def path_object(path: bytes):
    return Path(path_to_ascii(path))


def path_get_filename(path):
    """Cross-platform filename extraction from path.
    @param path: file path.
    @return: filename.
    """
    return PureWindowsPath(path_to_ascii(path)).name


def path_delete(path: str):
    Path(path_to_ascii(path)).unlink()


def path_mkdir(path: str, parent: bool = True, exist_ok=False, mode=0o755):
    Path(path_to_ascii(path)).mkdir(parents=parent, exist_ok=exist_ok, mode=mode)


def path_safe(path: str) -> bool:
    try:
        return str(Path(path).resolve(strict=True)).startswith(ANALYSIS_BASE_PATH)
    except FileNotFoundError:
        return False


def path_exists(path: str, windows: bool = False) -> bool:
    try:
        if not windows:
            return Path(path_to_ascii(path)).exists()
        return PureWindowsPath(path_to_ascii(path)).exists()
    except (OSError, ValueError):
        return False


def path_get_size(path: str):
    return Path(path_to_ascii(path)).stat().st_size


def path_get_date(path: str, value: str = "st_ctime"):
    return getattr(Path(path_to_ascii(path)).stat(), value)


def path_is_file(path: str) -> bool:
    try:
        return Path(path_to_ascii(path)).is_file()
    except (OSError, ValueError):
        return False


def path_is_dir(path: str) -> bool:
    try:
        return Path(path_to_ascii(path)).is_dir()
    except (OSError, ValueError):
        return False


def path_read_file(path: str, mode="bytes"):
    if mode == "bytes":
        return Path(path_to_ascii(path)).read_bytes()
    return Path(path_to_ascii(path)).read_text()


def path_write_file(path: str, content, mode="bytes"):
    if mode == "bytes":
        return Path(path_to_ascii(path)).write_bytes(content)
    return Path(path_to_ascii(path)).write_text(content)


def path_cwd():
    return Path.cwd()


def path_mount_point(path: str):
    return Path(path_to_ascii(path)).is_mount()
