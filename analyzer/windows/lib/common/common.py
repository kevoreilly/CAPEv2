import ctypes
import logging
import os
import sys
from ctypes import POINTER, wintypes
from ctypes.wintypes import BOOL, HANDLE
from functools import wraps

log = logging.getLogger(__name__)


def check_file_extension(path: str, ext: str) -> str:
    # Check file extension.
    # If the file doesn't have the proper extension force it and rename it.
    if os.path.splitext(path)[-1].lower() != ext:
        os.rename(path, f"{path}{ext}")
        log.info("Submitted file is missing extension, adding %s", ext)
        return path + ext
    return path


def disable_wow64_redirection(func):
    if os.name == "nt" and sys.maxsize == 2**31 - 1:
        log.info("disable_wow64_redirection")
        kernel32 = ctypes.windll.kernel32

        Wow64DisableWow64FsRedirection = kernel32.Wow64DisableWow64FsRedirection
        Wow64DisableWow64FsRedirection.restype = BOOL
        Wow64DisableWow64FsRedirection.argtypes = [POINTER(HANDLE)]

        Wow64RevertWow64FsRedirection = kernel32.Wow64RevertWow64FsRedirection
        Wow64RevertWow64FsRedirection.restype = BOOL
        Wow64RevertWow64FsRedirection.argtypes = [HANDLE]
    else:
        log.info("wow64_redirection")

    @wraps(func)
    def wrapper(*args, **kwargs):
        if os.name == "nt" and sys.maxsize == 2**31 - 1:
            log.info("wrapping")
            old_value = wintypes.HANDLE()
            Wow64DisableWow64FsRedirection(ctypes.byref(old_value))

            result = func(*args, **kwargs)

            Wow64RevertWow64FsRedirection(old_value)
            return result
        else:
            log.info("no wrapping")
            return func(*args, **kwargs)

    return wrapper
