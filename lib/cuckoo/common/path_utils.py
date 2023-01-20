import os
from pathlib import Path, PureWindowsPath
from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH


def path_delete(path: str):
    Path(path).unlink()


def path_mkdir(path: str, parent: bool = True):
    Path(path_to_ascii(path)).mkdir(parents=parent)


def path_safe(path: str) -> bool:
    # Path(path).resolve(string=True) # FileNotFoundError
    return os.path.normpath(path).startswith(ANALYSIS_BASE_PATH)


def path_exists(path: str, windows: bool = False) -> bool:
    if not windows:
        return Path(path_to_ascii(path)).exists()
    else:
        return PureWindowsPath(path_to_ascii(path)).exists()


def path_to_ascii(path: bytes):
    return path.decode() if isinstance(path, bytes) else path


def path_get_size(file: str):
    return Path(path_to_ascii(file)).stat().st_size
