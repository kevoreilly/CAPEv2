# Copyright (C) 2023 doomedraven

from pathlib import Path, PureWindowsPath

from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH


def path_to_ascii(path: bytes):
    return path.decode() if isinstance(path, bytes) else path


def path_get_filename(path):
    """Cross-platform filename extraction from path.
    @param path: file path.
    @return: filename.
    """
    return PureWindowsPath(path_to_ascii(path)).name


def path_delete(path: str):
    Path(path).unlink()


def path_mkdir(path: str, parent: bool = True, exist_ok=False, mode=0o755):
    Path(path_to_ascii(path)).mkdir(parents=parent, exist_ok=exist_ok, mode=mode)


def path_safe(path: str) -> bool:
    try:
        return str(Path(path).resolve(strict=True)).startswith(ANALYSIS_BASE_PATH)
    except FileNotFoundError:
        return False


def path_exists(path: str, windows: bool = False) -> bool:
    if not windows:
        return Path(path_to_ascii(path)).exists()
    return PureWindowsPath(path_to_ascii(path)).exists()


def path_get_size(path: str):
    return Path(path_to_ascii(path)).stat().st_size


def path_is_file(path: str) -> bool:
    return Path(path_to_ascii(path)).is_file()


def path_is_dir(path: str) -> bool:
    return Path(path_to_ascii(path)).is_dir()


def path_read_file(path: str, mode="bytes"):
    if mode == "bytes":
        return Path(path_to_ascii(path)).read_bytes()
    return Path(path_to_ascii(path)).read_text()


def path_write_file(path: str, content, mode="bytes"):
    if mode == "bytes":
        return Path(path_to_ascii(path)).write_bytes(content)
    return Path(path_to_ascii(path)).write_text(content)


def path_cwd():
    return Path().cwd()


def path_mount_point(path: str):
    return Path(path_to_ascii(path)).is_mount()
