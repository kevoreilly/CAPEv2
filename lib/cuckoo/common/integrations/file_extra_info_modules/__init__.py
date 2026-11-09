import contextlib
import functools
import logging
import os
import shlex
import subprocess
import tempfile
import timeit
from typing import List, Optional, TypedDict

from lib.cuckoo.common.path_utils import path_mkdir, path_object
from lib.cuckoo.common.utils import get_cape_external_dir

log = logging.getLogger(__name__)


class SuccessfulExtractionReturnType(TypedDict, total=False):
    tempdir: str
    extracted_files: List[str]
    tool_name: str


ExtractorReturnType = Optional[SuccessfulExtractionReturnType]


def _sanitize_surrogate_str(value: str) -> str:
    return value.encode("utf-8", errors="replace").decode("utf-8")


def _collision_safe_destination(source: str, destination: str, is_directory: bool = False) -> str:
    if source == destination or not os.path.lexists(destination):
        return destination

    parent, name = os.path.split(destination)
    if is_directory:
        stem, extension = name, ""
    else:
        stem, extension = os.path.splitext(name)

    suffix = 1
    while True:
        candidate = os.path.join(parent, f"{stem} ({suffix}){extension}")
        if not os.path.lexists(candidate):
            return candidate
        suffix += 1


def collect_extracted_filenames(tempdir):
    """Gather files using UTF-8-safe, collision-free relative paths."""
    extracted_files = []
    for root, dirs, files in os.walk(tempdir, topdown=True):
        for idx, dirname in enumerate(dirs):
            clean_dirname = _sanitize_surrogate_str(dirname)
            if clean_dirname != dirname:
                src_dir = os.path.join(root, dirname)
                dst_dir = _collision_safe_destination(
                    src_dir, os.path.join(root, clean_dirname), is_directory=True
                )
                try:
                    os.replace(src_dir, dst_dir)
                    dirs[idx] = os.path.basename(dst_dir)
                except OSError:
                    pass
        for file in files:
            clean_file = _sanitize_surrogate_str(file)
            full_path = os.path.join(root, file)
            if clean_file != file:
                clean_full_path = _collision_safe_destination(full_path, os.path.join(root, clean_file))
                try:
                    os.replace(full_path, clean_full_path)
                    full_path = clean_full_path
                except OSError:
                    pass
            path = path_object(full_path)
            if path.is_file():
                extracted_files.append(_sanitize_surrogate_str(str(path.relative_to(tempdir))))
    return extracted_files


def time_tracker(func):
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        time_start = timeit.default_timer()
        result = func(*args, **kwargs)
        return {
            "result": result,
            "took_seconds": timeit.default_timer() - time_start,
        }

    return wrapped


@contextlib.contextmanager
def extractor_ctx(filepath, tool_name, prefix=None, folder=None):
    folder = folder or get_cape_external_dir()
    path_mkdir(folder, exist_ok=True)

    tempdir = tempfile.mkdtemp(prefix=prefix, dir=folder)
    retval = {"tempdir": tempdir}
    try:
        yield retval
    except subprocess.CalledProcessError as err:
        log.error(
            "%s: Failed to extract files from %s: cmd=`%s`, stdout=`%s`, stderr=`%s`",
            tool_name,
            filepath,
            shlex.join(err.cmd),
            err.stdout,
            err.stderr,
        )
    except Exception:
        log.exception("Exception was raised while attempting to use %s on %s", tool_name, filepath)
    else:
        if retval.get("extracted_files", []):
            retval["tool_name"] = tool_name
        else:
            retval.pop("extracted_files", None)
