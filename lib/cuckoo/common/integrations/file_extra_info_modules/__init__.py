import contextlib
import functools
import logging
import os
import shlex
import subprocess
import tempfile
import timeit
from typing import List, Optional, TypedDict

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_mkdir, path_object

cfg = Config()
log = logging.getLogger()


class SuccessfulExtractionReturnType(TypedDict, total=False):
    tempdir: str
    extracted_files: List[str]
    tool_name: str


ExtractorReturnType = Optional[SuccessfulExtractionReturnType]


def collect_extracted_filenames(tempdir):
    """Gather a list of files relative to the given directory."""
    extracted_files = []
    for root, _, files in os.walk(tempdir):
        for file in files:
            path = path_object(os.path.join(root, file))
            if path.is_file():
                extracted_files.append(str(path.relative_to(tempdir)))
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
def extractor_ctx(filepath, tool_name, prefix=None):
    folder = os.path.join(cfg.cuckoo.get("tmppath", "/tmp"), "cape-external")
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
