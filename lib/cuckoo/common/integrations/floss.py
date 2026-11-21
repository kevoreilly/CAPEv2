import contextlib
import hashlib
import logging
import mmap
import os.path
from pathlib import Path
import time

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.process_timeout import (
    ResultUnavailableError,
    get_cached_task_result,
    mark_budget_warned,
    record_task_budget_elapsed,
    resolve_call_timeout,
    run_with_timeout,
    set_cached_task_result,
)

integrations_conf = Config("integrations")

HAVE_FLOSS = False
try:
    import floss.main as fm
    from floss.strings import extract_ascii_unicode_strings

    HAVE_FLOSS = True
except ImportError:
    print("Missed dependency flare-floss: uv pip install -U flare-floss")

log = logging.getLogger(__name__)


def _file_sha256(file_path: str) -> str:
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return ""


def _run_floss_analysis(
    file_path: str,
    package: str,
    min_length: int,
    static_strings: bool,
    stack_strings: bool,
    tight_strings: bool,
    decoded_strings: bool,
    sigs_path: str,
) -> dict:
    """Run FLOSS extraction in the current process (intended for isolated execution)."""
    if not HAVE_FLOSS:
        return {}

    results: dict = {}
    log_configured = False
    try:
        if not fm.is_supported_file_type(Path(file_path)):
            if package == "shellcode":
                fileformat = "sc32"
            elif package == "shellcode_x64":
                fileformat = "sc64"
            else:
                return results
        else:
            fileformat = "pe"

        fm.set_log_config(fm.DebugLevel.NONE, True)
        log_configured = True
        tmpres: dict = {}

        if static_strings:
            with open(file_path, "rb") as f:
                with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                    tmpres["static_strings"] = list(extract_ascii_unicode_strings(buf, min_length))

        resolved_sigs = sigs_path if os.path.isabs(sigs_path) else os.path.join(CUCKOO_ROOT, sigs_path)
        sigspath = fm.get_signatures(Path(resolved_sigs))
        vw = fm.load_vw(Path(file_path), fileformat, sigspath, False)

        try:
            selected_functions = fm.select_functions(vw, None)
        except ValueError as e:
            # failed to find functions in workspace
            print(e.args[0])
            return results

        decoding_function_features, _library_functions = fm.find_decoding_function_features(
            vw,
            selected_functions,
            True,
        )

        if stack_strings:
            selected_functions = fm.get_functions_without_tightloops(decoding_function_features)
            tmpres["stack_strings"] = fm.extract_stackstrings(
                vw,
                selected_functions,
                min_length,
                verbosity=False,
                disable_progress=True,
            )

        if tight_strings:
            tightloop_functions = fm.get_functions_with_tightloops(decoding_function_features)
            tmpres["tight_strings"] = fm.extract_tightstrings(
                vw,
                tightloop_functions,
                min_length=min_length,
                verbosity=False,
                disable_progress=True,
            )

        if decoded_strings:
            top_functions = fm.get_top_functions(decoding_function_features, 20)
            fvas_to_emulate = fm.get_function_fvas(top_functions)
            fvas_tight_functions = fm.get_tight_function_fvas(decoding_function_features)
            fvas_to_emulate = fm.append_unique(fvas_to_emulate, fvas_tight_functions)

            tmpres["decoded_strings"] = fm.decode_strings(
                vw,
                fvas_to_emulate,
                min_length,
                verbosity=False,
                disable_progress=True,
            )

        for stype in tmpres.keys():
            if tmpres[stype]:
                results[stype] = []
            for sval in tmpres[stype]:
                results[stype].append(sval.string)

    except MemoryError:
        log.warning("FLOSS -> MemoryError on %s", file_path)
        results = {}
    except Exception as e:
        log.exception(e)
    finally:
        if log_configured:
            fm.set_log_config(fm.DebugLevel.DEFAULT, False)

    return results


def _is_supported_floss_input(file_path: str, package: str) -> bool:
    """Cheap parent-side file-type check to avoid spawning a FLOSS child on unsupported files."""
    if package in ("shellcode", "shellcode_x64"):
        return True
    floss_main = globals().get("fm")
    if floss_main is None or not hasattr(floss_main, "is_supported_file_type"):
        return True
    try:
        return bool(floss_main.is_supported_file_type(Path(file_path)))
    except Exception:
        return False


class Floss:
    """Extract strings from sample using FLOSS."""

    def __init__(self, filepath: str, package: str, on_demand: bool = False):
        self.file_path = filepath
        self.package = package
        self.on_demand = on_demand

    def run(self):
        """Run FLOSS to extract strings from sample.
        @return: dictionary of floss strings.
        """

        if not HAVE_FLOSS:
            return

        if integrations_conf.floss.on_demand and not self.on_demand:
            return

        if not path_exists(self.file_path):
            log.error("Sample file doesn't exist: %s", self.file_path)
            return

        cache_key = ""
        if not self.on_demand:
            sha256 = _file_sha256(self.file_path)
            if sha256:
                cache_key = f"{sha256}:{self.package}"
                hit, cached = get_cached_task_result("floss", cache_key)
                if hit:
                    return cached

        if not _is_supported_floss_input(self.file_path, self.package):
            if cache_key:
                set_cached_task_result("floss", cache_key, {})
            return {}

        if self.on_demand:
            call_timeout = float(integrations_conf.floss.get("on_demand_timeout", 180) or 0)
        else:
            task_cap = integrations_conf.floss.get("task_timeout", 180)
            call_timeout = resolve_call_timeout(
                "floss",
                integrations_conf.floss.get("timeout", 60),
                task_cap,
            )
            if call_timeout < 0:
                if mark_budget_warned("floss"):
                    log.warning(
                        "FLOSS -> per-task budget (%ss) exhausted, skipping remaining files",
                        task_cap,
                    )
                return {}

        min_length = int(integrations_conf.floss.get("min_length", 5) or 5)
        static_strings = bool(integrations_conf.floss.get("static_strings", False))
        stack_strings = bool(integrations_conf.floss.get("stack_strings", True))
        tight_strings = bool(integrations_conf.floss.get("tight_strings", True))
        decoded_strings = bool(integrations_conf.floss.get("decoded_strings", True))
        sigs_path = str(integrations_conf.floss.get("sigs_path", "data/flare-signatures") or "data/flare-signatures")

        results: dict = {}
        t0 = time.monotonic()
        try:
            results = run_with_timeout(
                _run_floss_analysis,
                call_timeout,
                self.file_path,
                self.package,
                min_length,
                static_strings,
                stack_strings,
                tight_strings,
                decoded_strings,
                sigs_path,
            )
        except TimeoutError:
            log.warning("FLOSS -> timed out after %ss on %s, skipping (partial results)", call_timeout, self.file_path)
            results = {}
        except ResultUnavailableError:
            log.warning("FLOSS -> analysis process terminated unexpectedly on %s, skipping (partial results)", self.file_path)
            results = {}
        except Exception as e:
            log.exception(e)
            results = {}
        finally:
            if not self.on_demand:
                record_task_budget_elapsed("floss", time.monotonic() - t0)

        if cache_key:
            set_cached_task_result("floss", cache_key, results)

        return results
