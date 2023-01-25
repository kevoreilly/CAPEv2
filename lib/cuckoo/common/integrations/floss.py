import contextlib
import logging
import mmap
import os.path

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists

processing_cfg = Config("processing")

HAVE_FLOSS = False
try:
    HAVE_FLOSS = True
    import floss.main as fm
except ImportError:
    print("Missed dependency flare-floss: pip3 install -U flare-floss")

log = logging.getLogger(__name__)


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

        if not HAVE_FLOSS or processing_cfg.floss.on_demand and not self.on_demand:
            return

        results = {}

        if not path_exists(self.file_path):
            log.error("Sample file doesn't exist: %s", self.file_path)

        try:
            if not fm.is_supported_file_type(self.file_path):
                if self.package == "Shellcode":
                    fileformat = "sc32"
                elif self.package == "Shellcode_x64":
                    fileformat = "sc64"
                else:
                    return results
            else:
                fileformat = "pe"

            min_length = processing_cfg.floss.min_length
            fm.set_log_config(fm.DebugLevel.NONE, True)
            tmpres = {}
            results = {}

            if processing_cfg.floss.static_strings:
                with open(self.file_path, "rb") as f:
                    with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
                        tmpres["static_strings"] = list(fm.extract_ascii_unicode_strings(buf, min_length))

            sigspath = fm.get_signatures(os.path.join(CUCKOO_ROOT, processing_cfg.floss.sigs_path))
            vw = fm.load_vw(self.file_path, fileformat, sigspath, False)

            try:
                selected_functions = fm.select_functions(vw, None)
            except ValueError as e:
                # failed to find functions in workspace
                print(e.args[0])
                return

            decoding_function_features, library_functions = fm.find_decoding_function_features(
                vw,
                selected_functions,
                True,
            )

            if processing_cfg.floss.stack_strings:
                selected_functions = fm.get_functions_without_tightloops(decoding_function_features)
                tmpres["stack_strings"] = fm.extract_stackstrings(
                    vw,
                    selected_functions,
                    min_length,
                    verbosity=False,
                    disable_progress=True,
                )

            if processing_cfg.floss.tight_strings:
                tightloop_functions = fm.get_functions_with_tightloops(decoding_function_features)
                tmpres["tight_strings"] = fm.extract_tightstrings(
                    vw,
                    tightloop_functions,
                    min_length=min_length,
                    verbosity=False,
                    disable_progress=True,
                )

            if processing_cfg.floss.decoded_strings:
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

        except Exception as e:
            log.error(e, exc_info=True)

        fm.set_log_config(fm.DebugLevel.DEFAULT, False)

        return results
