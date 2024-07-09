import os
import time

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import MSOFFICE_TRUSTED_PATH, TRUSTED_PATH_TEXT
from lib.common.exceptions import CuckooPackageError


class DOC_ANTIVM(Package):
    """Word analysis package, with anti-VM technique prevention."""

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ]
    default_curdir = MSOFFICE_TRUSTED_PATH
    summary = "Open a document file with WINWORD.EXE."
    description = f"""Use 'WINWORD.EXE <sample> /q', or if unavailable, 'WORDVIEW.EXE <sample> /q'.
    {TRUSTED_PATH_TEXT}
    First start up 20 calc.exe windows, and other standard applications, to thwart some antivm measures.
    The .doc filename extension will be added automatically."""

    def start(self, path):
        # Determine if the submitter wants the sample to be monitored
        free = self.options.get("free", False)

        # We will be temporarily setting this option so that the background processes will not be monitored.
        self.options["free"] = 1

        # First, start 20 Calculator windows
        for _ in range(20):
            calc = os.path.join("C:\\windows", "system32", "calc.exe")
            self.execute(calc, "", path)

        # Next, open a bunch of standard applications
        bnr = os.path.join("C:\\windows", "system32", "control.exe")
        self.execute(bnr, "/name Microsoft.BackupAndRestore", path)

        # sync center
        mobs = os.path.join("C:\\windows", "system32", "mobsync.exe")
        self.execute(mobs, "", path)

        # rdp
        rdp = os.path.join("C:\\windows", "system32", "mstsc.exe")
        self.execute(rdp, "", path)

        # char map
        chrm = os.path.join("C:\\windows", "system32", "charmap.exe")
        self.execute(chrm, "", path)

        # paint
        paint = os.path.join("C:\\windows", "system32", "mspaint.exe")
        self.execute(paint, "", path)

        # If the user did not request the monitor to be disabled, enable it
        if not free:
            self.options["free"] = 0

        time.sleep(5)
        # Try getting winword or wordview as a backup
        try:
            word = self.get_path_glob("WINWORD.EXE")
        except CuckooPackageError:
            word = self.get_path_glob("WORDVIEW.EXE")

        path = check_file_extension(path, ".doc")
        return self.execute(word, f'"{path}" /q', path)
