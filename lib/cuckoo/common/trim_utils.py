from contextlib import suppress
from pathlib import Path

import olefile

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.integrations.parse_pe import HAVE_PEFILE, IsPEImage, PortableExecutable
from lib.cuckoo.common.path_utils import path_write_file

web_cfg = Config("web")


def trimmed_path(filename: bytes) -> bytes:
    path = Path(filename.decode())
    return f"{path.parent}/trimmed_{path.name}".encode()


def trim_file(filename: bytes, doc: bool = False) -> bool:
    """
    Trim PE/OLE doc file
    """
    trimmed_size = None
    if doc:
        trimmed_size = trim_ole_doc(filename)
    else:
        file_head = File(filename).get_chunks(64).__next__()
        if HAVE_PEFILE and IsPEImage(file_head):
            trimmed_size = trim_sample(file_head)

    if trimmed_size and trimmed_size < web_cfg.general.max_sample_size:
        with open(filename, "rb") as hfile:
            data = hfile.read(trimmed_size)
        _ = path_write_file(trimmed_path(filename).decode(), data)
        return True


def trim_sample(first_chunk):
    with suppress(Exception):
        return PortableExecutable(data=first_chunk).get_overlay_raw()


def trim_ole_doc(file_path: bytes) -> int:
    with suppress(Exception):
        ole = olefile.OleFileIO(file_path)
        if ole.header_signature != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return

        num_sectors_per_fat_sector = ole.sector_size / 4
        num_sectors_in_fat = num_sectors_per_fat_sector * ole.num_fat_sectors
        max_filesize_fat = (num_sectors_in_fat + 1) * ole.sector_size
        if ole._filesize > max_filesize_fat:
            last_used_sector = len(ole.fat) - 1
            for i in range(len(ole.fat) - 1, 0, -1):
                last_used_sector = i
                if ole.fat[i] != olefile.FREESECT:
                    break

            return ole.sectorsize * (last_used_sector + 2)
