from contextlib import suppress
from typing import Union

import olefile

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.integrations.parse_pe import PortableExecutable
from lib.cuckoo.common.path_utils import path_write_file

web_cfg = Config("web")


def trim_file(filename: any, doc: bool = False) -> Union[bool, int]:
    """
    Trim PE/OLE doc file
    """
    trimmed_size = False
    if isinstance(filename, bytes):
        if doc:
            trimmed_size = trim_ole_doc(filename)
        if not trimmed_size:
            file_head = File(filename).get_chunks(64).__next__()
            trimmed_size = trim_sample(file_head)
    else:
        if doc:
            filename.seek(0)
            trimmed_size = trim_ole_doc(filename.read())
        else:
            trimmed_size = trim_sample(filename.chunks().__next__())
        return trimmed_size

    if trimmed_size and trimmed_size < web_cfg.general.max_sample_size:
        with open(filename, "rb") as hfile:
            data = hfile.read(trimmed_size)
        _ = path_write_file(filename.decode(), data)
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
