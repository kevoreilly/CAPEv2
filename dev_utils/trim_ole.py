import sys

try:
    import olefile
except ImportError:
    print("Missed olefile dependency: pip3 install olefile")
    sys.exit(1)

from oletools.thirdparty.tablestream import tablestream
from pathlib import Path


def debloat():
    try:
        ole = olefile.OleFileIO(sys.argv[1])
        if ole.header_signature != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            print("Not a proper OLE Doc file.")
            sys.exit(1)

        print(f"File size: {ole._filesize} bytes")

        num_sectors_per_fat_sector = ole.sector_size / 4
        num_sectors_in_fat = num_sectors_per_fat_sector * ole.num_fat_sectors
        max_filesize_fat = (num_sectors_in_fat + 1) * ole.sector_size
        if ole._filesize > max_filesize_fat:
            last_used_sector = len(ole.fat) - 1
            for i in range(len(ole.fat) - 1, 0, -1):
                last_used_sector = i
                if ole.fat[i] != olefile.FREESECT:
                    break

            debloated_size = ole.sectorsize * (last_used_sector + 2)

            print(f"Debloated file size: {debloated_size} bytes")
            newfile = Path(sys.argv[1]).name
            with open(sys.argv[1], "rb") as hfile:
                data = hfile.read(debloated_size)
            Path(f"t_{newfile}").write_bytes(data)
        else:
            print("Still bloated :(")

    except Exception as e:
        print(e)


if __name__ == "__main__":
    debloat()

    print("Finito.")
