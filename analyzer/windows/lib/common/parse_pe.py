import struct
from contextlib import suppress

try:
    import pefile

    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
OPTIONAL_HEADER_MAGIC_PE = 0x10B
OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
DOS_HEADER_LIMIT = 0x40
PE_HEADER_LIMIT = 0x200


def is_pe_image(path) -> bool:
    if not path:
        return False

    with open(path, "rb") as f:
        buf = f.read(PE_HEADER_LIMIT)

    if len(buf) < DOS_HEADER_LIMIT:
        return False

    dos_header = buf[:DOS_HEADER_LIMIT]
    nt_headers = None
    e_lfanew = False
    if len(dos_header[:64]) == 64:
        # Check for sane value in e_lfanew
        e_lfanew = struct.unpack("<L", dos_header[60:64])[0]
    if not e_lfanew or e_lfanew > PE_HEADER_LIMIT:
        offset = 0
        while offset < PE_HEADER_LIMIT - 86:
            try:
                machine_probe = struct.unpack("<H", buf[offset: offset + 2])[0]
            except struct.error:
                machine_probe = ""
            if machine_probe and machine_probe in {IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64}:
                nt_headers = buf[offset - 4: offset + 252]
                break
            offset += 2
    else:
        nt_headers = buf[e_lfanew: e_lfanew + 256]
    if not nt_headers:
        return False

    try:
        if 0 in (
            struct.unpack("<H", nt_headers[4:6])[0],
            struct.unpack("<H", nt_headers[20:22])[0],
            struct.unpack("<H", nt_headers[84:86])[0],
        ):
            return False
        if struct.unpack("<H", nt_headers[22:24])[0] & IMAGE_FILE_EXECUTABLE_IMAGE == 0:
            return False
        if struct.unpack("<H", nt_headers[20:22])[0] & 3 != 0:
            return False
        if struct.unpack("<H", nt_headers[24:26])[0] not in {OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS}:
            return False
    except struct.error:
        return False

    # After passing the above tests it should be safe to assume it's a PE image
    return True


def pe_trimmed_size(path) -> int:
    if not HAVE_PEFILE:
        return 0

    with open(path, "rb") as f:
        data = f.read(PE_HEADER_LIMIT * 2)

    with suppress(Exception):
        pe = pefile.PE(data=data, fast_load=False)
        if pe.FILE_HEADER.NumberOfSections:
            return (
                pe.sections[pe.FILE_HEADER.NumberOfSections - 1].PointerToRawData
                + pe.sections[pe.FILE_HEADER.NumberOfSections - 1].SizeOfRawData
            )
    return 0


def choose_dll_export(path) -> str:
    if not HAVE_PEFILE:
        return ""

    if not is_pe_image(path):
        return ""

    pe = pefile.PE(path)

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            with suppress(Exception):
                if not exp.name:
                    continue
                if exp.name.decode() in ("DllInstall", "DllRegisterServer", "xlAutoOpen"):
                    return exp.name.decode()
