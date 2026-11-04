"""Tests for lib.cuckoo.common.dotnet_utils."""

import struct
import pefile

from lib.cuckoo.common.dotnet_utils import (
    _get_bsjb_metadata_size,
    dotnet_user_strings,
    rebuild_dotnet_pe,
)


def _make_test_pe(include_bsjb: bool = True, include_cor20: bool = True) -> bytes:
    """Build a minimal synthetic PE32 with BSJB metadata and optional COR20 header."""
    # DOS Header
    dos_header = bytearray(128)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 0x80)

    # NT Signature
    nt_sig = b"PE\x00\x00"

    # File Header: Machine=0x14c, NumSections=1, SizeOptHeader=224, Char=0x102
    file_header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 224, 0x102)

    # Optional Header: 96 bytes fields + 128 bytes data directories = 224 bytes
    # Format: HBBIIIIIIIIIHHHHHHIIIIHHIIIIII
    opt_header_fields = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,    # Magic (PE32)
        1,        # MajorLinkerVersion
        0,        # MinorLinkerVersion
        0x1000,   # SizeOfCode
        0x1000,   # SizeOfInitializedData
        0,        # SizeOfUninitializedData
        0x1000,   # AddressOfEntryPoint
        0x1000,   # BaseOfCode
        0x2000,   # BaseOfData
        0x400000, # ImageBase
        0x1000,   # SectionAlignment
        0x200,    # FileAlignment (initial non-aligned)
        4,        # MajorOperatingSystemVersion
        0,        # MinorOperatingSystemVersion
        0,        # MajorImageVersion
        0,        # MinorImageVersion
        4,        # MajorSubsystemVersion
        0,        # MinorSubsystemVersion
        0,        # Reserved1
        0x3000,   # SizeOfImage
        0x200,    # SizeOfHeaders
        0,        # CheckSum
        3,        # Subsystem (Windows CUI)
        0,        # DllCharacteristics
        0x100000, # SizeOfStackReserve
        0x1000,   # SizeOfStackCommit
        0x100000, # SizeOfHeapReserve
        0x1000,   # SizeOfHeapCommit
        0,        # LoaderFlags
        16,       # NumberOfRvaAndSizes
    )

    data_dirs = bytearray(16 * 8)
    opt_header = opt_header_fields + data_dirs

    # Section Header: 40 bytes
    sec_name = b".text\x00\x00\x00"
    sec_header = struct.pack("<8sIIIIIIHHI", sec_name, 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    headers = dos_header + nt_sig + file_header + opt_header + sec_header
    headers = headers.ljust(0x1000, b"\x00")

    body = bytearray(0x1000)

    if include_bsjb:
        vstr = b"v4.0.30319\x00\x00"
        vlen = len(vstr)
        streams = bytearray()
        # Stream 1: offset=0x40, size=0x100, name="#~"
        streams += struct.pack("<II", 0x40, 0x100) + b"#~\x00\x00"
        # Stream 2: offset=0x140, size=0x200, name="#Strings"
        streams += struct.pack("<II", 0x140, 0x200) + b"#Strings\x00\x00\x00\x00"

        bsjb = b"BSJB" + struct.pack("<HHII", 1, 1, 0, vlen) + vstr + struct.pack("<HH", 0, 2) + streams
        bsjb_offset_in_sec = 0x200  # RVA = 0x1200
        body[bsjb_offset_in_sec : bsjb_offset_in_sec + len(bsjb)] = bsjb

        if include_cor20:
            metadata_rva = 0x1000 + bsjb_offset_in_sec
            cor20 = struct.pack("<IHHIIII", 0x48, 2, 5, metadata_rva, 0x340, 1, 0) + (b"\x00" * 48)
            body[0x100 : 0x100 + 72] = cor20

    return bytes(headers + body)


def test_get_bsjb_metadata_size():
    data = _make_test_pe(include_bsjb=True, include_cor20=True)
    bsjb_offset = data.find(b"BSJB")
    assert bsjb_offset != -1
    size = _get_bsjb_metadata_size(data, bsjb_offset)
    assert size == 0x340  # 0x140 + 0x200


def test_get_bsjb_metadata_size_truncated():
    assert _get_bsjb_metadata_size(b"BSJB\x01\x00", 0) == 0


def test_rebuild_dotnet_pe_with_existing_cor20():
    raw = _make_test_pe(include_bsjb=True, include_cor20=True)
    pe_orig = pefile.PE(data=raw)
    assert pe_orig.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress == 0

    rebuilt = rebuild_dotnet_pe(raw)
    assert rebuilt != raw

    pe = pefile.PE(data=rebuilt)
    cor20_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    assert cor20_dir.VirtualAddress == 0x1100
    assert cor20_dir.Size == 0x48

    # Verify section alignment was fixed
    sec = pe.sections[0]
    assert sec.PointerToRawData == sec.VirtualAddress
    assert sec.SizeOfRawData == 0x1000
    assert pe.OPTIONAL_HEADER.FileAlignment == pe.OPTIONAL_HEADER.SectionAlignment


def test_rebuild_dotnet_pe_synthesizes_cor20():
    raw = _make_test_pe(include_bsjb=True, include_cor20=False)
    pe_orig = pefile.PE(data=raw)
    assert pe_orig.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress == 0

    rebuilt = rebuild_dotnet_pe(raw)
    assert rebuilt != raw

    pe = pefile.PE(data=rebuilt)
    cor20_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    assert cor20_dir.VirtualAddress != 0
    assert cor20_dir.Size == 0x48

    # Verify synthesized COR20 header content
    cor20_bytes = rebuilt[cor20_dir.VirtualAddress : cor20_dir.VirtualAddress + 0x48]
    cb, major, minor, meta_rva, meta_size, flags, entry_token = struct.unpack_from("<IHHIIII", cor20_bytes, 0)
    assert cb == 0x48
    assert major == 2
    assert minor == 5
    assert meta_rva == 0x1200
    assert meta_size == 0x340
    assert flags == 1


def test_rebuild_dotnet_pe_non_pe():
    data = b"not a pe file at all"
    assert rebuild_dotnet_pe(data) == data


def test_rebuild_dotnet_pe_no_bsjb():
    raw = _make_test_pe(include_bsjb=False, include_cor20=False)
    rebuilt = rebuild_dotnet_pe(raw)
    pe = pefile.PE(data=rebuilt)
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress == 0
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size == 0


def test_dotnet_user_strings_empty():
    assert dotnet_user_strings(data=b"") == []
