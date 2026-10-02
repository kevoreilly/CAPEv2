import logging

try:
    import dnfile

    HAVE_DNFILE = True
    logging.getLogger("dnfile").setLevel(logging.CRITICAL)
    logging.getLogger("dnfile.stream").setLevel(logging.CRITICAL)
except ImportError:
    HAVE_DNFILE = False


log = logging.getLogger("dotnet_utils")


def dotnet_user_strings(file: str = False, data: bytes = False, dn_whitelisting: list = []) -> list:
    """
    Extracts user strings from a .NET file or data blob using dnfile.

    Args:
        file (str): Path to the .NET file. Default is False.
        data (bytes): Byte data of the .NET file. Default is False.
        dn_whitelisting (list): List of string patterns to whitelist. Default is an empty list.

    Returns:
        list: A list of extracted user strings that are not in the whitelist.

    Raises:
        Exception: If there is an error processing the .NET file or data.
    """

    if not HAVE_DNFILE:
        return []

    try:
        if file:
            dn = dnfile.dnPE(file)
        elif data:
            dn = dn = dnfile.dnPE(data=data)

        dn_strings = []
        if not hasattr(dn, "net") or not hasattr(dn.net, "metadata") or not hasattr(dnfile, "streams"):
            return []

        us: dnfile.stream.UserStringHeap = dn.net.metadata.streams.get(b"#US", None)
        if us:
            size = us.sizeof()
            offset = 1
            while offset < size:
                ret = us.get_with_size(offset)
                if not ret:
                    break

                buf, readlen = ret
                try:
                    if not buf.endswith(b"\x00\x00\x00"):
                        buf = buf[:-1]
                    s = dnfile.stream.UserString(buf)
                    if s.value and not any([pattern in s.value for pattern in dn_whitelisting]):
                        dn_strings.append(s.value)
                except UnicodeDecodeError:
                    log.debug("Bad string:", buf.replace(b"\x00", b""))
                # continue to next entry
                offset += readlen
    except Exception as e:
        log.error("dnFile error: ", str(e))

    dn.close()
    return dn_strings

import struct

def rebuild_dotnet_pe(data: bytes) -> bytes:
    """
    Rebuilds a .NET PE file dumped from memory (Memory Layout).
    Fixes section alignments and attempts to restore missing .NET headers
    by locating the BSJB metadata signature.
    """
    try:
        import pefile
    except ImportError:
        return data

    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError:
        return data

    modified = bytearray(data)

    # 1. Align Sections (Memory to File Layout conversion)
    # Match FileAlignment to SectionAlignment
    pe.OPTIONAL_HEADER.FileAlignment = pe.OPTIONAL_HEADER.SectionAlignment
    
    # Update Section Headers
    for section in pe.sections:
        section.PointerToRawData = section.VirtualAddress
        # SizeOfRawData should be VirtualSize aligned to FileAlignment
        alignment_mask = pe.OPTIONAL_HEADER.FileAlignment - 1
        section.SizeOfRawData = (section.Misc_VirtualSize + alignment_mask) & ~alignment_mask

        # Overwrite physical bytes in header
        struct.pack_into("<I", modified, section.get_file_offset() + 16, section.SizeOfRawData)
        struct.pack_into("<I", modified, section.get_file_offset() + 20, section.PointerToRawData)

    # Overwrite FileAlignment in the optional header
    struct.pack_into("<I", modified, pe.OPTIONAL_HEADER.get_file_offset() + 36, pe.OPTIONAL_HEADER.FileAlignment)

    # 2. Restore .NET Data Directory if missing
    dotnet_dir_index = 14 # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    if dotnet_dir_index < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        dotnet_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_dir_index]
        if dotnet_dir.VirtualAddress == 0 or dotnet_dir.Size == 0:
            bsjb_offset = modified.find(b"BSJB")
            if bsjb_offset != -1:
                # Naive backwards scan for IMAGE_COR20_HEADER (cb=0x48, Major=2, Minor=5, MetaData=bsjb_offset)
                metadata_rva = bsjb_offset
                search_pattern = struct.pack("<IHHUI", 0x48, 2, 5, metadata_rva, 0)
                cor20_rva = 0

                search_start = max(0, bsjb_offset - 1024)
                for i in range(bsjb_offset, search_start, -1):
                    if modified[i:i+12] == search_pattern[:12]:
                        cor20_rva = i
                        break

                if cor20_rva != 0:
                    dir_offset = dotnet_dir.get_file_offset()
                    struct.pack_into("<II", modified, dir_offset, cor20_rva, 0x48)

    return bytes(modified)
