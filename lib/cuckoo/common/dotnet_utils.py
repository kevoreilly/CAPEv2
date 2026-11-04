import logging
import struct

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
    if not file and not data:
        return []

    dn = None
    dn_strings = []
    try:
        if file:
            dn = dnfile.dnPE(file)
        elif data:
            dn = dnfile.dnPE(data=data)

        if not dn or not hasattr(dn, "net") or not hasattr(dn.net, "metadata") or not hasattr(dnfile, "streams"):
            return []

        us = dn.net.metadata.streams.get(b"#US", None)
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
                    if s.value and not any(pattern in s.value for pattern in dn_whitelisting):
                        dn_strings.append(s.value)
                except UnicodeDecodeError:
                    log.debug("Bad string: %s", buf.replace(b"\x00", b""))
                # continue to next entry
                offset += readlen
    except Exception as e:
        log.error("dnFile error: %s", e)
    finally:
        if dn is not None and hasattr(dn, "close"):
            dn.close()

    return dn_strings



def _get_bsjb_metadata_size(data: bytes, bsjb_offset: int) -> int:
    """Calculate the total size of the .NET metadata from the BSJB root header."""
    try:
        if len(data) < bsjb_offset + 20:
            return 0
        # BSJB header layout (ECMA-335 II.24.2.1):
        # 0: Signature "BSJB" (4 bytes)
        # 4: MajorVersion (2 bytes)
        # 6: MinorVersion (2 bytes)
        # 8: Reserved (4 bytes)
        # 12: Length of version string (4 bytes)
        vlen = struct.unpack_from("<I", data, bsjb_offset + 12)[0]
        if bsjb_offset + 16 + vlen + 4 > len(data):
            return 0
        streams_offset = bsjb_offset + 16 + vlen
        _, nstreams = struct.unpack_from("<HH", data, streams_offset)
        cur = streams_offset + 4
        max_end = 0
        for _ in range(nstreams):
            if cur + 8 > len(data):
                break
            s_offset, s_size = struct.unpack_from("<II", data, cur)
            cur += 8
            # Stream name is null-terminated ASCII, 4-byte aligned
            name_end = data.find(b"\x00", cur)
            if name_end == -1:
                break
            name_len = name_end - cur + 1
            padded_len = (name_len + 3) & ~3
            cur += padded_len
            if s_offset + s_size > max_end:
                max_end = s_offset + s_size
        return max_end
    except Exception:
        return 0


def rebuild_dotnet_pe(data: bytes) -> bytes:
    """Rebuilds a .NET PE file dumped from memory (Memory Layout to File Layout).

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

    # Overwrite FileAlignment in the optional header (offset 36 in Standard/Windows fields)
    struct.pack_into("<I", modified, pe.OPTIONAL_HEADER.get_file_offset() + 36, pe.OPTIONAL_HEADER.FileAlignment)

    # 2. Restore .NET Data Directory if missing
    dotnet_dir_index = 14  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    if dotnet_dir_index < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        dotnet_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[dotnet_dir_index]
        if dotnet_dir.VirtualAddress == 0 or dotnet_dir.Size == 0:
            bsjb_offset = modified.find(b"BSJB")
            if bsjb_offset != -1:
                metadata_rva = bsjb_offset
                metadata_size = _get_bsjb_metadata_size(modified, bsjb_offset)
                if metadata_size == 0:
                    metadata_size = len(modified) - bsjb_offset

                # Backwards scan for existing IMAGE_COR20_HEADER (cb=0x48, Major=2, Minor=5, MetaData=bsjb_offset)
                search_prefix = struct.pack("<IHHI", 0x48, 2, 5, metadata_rva)
                cor20_rva = 0

                search_start = max(0, bsjb_offset - 4096)
                for i in range(bsjb_offset - 12, search_start - 1, -1):
                    if modified[i : i + 12] == search_prefix:
                        cor20_rva = i
                        break

                if cor20_rva != 0:
                    # Update MetaData.Size if zero
                    existing_meta_size = struct.unpack_from("<I", modified, cor20_rva + 12)[0]
                    if existing_meta_size == 0 and metadata_size > 0:
                        struct.pack_into("<I", modified, cor20_rva + 12, metadata_size)
                else:
                    # Synthesize an IMAGE_COR20_HEADER (72 = 0x48 bytes)
                    # ECMA-335 II.25.3.3:
                    # cb (4), Major (2), Minor (2), MetaData.RVA (4), MetaData.Size (4),
                    # Flags (4), EntryPointToken (4), + 6 * 8-byte empty data directories = 72 bytes
                    cor20_header = struct.pack(
                        "<IHHIIII",
                        0x48,           # cb
                        2,              # MajorRuntimeVersion
                        5,              # MinorRuntimeVersion
                        metadata_rva,   # MetaData.VirtualAddress
                        metadata_size,  # MetaData.Size
                        1,              # Flags (COMIMAGE_FLAGS_ILONLY)
                        0,              # EntryPointToken
                    ) + (b"\x00" * 48)

                    # Look for 72 bytes of zero padding before bsjb_offset
                    if bsjb_offset >= 72 and modified[bsjb_offset - 72 : bsjb_offset] == b"\x00" * 72:
                        cor20_rva = bsjb_offset - 72
                        modified[cor20_rva : cor20_rva + 72] = cor20_header
                    else:
                        zero_block = b"\x00" * 72
                        pad_pos = modified.rfind(zero_block, 0, bsjb_offset)
                        if pad_pos != -1:
                            cor20_rva = pad_pos
                            modified[cor20_rva : cor20_rva + 72] = cor20_header

                if cor20_rva != 0:
                    dir_offset = dotnet_dir.get_file_offset()
                    struct.pack_into("<II", modified, dir_offset, cor20_rva, 0x48)

    return bytes(modified)

