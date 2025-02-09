import struct

import pefile


# dotnet
def get_mdtoken(data: bytes) -> int:
    """
    Extracts a metadata token from the given byte data.

    The function interprets the first 4 bytes of the input data as an unsigned
    integer in little-endian format and then masks it with 0xFFFFFF to obtain
    the metadata token.

    Args:
        data (bytes): The byte data from which to extract the metadata token.

    Returns:
        int: The extracted metadata token.
    """
    return struct.unpack_from("<I", data)[0] & 0xFFFFFF


def get_data_offset(pe: pefile.PE, string_offset: int, addr: int) -> int:
    alignment = calc_section_alignment(pe, string_offset, addr)
    return string_offset + addr - alignment


def calc_section_alignment(pe: pefile.PE, offset: int, addr: int) -> int:
    """
    Calculate the alignment between two sections in a PE file.

    Args:
        pe (pefile.PE): The PE file object.
        offset (int): The offset value, typically calculated as
                    struct.unpack("i", blob[0x43:0x47])[0] + 0x47.
        addr (int): The address where data starts, which can be a YARA address match.

    Returns:
        int: The calculated alignment between the sections. Returns 0 if sections are not found or an error occurs.

    Raises:
        Exception: If an error occurs during the calculation, it will be caught and printed.

    offset is: Ex struct.unpack("i", blob[0x43:0x47])[0] + 0x47
    addr is where data starts, can be YARA address match
    """
    alignment = 0
    try:
        text = pe.get_section_by_rva(offset)
        rdata = pe.get_section_by_rva(offset + addr)
        if not text or not rdata:
            return alignment
        # add (section1VA - sectionXVA) - (section1Raw - sectionXRaw)
        alignment = (rdata.VirtualAddress - text.VirtualAddress) - (rdata.PointerToRawData - text.PointerToRawData)
    except Exception as e:
        print(e)
    return alignment


def function_offset_from_VA(addr: int, blob: bytes, pe: pefile.PE):
    """
    Calculate the function offset from a given virtual address (VA) in a PE file.

    Args:
        addr (int): The virtual address to start from.
        blob (bytes): The binary data blob containing the instructions.
        pe (PE): The PE file object, typically from the pefile module.

    Returns:
        tuple: A tuple containing:
            - function_addr (int): The calculated function address.
            - offset (int): The offset of the next instruction after the function call.
    """
    shift_pos = blob.find(b"\xE8") + 1
    function_addr = pe.get_rva_from_offset(addr + shift_pos) + pe.OPTIONAL_HEADER.ImageBase
    # print(f"Getting offset for function: {hex(function_addr)}")
    next_instruction = pe.get_rva_from_offset(addr + shift_pos) + pe.OPTIONAL_HEADER.ImageBase + 5
    addr = struct.unpack("i", blob[shift_pos : shift_pos + 4])[0]
    return function_addr, pe.get_offset_from_rva(next_instruction + addr - pe.OPTIONAL_HEADER.ImageBase)


def function_offset_from_offset(addr: int, binary: bytes, pe: pefile.PE):
    """
    Calculates the virtual address and file offset of a subfunction call within a binary.

    Args:
        addr (int): The starting address to search for the CALL instruction.
        binary (bytes): The binary data of the executable.
        pe (pefile.PE): The PE file object representing the executable.

    Returns:
        tuple: A tuple containing:
            - call_virtual_address (int): The virtual address of the CALL instruction.
            - subfunc_file_offset (int): The file offset of the subfunction being called.
    """
    # where our subcall starts - example: 8
    shift_pos = binary[addr:].find(b"\xE8")
    call_file_offset = addr + shift_pos
    # convert file offset to RVA + add address image base
    # print(pe.get_rva_from_offset(call_file_offset))
    call_virtual_address = pe.get_rva_from_offset(call_file_offset) + pe.OPTIONAL_HEADER.ImageBase
    # convert rva address to subfunc offset, we add 1 to skip E8 aka CALL instruction
    subfunc_offset = struct.unpack_from("i", binary, call_file_offset + 1)[0]
    # calculate next instruction after our CALL
    subfunc_virtual_address = (call_virtual_address + 5 + subfunc_offset) & 0xFFFFFFFF
    # convert VA to offset in file
    return call_virtual_address, pe.get_offset_from_rva(subfunc_virtual_address - pe.OPTIONAL_HEADER.ImageBase)


def find_function_xrefs(data, start, end):
    """
    Finds function cross-references (xrefs) within a specified range in the given binary data.

    Args:
        data (bytes): The binary data to search for function xrefs.
        start (int): The starting address (inclusive) of the range to search.
        end (int): The ending address (exclusive) of the range to search.

    Returns:
        dict: A dictionary where keys are target addresses of CALL instructions and values are lists of addresses
            where these CALL instructions are located.
    """
    function_xrefs = {}
    # The re.finditer function only finds *non-overlapping* matches, which fails to find some CALL instructions
    for rva in range(start, end):
        if not 0 <= rva < len(data) - 5:
            continue
        if data[rva] != 0xE8:
            continue
        # print( data[rva - 2 : rva].hex())
        if data[rva - 2 : rva] in (b"\x81\x40", b"\x81\x45", b"\x81\x75", b"\xc7\x40", b"\xc7\x45", b"\xc7\x75"):
            # this is not a real function call
            continue
        offset = struct.unpack_from("=i", data, rva + 1)[0]
        target = (rva + 5) + offset

        if not 0 <= target < len(data):
            continue
        if start <= target < end:
            function_xrefs.setdefault(target, []).append(rva)
            # log.debug("Found a CALL instruction: %#x -> %#x", rva + ib, target + ib)
    return function_xrefs
