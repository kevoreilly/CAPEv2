import struct

import pefile


# dotnet
def get_mdtoken(data: bytes) -> int:
    return struct.unpack_from("<I", data)[0] & 0xFFFFFF


def get_data_offset(pe: pefile.PE, string_offset: int, addr: int) -> int:
    alignment = calc_section_alignment(pe, string_offset, addr)
    return string_offset + addr - alignment


def calc_section_alignment(pe: pefile.PE, offset: int, addr: int) -> int:
    """
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


def function_offset_from_VA(addr, blob, pe):
    shift_pos = blob.find(b"\xE8") + 1
    function_addr = pe.get_rva_from_offset(addr + shift_pos) + pe.OPTIONAL_HEADER.ImageBase
    # print(f"Getting offset for function: {hex(function_addr)}")
    next_instruction = pe.get_rva_from_offset(addr + shift_pos) + pe.OPTIONAL_HEADER.ImageBase + 5
    addr = struct.unpack("i", blob[shift_pos : shift_pos + 4])[0]
    return function_addr, pe.get_offset_from_rva(next_instruction + addr - pe.OPTIONAL_HEADER.ImageBase)


def function_offset_from_offset(addr: int, binary: bytes, pe: pefile.PE):
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
