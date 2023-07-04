# This is adapted for CAPE from Tomasuh's retefe-unpacker script:
# https://github.com/Tomasuh/retefe-unpacker
# http://tomasuh.github.io/2018/12/28/retefe-unpack.html
# Many thanks to Tomasuh

DESCRIPTION = "Retefe configuration parser."
AUTHOR = "Tomasuh"

import struct

import pefile
import yara

rule_source = """
rule Retefe
{
    meta:
        author = "Tomasuh"
        description = "Retefe Payload"
        cape_type = "Retefe Payload"
    strings:
        $retefe_encoded_buffer = {48 8b 44 24 20 8b 40 08 48 8b 4c 24 20 48 8d 15}
        $retefe_xor_seed = {24 20 48 8b 44 24 20 C7 40 08}
        $retefe_xor_seed_2ndarg = {89 54 24 10 48 89 4c 24 08 48 83 ec 58 ba}
        $retefe_shift_and_sub_match = {c1 e0 ?? b9}
    condition:
        uint16(0) == 0x5A4D and (all of them)
}
"""


def yara_scan(raw_data):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Emotet":
            for item in match.strings:
                addresses[item.identifier] = item.instances[0].offset
    return addresses


def number_gen_rec(buffer_size, number):
    if number == 1:
        return buffer_size
    return 0xFFFFFFFF & buffer_size * (0xFFFFFFFF & number_gen_rec(buffer_size, number - 1))


def number_gen(buffer_size, number, shifts, subtract_val):
    calculated_number = number_gen_rec(buffer_size, number)

    number = calculated_number << shifts  # * 8
    number = subtract_val - number

    return number & 0xFFFFFFFF


def pwd_calc(buffer_size, number, shifts, subtract_val):
    xor_arr = []
    seed = number_gen(buffer_size, number, shifts, subtract_val)

    while seed:
        xor_arr.append(seed & 0xFF)
        seed >>= 8

    return xor_arr


def extract_config(filebuf):
    pe = pefile.PE(data=filebuf, fast_load=False)

    yara_matches = yara_scan(filebuf)

    if not all(
        [
            yara_matches.get(key)
            for key in ("$retefe_xor_seed", "$retefe_xor_seed_2ndarg", "$retefe_shift_and_sub_match", "$retefe_encoded_buffer")
        ]
    ):
        return

    # Offset to seed for xor
    offset = int(yara_matches["$retefe_xor_seed"])
    # Offset to value that will be used to take xor^value
    offset2 = int(yara_matches["$retefe_xor_seed_2ndarg"])
    # Offset to values that will be used in part of subtraction and shifts of xor^value
    offset3 = int(yara_matches["$retefe_shift_and_sub_match"])
    offset4 = int(yara_matches["$retefe_encoded_buffer"])

    # Offset starts at match, we want end of match
    seed_val = struct.unpack("<i", filebuf[offset + 10 : offset + 14])[0] - 1  # -1 because of indexing in code
    # print(f"Found seed (and buffer size) value {hex(seed_val)}")
    # Offset starts at match, we want end of match
    power_to_val = struct.unpack("<i", filebuf[offset2 + 14 : offset2 + 18])[0]
    # print(f"Found power to value {hex(power_to_val)}")
    shift_val = struct.unpack("b", filebuf[offset3 + 2 : offset3 + 3])[0]
    # print(f"Found shift left value {hex(shift_val)}")
    subtract_val = struct.unpack("<i", filebuf[offset3 + 4 : offset3 + 8])[0]
    # print(f"Found subtract value {hex(subtract_val)}")
    # (match length before instruction) + 7 (instruction length)
    buffer_place = struct.unpack("<i", filebuf[offset4 + 16 : offset4 + 20])[0] + 13 + 7
    # print(f"Found buffer place arg {hex(buffer_place)}")
    xor_arr = pwd_calc(seed_val, power_to_val, shift_val, subtract_val)
    # print(f"XOR array that will be used for decryption {xor_arr}")
    text_va_base = None
    text_raw_base = None
    for section in pe.sections:
        if section.Name == b".text" or section.Name.startswith(b".text\x00"):
            text_va_base = section.VirtualAddress
            text_raw_base = section.PointerToRawData

    rva_next_instr = offset4 - text_raw_base
    # Encoded buffer rva address :
    rva = rva_next_instr + text_va_base + buffer_place
    # print(f"Calculated RVA for encoded buffer is {hex(rva)}")
    buffer = pe.get_memory_mapped_image()[rva : rva + seed_val]
    n = 0
    result = ""
    for ch in buffer:
        result += chr((ord(ch) ^ xor_arr[n % 4]))
        n += 1

    return {"Script": result}


# Some logical reasoning left behind....
# Now also find buffer and calculate va to physical and dump it

# Raw address is 4ef60
# Data segment raw base is 4E600
# 4ef60 - 4E600 = 0x960, 2400, offset
# Data segment virtual is 50000
# Image base is 140000000
# So the encoded buffer should be in: 0x140000000 + 0x50000 + 0x960 = 0x140050960 = Correct!


# 0x4ad7c is value from lea
# Next instruction after lea is at 140005be4
# 5be4 + 0x4ad7c = 0x50960 = VA for encoded buffer

# So we need to know instruction address in order to calculate encoded buffer address
# raw address of matched instruction is offset4, 0x4fd0
# 0x4fd0 + 13(match length before instruction) + 7 (instruction length) = 0x4FE4 = Raw address Next instruction
# Raw base of .text is 0x400, so RVA is 0x4FE4 - 0x400 = 0x4BE4
# VA base of .text is 1000, and image base 140000000
# So next instruction should be at 0x140000000 + 0x1000 + 0x4BE4 = 0x140005BE4 = Correct!
