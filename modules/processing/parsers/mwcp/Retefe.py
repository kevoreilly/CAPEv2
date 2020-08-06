# This is adapted for CAPE from Tomasuh's retefe-unpacker script:
# https://github.com/Tomasuh/retefe-unpacker
# http://tomasuh.github.io/2018/12/28/retefe-unpack.html
# Many thanks to Tomasuh

from mwcp.parser import Parser
import yara
import struct
import pefile

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


def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == "Retefe":
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
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
        seed = seed >> 8

    return xor_arr


class Retefe(Parser):

    DESCRIPTION = "Retefe configuration parser."
    AUTHOR = "kevoreilly"

    def run(self):
        filebuf = self.file_object.file_data
        pe = pefile.PE(data=self.file_object.file_data, fast_load=False)

        # Offset to seed for xor
        retefe_xor_seed = yara_scan(filebuf, "$retefe_xor_seed")
        if retefe_xor_seed:
            offset = int(retefe_xor_seed["$retefe_xor_seed"])
        else:
            return

        # Offset to value that will be used to take xor^value
        xor_seed_2ndarg = yara_scan(filebuf, "$retefe_xor_seed_2ndarg")
        if xor_seed_2ndarg:
            offset2 = int(xor_seed_2ndarg["$retefe_xor_seed_2ndarg"])
        else:
            return

        # Offset to values that will be used in part of subtraction and shifts of xor^value
        shift_and_subtract = yara_scan(filebuf, "$retefe_shift_and_sub_match")
        if shift_and_subtract:
            offset3 = int(shift_and_subtract["$retefe_shift_and_sub_match"])
        else:
            return

        retefe_encoded_buffer = yara_scan(filebuf, "$retefe_encoded_buffer")
        if retefe_encoded_buffer:
            offset4 = int(retefe_encoded_buffer["$retefe_encoded_buffer"])
        else:
            return

        # Offset starts at match, we want end of match
        seed_val = struct.unpack("<i", filebuf[offset + 10 : offset + 14])[0] - 1  # -1 because of indexing in code
        # print("Found seed (and buffer size) value {}".format(hex(seed_val)))

        # Offset starts at match, we want end of match
        power_to_val = struct.unpack("<i", filebuf[offset2 + 14 : offset2 + 18])[0]
        # print("Found power to value {}".format(hex(power_to_val)))

        shift_val = struct.unpack("b", filebuf[offset3 + 2 : offset3 + 3])[0]
        # print("Found shift left value {}".format(hex(shift_val)))

        subtract_val = struct.unpack("<i", filebuf[offset3 + 4 : offset3 + 8])[0]
        # print("Found subtract value {}".format(hex(subtract_val)))

        # (match length before instruction) + 7 (instruction length)
        buffer_place = struct.unpack("<i", filebuf[offset4 + 16 : offset4 + 20])[0] + 13 + 7

        # print("Found buffer place arg {}".format(hex(buffer_place)))

        xor_arr = pwd_calc(seed_val, power_to_val, shift_val, subtract_val)

        # print("XOR array that will be used for decryption {}".format(xor_arr))

        text_va_base = None
        text_raw_base = None

        for section in pe.sections:
            if section.Name == ".text" or section.Name.startswith(b".text\x00"):
                text_va_base = section.VirtualAddress
                text_raw_base = section.PointerToRawData

        rva_next_instr = offset4 - text_raw_base

        # Encoded buffer rva address :
        rva = rva_next_instr + text_va_base + buffer_place

        # print("Calculated RVA for encoded buffer is {}".format(hex(rva)))

        buffer = pe.get_memory_mapped_image()[rva : rva + seed_val]

        n = 0
        result = ""
        for ch in buffer:
            result += chr((ord(ch) ^ xor_arr[n % 4]))
            n += 1

        self.reporter.add_metadata("other", {"Script": result})


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
