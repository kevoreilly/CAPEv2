import re
import struct
from contextlib import suppress
from itertools import cycle

import pefile
import yara

# Hash = b462e3235c7578450b2b56a8aff875a3d99d22f6970a01db3ba98f7ecb6b01a0

RULE_SOURCE = """
rule KoiLoaderResources
{
    meta:
        author = "YungBinary"
        description = "Find KoiLoader XOR key and payload resource ids"
    strings:
        $payload_resource = {8D [2] 50 68 [4] E8}
        $xor_key_resource = {8D [2] 51 68 [4] E8}
    condition:
        uint16(0) == 0x5A4D and $payload_resource and $xor_key_resource
}
"""


def yara_scan(raw_data):
    yara_rules = yara.compile(source=RULE_SOURCE)
    matches = yara_rules.match(data=raw_data)
    payload_resource_id = None
    xor_key_resource_id = None

    for match in matches:
        if match.rule != "KoiLoaderResources":
            continue
        for item in match.strings:
            if "$payload_resource" in item.identifier:
                payload_offset = item.instances[0].offset
                payload_resource_id = struct.unpack("i", raw_data[payload_offset + 5 : payload_offset + 9])[0]

            elif "$xor_key_resource" in item.identifier:
                xor_key_offset = item.instances[0].offset
                xor_key_resource_id = struct.unpack("i", raw_data[xor_key_offset + 5 : xor_key_offset + 9])[0]

    return (payload_resource_id, xor_key_resource_id)


def remove_nulls(buffer, buffer_size):
    """
    Modify a buffer removing null bytes
    """
    num_nulls = count_nulls(buffer)
    result = skip_nth(buffer, num_nulls + 1)
    return bytearray(result)


def count_nulls(buffer):
    """
    Count null separation in a buffer
    """
    num_nulls = 0
    idx = 1
    while True:
        cur_byte = buffer[idx]
        if cur_byte == 0:
            num_nulls += 1
            idx += 1
            continue
        else:
            break

    return num_nulls


def skip_nth(buffer, n):
    iterable = list(buffer)
    yield from (value for index, value in enumerate(iterable) if (index + 1) % n and (index - 1) % n)


def find_c2(decoded_buffer):
    decoded_buffer = bytearray(skip_nth(decoded_buffer, 2))
    url_regex = re.compile(rb"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
    urls = [url.lower().decode() for url in url_regex.findall(decoded_buffer)]
    return urls


def xor_data(data, key):
    return bytes(c ^ k for c, k in zip(data, cycle(key)))


def extract_config(data):
    config_dict = {"C2": []}

    xor_key = b""
    encoded_payload = b""

    payload_resource_id, xor_key_resource_id = yara_scan(data)

    if payload_resource_id is None or xor_key_resource_id is None:
        return

    with suppress(Exception):
        pe = pefile.PE(data=data)
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            resource_type = pefile.RESOURCE_TYPE.get(entry.struct.Id)
            for directory in entry.directory.entries:
                for resource in directory.directory.entries:
                    if resource_type != "RT_RCDATA":
                        continue
                    if directory.struct.Id == xor_key_resource_id:
                        offset = resource.data.struct.OffsetToData
                        xor_phrase_size = resource.data.struct.Size
                        xor_key = pe.get_memory_mapped_image()[offset : offset + xor_phrase_size]
                    elif directory.struct.Id == payload_resource_id:
                        offset = resource.data.struct.OffsetToData
                        encoded_payload_size = resource.data.struct.Size
                        encoded_payload = pe.get_memory_mapped_image()[offset : offset + encoded_payload_size]

        encoded_payload = remove_nulls(encoded_payload, encoded_payload_size)
        decoded_payload = xor_data(encoded_payload, xor_key)

        config_dict["C2"] = find_c2(decoded_payload)

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
