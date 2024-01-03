# based on https://github.com/nict-csl/NanoCoreRAT-Analysis.git

import datetime
import io
import logging
import uuid
import zlib
from contextlib import suppress
from enum import Enum

import pefile

HAVE_PYCYPTODOMEX = False
with suppress(ImportError):
    from Cryptodome.Cipher import DES
    from Cryptodome.Util.Padding import unpad

    HAVE_PYCYPTODOMEX = True

log = logging.getLogger(__name__)

DES_KEY = b"\x72\x20\x18\x78\x8c\x29\x48\x97"
DES_IV = DES_KEY


class DataType(Enum):
    BOOL = 0
    BYTE = 1
    BYTEARRAY = 2
    CHAR = 3
    CHARARRAY = 4
    DECIMAL = 5
    DOUBLE = 6
    INT = 7
    LONG = 8
    SBYTE = 9
    SHORT = 10
    FLOAT = 11
    STRING = 12
    UINT = 13
    ULONG = 14
    USHORT = 15
    DATETIME = 16
    STRINGARRAY = 17
    GUID = 18
    SIZE = 19
    RECTANGLE = 20
    VERSION = 21
    UNKNOWN = 100


def des_decrypt(data):
    cipher = DES.new(key=DES_KEY, iv=DES_IV, mode=DES.MODE_CBC)
    dec_data = cipher.decrypt(data)
    if not dec_data:
        return b""
    return unpad(dec_data, DES.block_size)


def bool_from_byte(byte):
    return byte == b"\x01"


def deserialize_datetime(ticks):
    base_ticks = 0x489F7FF5F7B58000  # 1970/01/01 00:00:00
    unixtime = (ticks - base_ticks) / 10000000
    try:
        return datetime.datetime.fromtimestamp(unixtime)
    except ValueError:
        return ticks


def decode(payload):
    payload_len = int.from_bytes(payload[:4], "little")
    try:
        payload_body = des_decrypt(payload[4 : payload_len + 4])
    except ValueError:
        return None

    f = io.BytesIO(payload_body)
    compressed_mode = bool_from_byte(f.read(1))
    if compressed_mode:
        # data length after raw inflate.
        data_len = int.from_bytes(f.read(4), "little")
        deflate_data = f.read()
        inflate_data = zlib.decompress(deflate_data, wbits=-15)
        payload_len = len(inflate_data)
        f.close()
        f = io.BytesIO(inflate_data)

    flag1 = int.from_bytes(f.read(1), "little")  # unknown data
    flag2 = int.from_bytes(f.read(1), "little")  # unknown data
    guid = uuid.UUID(bytes=b"\x00" * 16)
    params = []

    check_guid = bool_from_byte(f.read(1))
    if check_guid:
        guid_bytes = f.read(16)
        guid = uuid.UUID(bytes_le=guid_bytes)

    position = f.tell()
    while payload_len > position:
        type_num = int.from_bytes(f.read(1), "little")
        data_type = DataType(type_num)
        if data_type == DataType.BOOL:
            value = bool_from_byte(f.read(1))
        elif data_type == DataType.BYTE:
            value = f.read(1)
        elif data_type == DataType.BYTEARRAY:
            data_len = int.from_bytes(f.read(4), "little")
            value = f.read(data_len)
        elif data_type in (DataType.INT, DataType.UINT):
            value = int.from_bytes(f.read(4), "little")
        elif data_type in (DataType.LONG, DataType.ULONG):
            value = int.from_bytes(f.read(8), "little")
        elif data_type in (DataType.SHORT, DataType.USHORT):
            value = int.from_bytes(f.read(2), "little")
        elif data_type == DataType.FLOAT:
            value = float(int.from_bytes(f.read(4), "little"))
        elif data_type in (DataType.STRING, DataType.VERSION):
            data_len = int.from_bytes(f.read(1), "little")
            value = f.read(data_len).decode()
        elif data_type == DataType.DATETIME:
            ticks = int.from_bytes(f.read(8), "little")
            value = deserialize_datetime(ticks)
        elif data_type == DataType.GUID:
            value = uuid.UUID(bytes_le=f.read(16))
        else:  # TODO: Other Types
            data_type = DataType.UNKNOWN
            value = f.read()

        if position == f.tell():
            break
        position = f.tell()
        params.append({"type": data_type, "value": value})
    f.close()

    result = {"uuid": guid, "compressed_mode": compressed_mode, "flags": [flag1, flag2], "params": params}
    return result


def extract_config(filebuf):
    if not HAVE_PYCYPTODOMEX:
        log.error("Missed pycryptodomex. Run: poetry install")
        return {}
    pe = False
    with suppress(pefile.PEFormatError, ValueError):
        pe = pefile.PE(data=filebuf)
        for section in pe.sections:
            if b".rsrc" in section.Name:
                break

    if not pe:
        return

    config_dict = {}
    try:
        with io.BytesIO(filebuf) as f:
            offset = 0x58  # resource section header
            f.seek(section.PointerToRawData + offset)
            data_len = int.from_bytes(f.read(4), "little")
            _guid = f.read(data_len)
            enc_data = f.read()
        dec_data = decode(enc_data)

        # dec_data to config format

        params = iter(dec_data["params"])
        for param in params:
            if DataType.STRING == param["type"]:
                item_name = param["value"]
                param = next(params)
                if DataType.BYTEARRAY == param["type"]:
                    pass
                elif DataType.DATETIME == param["type"]:
                    dt = param["value"]
                    config_dict[item_name] = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
                else:
                    config_dict[item_name] = str(param["value"])
    except Exception as e:
        log.error("nanocore error: %s", e)

    cncs = []

    if config_dict.get("PrimaryConnectionHost"):
        cncs.append(config_dict["PrimaryConnectionHost"])
    if config_dict.get("PrimaryConnectionHost"):
        cncs.append(config_dict["BackupConnectionHost"])
    if config_dict.get("ConnectionPort") and cncs:
        port = config_dict["ConnectionPort"]
        config_dict["cncs"] = [f"{cnc}:{port}" for cnc in cncs]
    return config_dict


if __name__ == "__main__":
    import sys
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
