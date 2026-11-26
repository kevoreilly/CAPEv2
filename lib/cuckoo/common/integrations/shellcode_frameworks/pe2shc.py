"""pe2shc (github.com/hasherezade/pe_to_shellcode): the redirection stub written over the DOS
header, calling the loader appended after the PE's last section."""

import re

from lib.cuckoo.common.integrations.shellcode_frameworks import api

NAME = "pe2shc"
PRIORITY = 30


# pe2shc (github.com/hasherezade/pe_to_shellcode, pe2shc/main.cpp): the DOS header is overwritten
# with a redirection stub calling the loader appended at the end of the original file
_PE2SHC = (
    (re.compile(rb"MZER\xe8\x00\x00\x00\x00\x58\x83\xe8\x09\x50\x05(.{4})\xff\xd0\xc3", re.S), "x86"),
    (re.compile(rb"MZER\xe8\x00\x00\x00\x00\x59\x48\x83\xe9\x09\x48\x8b\xc1\x48\x05(.{4})\xff\xd0\xc3", re.S), "x64"),
    (re.compile(rb"MZER\xe8\x00\x00\x00\x00\x5b\x48\x83\xeb\x09\x53\x48\x81\xc3(.{4})\xff\xd3\xc3", re.S), "x86 (old loader)"),
)


def identify(data):
    for rx, arch in _PE2SHC:
        m = rx.match(data)
        if not m:
            continue
        stub = api.u32(m.group(1), 0)
        pes = api.find_embedded_pes(data[:0x1000], 0x1000, 1)
        if not pes or pes[0]["offset"] != "0x0":
            continue
        size = api.pe_raw_size(data, int(pes[0]["nt_offset"], 16)) or 0
        if not size <= stub < len(data):
            continue  # the loader must sit after the PE's last section
        kind = f"{pes[0]['arch']} {'DLL' if pes[0]['dll'] else 'EXE'}"
        payload = {
            "extract": lambda: bytes(data[:stub]) if 0 < stub <= api.extract_max() else None,
            "offset": 0,
            "description": f"pe2shc original PE: {kind}",
        }
        return {"name": "pe2shc", "confidence": "identified", "arch": pes[0]["arch"], "_payload": payload,
                "evidence": [f"pe2shc {arch} redirection stub in the DOS header", f"it calls the loader appended at {stub:#x}, after the PE's sections"],
                "details": {"payload": kind, "payload_size": stub, "loader_stub": f"{stub:#x}-{len(data):#x}"}, "iocs": {},
                "regions": [{"start": 0, "size": stub, "status": "structural", "framework": "pe2shc", "source": "file before the loader stub",
                             "result_type": "pe", "result": f"{kind}, {stub} bytes", "entropy": None, "decoded_entropy": None}]}  # fmt: skip
    return None
