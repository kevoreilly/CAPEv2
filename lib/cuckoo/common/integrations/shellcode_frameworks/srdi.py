"""sRDI (github.com/monoxgas/sRDI): the fixed bootstrap, its decoded fields, and the DLL it
points at (which must be a PE of the bootstrap's architecture)."""

import re

from lib.cuckoo.common.integrations.shellcode_frameworks import api

NAME = "sRDI"
PRIORITY = 20


# sRDI (github.com/monoxgas/sRDI, Python/ShellcodeRDI.py): fixed bootstraps, variable fields captured
_SRDI_X64 = re.compile(
    rb"\xe8\x00\x00\x00\x00\x59\x49\x89\xc8\xba(.{4})\x49\x81\xc0(.{4})\x41\xb9(.{4})\x56\x48\x89\xe6\x48\x83\xe4\xf0"
    rb"\x48\x83\xec\x30\x48\x89\x4c\x24\x28\x48\x81\xc1(.{4})\xc7\x44\x24\x20(.{4})\xe8\x05\x00\x00\x00\x48\x89\xf4\x5e\xc3",
    re.S,
)
_SRDI_X86 = re.compile(
    rb"\xe8\x00\x00\x00\x00\x58\x55\x89\xe5\x89\xc2\x68(.{4})\x50\x81\xc2(.{4})\x68(.{4})\x52\x68(.{4})\x05(.{4})\x50"
    rb"\xe8\x05\x00\x00\x00\x83\xc4\x14\xc9\xc3",
    re.S,
)
SRDI_FLAGS = {0x1: "clear header", 0x2: "clear memory", 0x4: "obfuscate imports", 0x8: "pass shellcode base"}


def identify(data):
    for rx, arch in ((_SRDI_X64, "x64"), (_SRDI_X86, "x86")):
        m = rx.search(data, 0, 0x1000)
        if not m:
            continue
        g = [int.from_bytes(x, "little") for x in m.groups()]
        if arch == "x64":
            fhash, ud_off, ud_len, dll_off, flags = g
        else:
            flags, ud_off, ud_len, fhash, dll_off = g
        base = m.start() + 5  # the pop receives this address
        dll = base + dll_off
        pes = api.find_embedded_pes(data[dll : dll + 0x1000], 0x1000, 1) if 0 < dll < len(data) else []
        if not (pes and pes[0]["offset"] == "0x0" and data[dll : dll + 2] == b"MZ" and pes[0]["arch"] == arch):
            continue  # the computed DLL offset must land on a PE of the bootstrap's architecture
        size = api.pe_raw_size(data, dll + int(pes[0]["nt_offset"], 16)) or None
        kind = f"{arch} {'DLL' if pes[0]['dll'] else 'EXE'}"
        details = {"payload": kind, "payload_size": size, "export_hash": f"{fhash:#x}" + (" (DllMain only)" if fhash == 0x10 else ""),
                   "flags": ", ".join(v for k, v in SRDI_FLAGS.items() if flags & k) or "none"}  # fmt: skip
        if flags >> 16:
            details["import_delay"] = f"{flags >> 16} s"
        ud = data[base + ud_off : base + ud_off + min(ud_len, 256)] if ud_len and base + ud_off < len(data) else b""
        if ud and all(0x20 <= c < 0x7F for c in ud):
            details["user_data"] = ud.decode()
        end = dll + size if size else len(data)
        payload = {
            "extract": lambda: bytes(data[dll:end]) if 0 < end - dll <= api.extract_max() and end <= len(data) else None,
            "offset": dll,
            "description": f"sRDI DLL: {kind}",
        }
        return {"name": "sRDI", "confidence": "identified", "arch": arch, "_payload": payload,
                "evidence": [f"sRDI {arch} bootstrap at {m.start():#x} (fixed template, variable fields decoded)",
                             f"the DLL offset it computes ({dll:#x}) holds the payload: {kind}"],
                "details": details, "iocs": {},
                "regions": [{"start": dll, "size": size, "status": "structural", "framework": "sRDI",
                             "source": f"DLL offset from the bootstrap at {m.start():#x}", "result_type": "pe",
                             "result": f"{kind}" + (f", {size} bytes" if size else ""), "entropy": None,
                             "decoded_entropy": None}]}  # fmt: skip
    return None
