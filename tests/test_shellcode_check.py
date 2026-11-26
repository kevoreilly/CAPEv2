# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import base64
import os
import random
import struct
import sys
import zlib

import pytest

from lib.cuckoo.common.integrations.shellcode_check import INDICATORS, analyse

pytest.importorskip("capstone")

# Small hand-assembled test stubs (keystone), representative of common loaders.
MSF_STYLE_X86 = bytes.fromhex(
    "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d0"
    "8b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b"
    "0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12eb865d686c6c00006833322e64687773325f54684c772607ffd5"
    "6a40680010000068000040006a006858a453e5ffd56a0068f0b5a256ffd5"
)
MSF_STYLE_X64 = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041"
    "c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b3488"
    "4801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b0488"
    "4801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49c7c63332000041564989e64c89f141ba4c"
    "772607ffd54831c9ba0010000041b80030000041b94000000041ba58a453e5ffd5c3"
)
DIRECT_SYSCALL_X64 = bytes.fromhex(
    "4883ec2848c7c1ffffffff4831d2e8050000004883c428c34989cab8180000000f05c34989cab8500000000f05c34989cab83a0000000f05c3"
)
HEAVENS_GATE_X86 = bytes.fromhex("5589e553568b75086a33e80000000083042405cb4889f1ff115e5b5dc3")
PUSH_STRINGS_X86 = bytes.fromhex("31c050682e6578656863616c6389e36a015368318b6f87ffd55068f0b5a256ffd5")
FNSTENV_STUB_X86 = bytes.fromhex("d9eed97424f45b31c9b1808173180d1c2b3a83c304e2f4")
JMP_CALL_POP_STUB_X86 = bytes.fromhex("eb0f5e31c966b9000280365a46e2faeb05e8ecffffff")
# Start of a real in-the-wild x64 stager (truncated at 180 bytes): call/pop/lea own
# base, align stack, then an export resolver: MZ/PE checks, export dir, djb2.
USER_SAMPLE_X64 = bytes.fromhex(
    "e80000000059488d49fb4883e4f04883ec20e869100000ebfe0f0b90909090904889c84885c90f84a500000080394d0f85930000008079015a"
    "0f85890000004189d38b513c813c1150450000757a8b9411880000004889d14801c285c974695756538b7a188d4fff81f9ff3f0000775b8b"
    "5a208b722431c94801c34801c6448b0c8b41b8051500004901c1450fb6114584d2740c456bc02149ffc14501d0ebeb4539c3751a440fb70c"
    "4e443b4a14730f8b521c4a"
)
HELLS_GATE_X64 = bytes.fromhex("534889cb4531c04a8d040381384c8bd1b874168038e9750d4983c0204981f80004000072e231c05bc30fb740045bc3")
INDIRECT_SYSCALL_X64 = bytes.fromhex("4989cab818000000ff25400000004989cab85000000041ffe34989cab83a000000ff2530000000")
EGG_HUNTER_X86 = bytes.fromhex("6681caff0f42526a0258cd2e3c055a74efb89050905089d7af75eaaf75e7ffe7")
AMSI_PATCH_X64 = bytes.fromhex(
    "4883ec4848b8416d73695363616e488944242048b842756666657200004889442428488d5424204889d9ff57104889c64889c1ba01000000"
    "41b8400000004c8d4c2430ff5718c606c34883c448c3"
)
# Reflective PE loaders (headers, section copy, relocations, imports, entry point)
REFLECTIVE_LOADER_X64 = bytes.fromhex(
    "53565741544155415641574883ec404889cb4863433c4c8d240341813c24504500000f8530010000418b54245031c941b80030000041b940"
    "000000ff9424800000004989c54c89ef4889de418b4c2454f3a4450fb7742406410fb74424144d8d7c04184585f6741d418b7f0c4c01ef41"
    "8b77144801de418b4f10f3a44983c72841ffceebde4c89e8492b4424304989c2418bb424b000000085f6743f4c01ee8b3e8b4e0485c97433"
    "4c8d46084c8d0c0e4d39c87321410fb70089c2c1ea0c25ff0f000083fa0a75084801f84d015405004983c002ebda4801ceebc4418bb42490"
    "00000085f6745c4c01ee8b4e0c85c974524c01e9ff9424880000004989c68b3e4c01ef448b7e104d01ef488b174885d2742b480fbae23f72"
    "07498d541502eb0681e2ffff00004c89f1ff9424900000004989074883c7084983c708ebcd4883c614eba7418b4424284c01e84c89e9ba01"
    "0000004531c0ffd04883c440415f415e415d415c5f5e5bc3"
)
REFLECTIVE_LOADER_X86 = bytes.fromhex(
    "5589e583ec205356578b5d088b433c01d88945fc8138504500000f85fe0000006a406800300000ff70506a00ff550c8945f889c789de8b55"
    "fc8b4a54f3a40fb74a060fb742148d54021885c97418518b7a0c037df88b721401de8b4a10f3a45983c22849ebe48b55fc8b45f82b423489"
    "45f48bb2a000000085f6743c0375f88b3e8b4e0485c974308d560801f139ca73230fb70250c1e80c83f80358751125ff0f000001f80345f8"
    "538b5df401185b83c202ebd989ceebc78b55fc8bb28000000085f674470375f88b460c85c0743d0345f850ff55108945f08b7e10037df88b"
    "0785c07422a90000008075080345f883c002eb0525ffff000050ff75f0ff5514890783c704ebd883c614ebbc8b55fc8b42280345f86a006a"
    "01ff75f8ffd05f5e5b89ec5dc3"
)
# sRDI-style bootstrap: call/pop own base, add PE offset (placeholder 0x11223344), call loader at +0x40
SRDI_BOOT_X64 = bytes.fromhex("e80000000059488d49fb4883e4f04883ec284881c144332211e822000000cc")
# MSF-style resolver + reverse TCP: WSAStartup/WSASocketA/connect hashes, sockaddr 192.168.56.101:4444
REVERSE_TCP_X86 = bytes.fromhex(
    "fce8890000006089e531d2648b52308b520c8b52148b72280fb74a2631ff31c0ac3c617c022c20c1cf0d01c7e2f052578b52108b423c01d0"
    "8b407885c0744a01d0508b48188b582001d3e33c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e2588b582401d3668b"
    "0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b6833320000687773325f54684c772607ffd581ec9001000054680101"
    "00006829806b00ffd5505050504050405068ea0fdfe0ffd59768c0a83865680200115c89e66a1056576899a57461ffd5c3"
)
SOCKADDR_X64 = bytes.fromhex("4883ec4849bc0200115cc0a8386541544989e54889f94c89ea6a10415841ba99a57461ffd54883c450c3")
# BeingDebugged, NtGlobalFlag, cpuid hypervisor bit, KUSER_SHARED_DATA, rdtsc pair
ANTI_ANALYSIS_X86 = bytes.fromhex(
    "5364a1300000000fb6480285c975318b486883e1707529b8010000000fa20fbae11f721ca11400fe7f0f3189c30f3129d83d001000007708"
    "8b400c8b40145bc331c05bc3"
)
# FreshyCalls / SysWhispers2 style: 'Zw' filter and syscall-byte search via registers, 32-byte stride
ZW_SORT_X64 = bytes.fromhex(
    "5341bc5a77000041b90f05000031c9448b148b6645392275134d8d421066453b481274064983c020ebf3ffc0ffc139d172dd5bc3"
)
# PEB walk matching 'ntdl' / 'l.dl' after OR 0x20202020 case folding
NAME_CHUNKS_X64 = bytes.fromhex(
    "6548a16000000000000000488b4018488b7020488b56508b020d202020203d6e74646c750f8b42040d202020203d6c2e646c7405488b36ebda488b4620c3"
)
# TEB self pointer -> PEB -> Ldr, crc32-instruction name hashing
CRC32_TEB_X64 = bytes.fromhex(
    "6548a13000000000000000488b4060488b4018488b70204531c0488b56500fb60a84c9740bf2440f38f0c148ffc2ebee4181f878563412c3"
)
# Chaskey permutation rounds (Donut) + search for a 'jmp [rbx]' gadget
CHASKEY_GADGET_X86 = bytes.fromhex(
    "5589e5568b7508b91000000001d8c1c30531c3c1c01001fac1c70831d701f8c1c70d31c701dac1c30731d3c1c2104975db8b4d0c668139ff"
    "23740341ebf689c85e5dc3"
)
# pe2shc-style stub: pop return address, rebase to image start, call loader at +0x20
PE2SHC_STUB_X86 = bytes.fromhex("5983e9096a006a006a0051e810000000c3")


def _fake_pe(x64=True, dll=True, size=0x400):
    """Header-only PE image (enough for find_embedded_pes)."""
    pe = bytearray(size)
    pe[0:2] = b"MZ"
    pe[0x3C:0x40] = (0x80).to_bytes(4, "little")
    pe[0x80:0x84] = b"PE\x00\x00"
    pe[0x84:0x86] = (0x8664 if x64 else 0x14C).to_bytes(2, "little")
    pe[0x86:0x88] = (1).to_bytes(2, "little")
    pe[0x94:0x96] = (0xF0 if x64 else 0xE0).to_bytes(2, "little")
    pe[0x96:0x98] = (0x2022 if dll else 0x22).to_bytes(2, "little")
    pe[0x98:0x9A] = (0x20B if x64 else 0x10B).to_bytes(2, "little")
    pe[0x98 + 0x38 : 0x98 + 0x3C] = (0x5000).to_bytes(4, "little")
    return bytes(pe)


def _rand(n, seed):
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


@pytest.mark.parametrize(
    "data, arch, tags",
    [
        (MSF_STYLE_X86, "x86", {"peb_walk", "api_hash_loop", "export_table_parse", "known_api_hash"}),
        (MSF_STYLE_X64, "x64", {"peb_walk", "api_hash_loop", "export_table_parse", "known_api_hash"}),
        (DIRECT_SYSCALL_X64, "x64", {"direct_syscall"}),
        (HEAVENS_GATE_X86, "x86", {"heavens_gate"}),
        (PUSH_STRINGS_X86, "x86", {"known_api_hash", "stack_string"}),
        (FNSTENV_STUB_X86 + _rand(0x200, 1), "x86", {"decoder_stub", "getpc_fnstenv"}),
        (JMP_CALL_POP_STUB_X86 + _rand(0x200, 2), "x86", {"decoder_stub", "getpc_jmp_call_pop"}),
        (USER_SAMPLE_X64, "x64", {"getpc_call_pop", "export_table_parse", "api_hash_loop", "pe_magic_check"}),
        (HELLS_GATE_X64, "x64", {"syscall_stub_scan"}),
        (INDIRECT_SYSCALL_X64 + b"\xcc" * 64, "x64", {"indirect_syscall"}),
        (EGG_HUNTER_X86, "x86", {"egg_hunter"}),
        (AMSI_PATCH_X64, "x64", {"amsi_etw_patch", "stack_string_api"}),
        (REFLECTIVE_LOADER_X64, "x64", {"reflective_pe_loader", "pe_reloc_fixup", "pe_import_resolve"}),
        (REFLECTIVE_LOADER_X86, "x86", {"reflective_pe_loader", "pe_reloc_fixup", "pe_import_resolve"}),
    ],
)
def test_confirms_shellcode(data, arch, tags):
    r = analyse(data)
    assert r["verdict"] == "shellcode", r
    assert r["arch"] == arch
    assert tags <= set(r["tags"])
    assert r["evidence"]


@pytest.mark.parametrize("payload", [MSF_STYLE_X86, MSF_STYLE_X64, PUSH_STRINGS_X86, DIRECT_SYSCALL_X64])
def test_confirms_shellcode_not_at_offset_zero(payload):
    # unpacked regions often carry data/config ahead of the code
    data = _rand(0x180, 3) + b"C2=" + b"a" * 61 + payload + b"\x00" * 256
    assert analyse(data)["verdict"] == "shellcode"


def test_random_data_is_not_shellcode():
    rng = random.Random(1337)
    for _ in range(300):
        r = analyse(bytes(rng.getrandbits(8) for _ in range(rng.choice((64, 512, 1262, 4096)))))
        assert r["verdict"] not in ("shellcode", "likely"), r["tags"]


@pytest.mark.parametrize(
    "data, verdict",
    [
        (b"\x00" * 600 + b"\x41" * 8 + b"\x00" * 36, "data"),
        (b"This is plainly a configuration string, not code at all. " * 10, "data"),
        (bytes.fromhex("8bff558bece900000000"), "trampoline"),  # hot-patch prologue + jmp out
        (bytes.fromhex("6834120077c3"), "trampoline"),  # push imm; ret
        (bytes.fromhex("48b87856341200000000ffe0"), "trampoline"),  # mov rax, imm64; jmp rax
    ],
)
def test_non_shellcode_verdicts(data, verdict):
    assert analyse(data)["verdict"] == verdict


def test_va_hint_forces_x64_and_is_fast():
    r = analyse(MSF_STYLE_X64, va="0x7ff6a0000000")
    assert r["arch"] == "x64" and r["verdict"] == "shellcode"
    assert r["time_ms"] < 500


def test_cape_processing_attaches_shellcode_check(tmp_path, monkeypatch):
    import hashlib
    import json

    import lib.cuckoo.common.integrations.file_extra_info as fei_mod
    import lib.cuckoo.common.integrations.shellcode_utils as sc_utils
    import modules.processing.CAPE as cape_mod

    if not sc_utils.HAVE_SHELLCODE_CHECK:
        pytest.skip("static_shellcode_check disabled in processing.conf")
    monkeypatch.setattr(cape_mod, "mongo_find_one", lambda *a, **k: None)
    monkeypatch.setattr(cape_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(fei_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(sc_utils, "SHELLCODE_ON_PAYLOADS", True)

    payloads = {9: MSF_STYLE_X86, 4: _rand(1262, 7)}
    (tmp_path / "CAPE").mkdir()
    with open(tmp_path / "files.json", "w") as fh:
        for code, data in payloads.items():
            sha = hashlib.sha256(data).hexdigest()
            (tmp_path / "CAPE" / sha).write_bytes(data)
            proc_path = "C:\\\\Users\\\\x\\\\AppData\\\\Local\\\\Temp\\\\a.exe"
            extra = "0x00790000;?" if code == 9 else f"{proc_path};?4608;?"
            meta = f"{code};?{proc_path};?{proc_path};?{extra}"
            fh.write(json.dumps({"path": f"CAPE/{sha}", "filepath": proc_path, "pids": [3768], "metadata": meta}) + "\n")

    proc = cape_mod.CAPE()
    proc.set_path(str(tmp_path))
    proc.task = {"id": 1, "category": "url", "target": "http://x", "options": ""}
    proc.results = {}

    class _Opts(dict):
        __getattr__ = dict.get

    proc.options = _Opts(buffer=8192, replace_patterns="")
    out = proc.run()

    by_code = {p["cape_type_code"]: p for p in out["payloads"]}
    assert by_code[9]["static_shellcode_check"]["verdict"] == "shellcode"
    assert by_code[4]["static_shellcode_check"]["verdict"] not in ("shellcode", "likely")


def test_cape_processing_skips_dumps_that_are_complete_pes(tmp_path, monkeypatch):
    """A region dumped as shellcode that is really a whole PE (e.g. an unpacked PikaBot payload) gets
    no shellcode result; a PE whose DOS header runs (pe2shc) is still shellcode and is checked."""
    import hashlib
    import json

    import lib.cuckoo.common.integrations.file_extra_info as fei_mod
    import lib.cuckoo.common.integrations.shellcode_utils as sc_utils
    import modules.processing.CAPE as cape_mod

    if not sc_utils.HAVE_SHELLCODE_CHECK:
        pytest.skip("static_shellcode_check disabled in processing.conf")
    monkeypatch.setattr(cape_mod, "mongo_find_one", lambda *a, **k: None)
    monkeypatch.setattr(cape_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(fei_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(sc_utils, "SHELLCODE_ON_PAYLOADS", True)
    pe = _pe_file()
    exec_pe = bytearray(pe)
    redir = b"MZER" + bytes.fromhex("e800000000594883e909488bc14805") + len(pe).to_bytes(4, "little") + b"\xff\xd0\xc3"
    exec_pe[: len(redir)] = redir
    exec_pe = bytes(exec_pe) + MSF_STYLE_X64
    (tmp_path / "CAPE").mkdir()
    with open(tmp_path / "files.json", "w") as fh:
        for data in (pe, exec_pe):
            sha = hashlib.sha256(data).hexdigest()
            (tmp_path / "CAPE" / sha).write_bytes(data)
            meta = "9;?C:\\\\x\\\\a.exe;?C:\\\\x\\\\a.exe;?0x00790000;?"
            fh.write(json.dumps({"path": f"CAPE/{sha}", "filepath": "C:\\\\x\\\\a.exe", "pids": [3768], "metadata": meta}) + "\n")

    class _Opts(dict):
        __getattr__ = dict.get

    proc = cape_mod.CAPE()
    proc.set_path(str(tmp_path))
    proc.task = {"id": 1, "category": "url", "target": "http://x", "options": ""}
    proc.results = {}
    proc.options = _Opts(buffer=8192, replace_patterns="")
    out = {p["sha256"]: p for p in proc.run()["payloads"]}
    assert "static_shellcode_check" not in out[hashlib.sha256(pe).hexdigest()]
    assert out[hashlib.sha256(exec_pe).hexdigest()]["static_shellcode_check"]["verdict"] == "shellcode"


def test_api_hash_algorithms_match_published_constants():
    from lib.cuckoo.common.integrations.shellcode_check import KNOWN_API_HASHES as H

    assert H[0xEC0E4E8E] == "ror13: LoadLibraryA"  # classic / Stephen Fewer ReflectiveLoader
    assert H[0x7C0DFCAA] == "ror13: GetProcAddress"
    assert H[0x6A4ABC5B] == "ror13: module kernel32.dll"  # KERNEL32.DLL as UTF-16 (ReflectiveLoader)
    assert H[0x0726774C] == "block_api ror13: kernel32!LoadLibraryA"  # Metasploit / Cobalt Strike
    assert H[0x7802F749] == "block_api ror13: kernel32!GetProcAddress"
    assert H[0xA779563A] == "block_api ror13: wininet!InternetOpenA"


def test_srdi_style_staged_pe():
    pe_off = 0x40 + len(REFLECTIVE_LOADER_X64)
    pe_off += -pe_off % 16
    boot = SRDI_BOOT_X64.replace(bytes.fromhex("44332211"), pe_off.to_bytes(4, "little"))
    blob = boot.ljust(0x40, b"\x90") + REFLECTIVE_LOADER_X64
    blob = blob.ljust(pe_off, b"\x90") + _fake_pe(x64=True)
    r = analyse(blob)
    assert r["verdict"] == "shellcode" and r["arch"] == "x64"
    assert {"reflective_pe_loader", "staged_pe", "embedded_pe", "getpc_call_pop"} <= set(r["tags"])
    assert r["embedded_pe"][0]["offset"] == hex(pe_off) and r["embedded_pe"][0]["dll"]


def _pe2shc(total_size):
    pe = bytearray(_fake_pe(x64=False, dll=False) + _rand(total_size, 11))
    stub_off = len(pe) + (-len(pe) % 16)
    pe = pe.ljust(stub_off, b"\x00")
    pe[0:9] = b"MZER\xe8" + (stub_off - 9).to_bytes(4, "little")  # dec ebp/pop edx/inc ebp/push edx; call stub
    return bytes(pe) + PE2SHC_STUB_X86.ljust(0x20, b"\x90") + REFLECTIVE_LOADER_X86


def test_pe2shc_style_stub_found_past_head_window():
    blob = _pe2shc(512 * 1024)  # stub sits ~512 KB in, well past the 256 KB head window
    r = analyse(blob)
    assert r["truncated"] and r["scanned"] == 256 * 1024
    assert r["verdict"] == "shellcode", r["tags"]
    assert {"executable_pe_header", "reflective_pe_loader", "staged_pe"} <= set(r["tags"])
    assert r["deep_windows"][0]["verdict"] == "shellcode"

    shallow = analyse(blob, deep_scan=False)
    assert "reflective_pe_loader" not in shallow["tags"]
    whole = analyse(blob, max_scan=0)
    assert not whole["truncated"] and "reflective_pe_loader" in whole["tags"]


def test_plain_pe_is_not_shellcode():
    r = analyse(_fake_pe() + _rand(4096, 12))
    assert r["verdict"] == "data" and r["reason"] == "PE image"


def test_stub_in_mostly_zeroed_allocation():
    r = analyse(MSF_STYLE_X64 + b"\x00" * (1024 * 1024))
    assert r["verdict"] == "shellcode" and r["truncated"]


def test_gemini_yara_guard_pitfall_documented():
    """The common non-PE guard 'uint32(uint32(0x3C)) != 0x4550' is undefined
    (so false) whenever the dword at 0x3C points past EOF - i.e. on most
    shellcode. Kept here as an executable note for rule writers."""
    yara = pytest.importorskip("yara")
    bad = "uint16(0) != 0x5A4D and uint32(uint32(0x3C)) != 0x00004550"
    good = "uint16(0) != 0x5A4D and not (uint32(0x3C) < filesize - 4 and uint32(uint32(0x3C)) == 0x00004550)"
    rule = "rule r {{ strings: $a = {{ E8 00 00 00 00 59 48 8D 49 FB }} condition: {} and $a in (0..16) }}"
    assert not yara.compile(source=rule.format(bad)).match(data=USER_SAMPLE_X64)
    assert yara.compile(source=rule.format(good)).match(data=USER_SAMPLE_X64)


def test_reverse_shell_sockaddr_capabilities_and_iocs():
    r = analyse(REVERSE_TCP_X86)
    assert r["verdict"] == "shellcode"
    assert "sockaddr_literal" in r["tags"]
    assert r["iocs"]["network"] == ["192.168.56.101:4444"]
    assert {"WSAStartup", "WSASocketA", "connect"} <= set(r["capabilities"]["raw_socket"])
    r = analyse(SOCKADDR_X64)
    assert r["arch"] == "x64" and r["iocs"]["network"] == ["192.168.56.101:4444"]


def test_anti_analysis_indicators():
    r = analyse(ANTI_ANALYSIS_X86)
    assert {"anti_debug_peb", "anti_vm_cpuid", "kuser_shared_data", "rdtsc_timing"} <= set(r["tags"])
    assert r["verdict"] == "likely"  # anti-analysis alone does not prove shellcode


def test_self_base_and_shikata():
    assert "getpc_self_base" in analyse(USER_SAMPLE_X64)["tags"]
    r = analyse(bytes.fromhex("d9ee") + FNSTENV_STUB_X86[2:] + _rand(0x200, 1))
    # an FPU GetPC decoder stub; 'shikata_ga_nai' is kept for a decoder proven by decoding it
    assert "fpu_getpc_decoder" in r["tags"] and "shikata_ga_nai" not in r["tags"]


def test_iocs_from_strings():
    blob = MSF_STYLE_X64 + (
        b"\x00Mozilla/5.0 (Windows NT 10.0; Win64; x64)\x00http://10.11.12.13:8080/submit.php?id=1\x00"
        b"cdn.example-updates.xyz\x00"
        + "\\\\.\\pipe\\msagent_7f\x00".encode("utf-16le")
        + b"C:\\Users\\Public\\svc.exe\x00SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00cmd.exe /c whoami\x00"
    )
    iocs = analyse(blob)["iocs"]
    assert iocs["urls"] == ["http://10.11.12.13:8080/submit.php?id=1"]
    assert iocs["ips"] == ["10.11.12.13:8080"]
    assert iocs["domains"] == ["cdn.example-updates.xyz"]
    assert iocs["pipes"] == ["\\\\.\\pipe\\msagent_7f"]
    assert iocs["paths"] == ["C:\\Users\\Public\\svc.exe"]
    assert iocs["registry"] == ["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]
    assert iocs["commands"] == ["cmd.exe /c whoami"]
    assert iocs["user_agents"][0].startswith("Mozilla/5.0")
    assert "files" not in iocs  # cmd.exe / svc.exe already shown in fuller indicators
    assert not analyse(MSF_STYLE_X64, extract_iocs=False).get("iocs")


def test_indicator_list_and_match_context():
    r = analyse(MSF_STYLE_X64)
    by_name = {i["name"]: i for i in r["indicators"]}
    assert by_name["peb_walk"]["confidence"] == "high" and by_name["peb_walk"]["group"] == "peb_walk"
    assert by_name["api_hash_loop"]["offsets"]
    loop = next(e for e in r["evidence"] if e["indicator"] == "api_hash_loop")
    # multi-line matches are one block: every stage highlighted with a note
    hit = {line[0]: line for line in loop["context"] if line[2]}
    assert hit[loop["offset"]][1].startswith("ror") and hit[loop["offset"]][3]
    assert any(line[1].startswith("lodsb") for line in hit.values())
    assert len(loop["context"]) <= 22
    assert "context" not in analyse(MSF_STYLE_X64, evidence_context=0)["evidence"][0]


def test_config_section():
    from lib.cuckoo.common.config import Config

    section = Config("processing").static_shellcode_check
    assert dict(section) == {
        "enabled": False,
        "on_demand": False,
        "cape_payloads": True,
        "submitted_shellcode": True,
        "shellcode_depth": 262144,
        "framework_detections": True,
        "extract_payloads": True,
    }


def test_entry_offset_hint():
    blob = _rand(0x300, 31) + MSF_STYLE_X86
    r = analyse(blob, entry=hex(0x300), arch="x86")
    assert r["verdict"] == "shellcode" and r["entry"] == "0x300"


def test_submitted_shellcode_package(tmp_path, monkeypatch):
    import lib.cuckoo.common.integrations.file_extra_info as fei_mod
    import lib.cuckoo.common.integrations.shellcode_utils as sc_utils
    import modules.processing.CAPE as cape_mod

    if not sc_utils.HAVE_SHELLCODE_CHECK:
        pytest.skip("static_shellcode_check disabled in processing.conf")
    monkeypatch.setattr(cape_mod, "mongo_find_one", lambda *a, **k: None)
    monkeypatch.setattr(cape_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(fei_mod, "HAVE_VIRUSTOTAL", False)
    sample = tmp_path / "binary"
    sample.write_bytes(_rand(0x100, 32) + MSF_STYLE_X64)

    class _Opts(dict):
        __getattr__ = dict.get

    def run(package, on):
        monkeypatch.setattr(sc_utils, "SHELLCODE_ON_SUBMISSION", on)
        proc = cape_mod.CAPE()
        proc.set_path(str(tmp_path))
        proc.file_path = str(sample)
        proc.task = {"id": 1, "category": "file", "target": str(sample), "package": package, "options": "offset=0x100"}
        proc.results = {}
        proc.options = _Opts(buffer=8192, replace_patterns="")
        proc.run()
        return proc.results["target"]["file"].get("static_shellcode_check")

    assert run("shellcode_x64", False) is None  # off by default
    r = run("shellcode_x64", True)
    assert r["verdict"] == "shellcode" and r["arch"] == "x64" and r["entry"] == "0x100"
    assert run("exe", True) is None  # only the shellcode packages


@pytest.mark.parametrize(
    "data, tags",
    [
        (ZW_SORT_X64, {"syscall_ssn_sort", "gadget_scan"}),
        (NAME_CHUNKS_X64, {"module_name_compare", "peb_walk"}),
        (CRC32_TEB_X64, {"api_hash_loop", "peb_walk"}),
        (CHASKEY_GADGET_X86, {"chaskey_cipher", "gadget_scan"}),
    ],
)
def test_loader_techniques(data, tags):
    assert tags <= set(analyse(data)["tags"])


def test_cobalt_strike_style_executable_header():
    """MZAR: pop r10; push r10; push rbp; mov rbp,rsp; sub rsp,0x20; lea rbx,[rip-0x16]; mov rdi,rbx; add rbx,X; call rbx"""
    pe = bytearray(_fake_pe(x64=True) + _rand(0x400, 21))
    loader_off = len(pe)
    hdr = bytes.fromhex("4d5a4152554889e54881ec20000000488d1deaffffff4889df4881c3")
    hdr += loader_off.to_bytes(4, "little") + b"\xff\xd3"
    pe[: len(hdr)] = hdr
    r = analyse(bytes(pe) + REFLECTIVE_LOADER_X64)
    assert r["verdict"] == "shellcode" and r["arch"] == "x64"
    assert {"executable_pe_header", "reflective_pe_loader", "staged_pe"} <= set(r["tags"])
    ev = next(e for e in r["evidence"] if e["indicator"] == "executable_pe_header")
    assert ev["insn"].endswith(hex(loader_off))


def test_donut_style_call_over_instance():
    blob = b"\xe8" + (0x600).to_bytes(4, "little") + _rand(0x600, 22) + b"\x59" + MSF_STYLE_X64[1:]
    r = analyse(blob)
    assert r["verdict"] == "shellcode"
    assert {"getpc_call_over_data", "peb_walk", "api_hash_loop"} <= set(r["tags"])


def test_position_independence():
    assert analyse(MSF_STYLE_X86)["pic"] == "yes"
    assert analyse(REVERSE_TCP_X86)["pic"] == "yes"
    # compiled-style x86: absolute globals and an IAT call
    compiled = bytes.fromhex(
        "558bec83ec10a1 00304000 8945fc 8b0d 04304000 51 ff15 00204000 8b55fc 8915 08304000 33c0 8be5 5dc3".replace(" ", "")
    )
    r = analyse(compiled * 3)
    assert r["pic"] == "no"


def test_every_indicator_has_a_location_even_with_many_hashes():
    """Many hash constants ahead of the resolver must not crowd out other indicators."""
    from lib.cuckoo.common.integrations.shellcode_check import KNOWN_API_HASHES, MAX_EVIDENCE_PER_INDICATOR

    hashes = [h for h in KNOWN_API_HASHES if h < 0x80000000][:40]
    head = b"".join(b"\xba" + h.to_bytes(4, "little") for h in hashes)  # mov edx, <hash> x40
    r = analyse(head + MSF_STYLE_X64, arch="x64")
    by_name = {i["name"]: i for i in r["indicators"]}
    assert {"known_api_hash", "api_hash_loop", "peb_walk", "export_table_parse"} <= set(by_name)
    assert all(i["offsets"] for i in r["indicators"]), [i["name"] for i in r["indicators"] if not i["offsets"]]
    per = {}
    for e in r["evidence"]:
        per[e["indicator"]] = per.get(e["indicator"], 0) + 1
    assert max(per.values()) <= MAX_EVIDENCE_PER_INDICATOR


def test_whole_blob_indicators_have_locations():
    pe_off = 0x40 + len(REFLECTIVE_LOADER_X64)
    pe_off += -pe_off % 16
    boot = SRDI_BOOT_X64.replace(bytes.fromhex("44332211"), pe_off.to_bytes(4, "little"))
    blob = (boot.ljust(0x40, b"\x90") + REFLECTIVE_LOADER_X64).ljust(pe_off, b"\x90") + _fake_pe(x64=True)
    r = analyse(blob)
    by_name = {i["name"]: i for i in r["indicators"]}
    assert by_name["staged_pe"]["offsets"] == [hex(pe_off)]
    assert by_name["embedded_pe"]["offsets"] == [hex(pe_off)]


def test_shellcode_depth_from_config(tmp_path, monkeypatch):
    import lib.cuckoo.common.integrations.file_extra_info as fei_mod
    import lib.cuckoo.common.integrations.shellcode_utils as sc_utils
    import modules.processing.CAPE as cape_mod

    if not sc_utils.HAVE_SHELLCODE_CHECK:
        pytest.skip("static_shellcode_check disabled in processing.conf")
    monkeypatch.setattr(cape_mod, "mongo_find_one", lambda *a, **k: None)
    monkeypatch.setattr(cape_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(fei_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(sc_utils, "SHELLCODE_ON_SUBMISSION", True)
    monkeypatch.setattr(sc_utils, "SHELLCODE_DEPTH", 4096)
    sample = tmp_path / "binary"
    sample.write_bytes(MSF_STYLE_X64 + _rand(64 * 1024, 41))

    class _Opts(dict):
        __getattr__ = dict.get

    proc = cape_mod.CAPE()
    proc.set_path(str(tmp_path))
    proc.file_path = str(sample)
    proc.task = {"id": 1, "category": "file", "target": str(sample), "package": "shellcode_x64", "options": ""}
    proc.results = {}
    proc.options = _Opts(buffer=8192, replace_patterns="")
    proc.run()
    r = proc.results["target"]["file"]["static_shellcode_check"]
    assert r["scanned"] == 4096 and r["truncated"] and r["verdict"] == "shellcode"


def test_depth_still_flags_stub_past_it():
    """Larger than the depth: still analysed, and the deep scan follows the
    pe2shc header's call to a loader stub that sits beyond it."""
    r = analyse(_pe2shc(64 * 1024), max_scan=4096)
    assert r["scanned"] == 4096 and r["verdict"] == "shellcode"
    assert {"executable_pe_header", "reflective_pe_loader"} <= set(r["tags"])


def test_zero_padding_is_not_a_decoder_loop():
    r = analyse(b"\x90" * 16 + b"\x00\x02\x00\x00\xeb\xfa" + _rand(400, 42) + b"\x00" * 64)
    assert "decoder_loop" not in r["tags"]


GETPC_MOVESP_X86 = bytes.fromhex("e8000000008b1c2483c40483eb0564a1300000008b400c8b4014c3")
CRC32_SOFT_X86 = bytes.fromhex(
    "64a1300000008b400c8b70148b562883c9ff0fb60284c0741731c1bb08000000d1e9730681f12083b8ed4b75f342ebe2f7d181f978563412c3"
)
# ror13 AddVectoredExceptionHandler + CONTEXT.ContextFlags = CONTEXT_DEBUG_REGISTERS + Dr0/Dr7
HWBP_VEH_X64 = bytes.fromhex(
    "4881ecd804000041baa03e9b15ffd5488d4c2420c7413010001000488b47084889414848c74170010000004889ca48c7c1feffffffff57"
    "104881c4d8040000c3"
)


def test_getpc_mov_from_stack_and_no_pop_esp():
    assert "getpc_call_pop" in analyse(GETPC_MOVESP_X86)["tags"]
    # call $+5; pop esp is never a real GetPC
    assert "getpc_call_pop" not in analyse(bytes.fromhex("e8000000005c90c3") + _rand(32, 51))["tags"]


def test_software_crc32_name_hash():
    r = analyse(CRC32_SOFT_X86)
    assert r["verdict"] == "shellcode"
    loop = next(i for i in r["indicators"] if i["name"] == "api_hash_loop")
    assert loop["confidence"] == "high"  # next to a PEB walk


def test_hwbp_context_and_veh():
    r = analyse(HWBP_VEH_X64)
    assert r["verdict"] == "shellcode" and "hwbp_context" in r["tags"]
    assert r["capabilities"]["veh_hwbp"] == ["AddVectoredExceptionHandler"]


def test_implausible_syscall_number_is_not_a_stub():
    stub = bytes.fromhex("4989cab8414141410f05c3") * 3  # mov r10, rcx; mov eax, 0x41414141; syscall; ret
    assert "direct_syscall" not in analyse(stub, arch="x64")["tags"]


def test_x64_pic_uses_external_rip_references():
    # compiled-style x64: calls through an import table outside the blob
    compiled = bytes.fromhex(
        "4883ec28488b0d f1ff0f00 ff15 f3ff0f00 488d15 e4ff0f00 4889c1 ff15 e3ff0f00 4883c428c3".replace(" ", "")
    )
    r = analyse(compiled * 4, arch="x64")
    assert r["pic"] == "no" and r["structure"]["external_rip_refs"] >= 2
    assert analyse(MSF_STYLE_X64)["pic"] == "yes"


def test_clr_strings_give_dotnet_hosting():
    blob = MSF_STYLE_X64 + b"\x00clr.dll\x00" + "v4.0.30319".encode("utf-16le") + b"\x00\x00"
    assert "dotnet_hosting" in analyse(blob)["capabilities"]


def test_runtime_imports_do_not_make_capabilities():
    # RtlCaptureContext / CreateThread are imported by ordinary programs
    blob = MSF_STYLE_X64 + b"\x00RtlCaptureContext\x00CreateThread\x00"
    caps = analyse(blob).get("capabilities", {})
    assert "sleep_obfuscation" not in caps and "callback_execution" not in caps


# --------------------------------------------------------------------------- register-tracked PEB walks
# push 0x60; pop rcx; mov rax, gs:[rcx] -> Ldr -> InInitializationOrder list, ror13 over BaseDllName
PEB_PUSHPOP_ININIT_X64 = bytes.fromhex(
    "6a605965488b01488b4018488b5830488b73400fb74b384531c931c0ac41c1c90d4101c1e2f44181f95bbc4a6a7405488b1bebdb488b4310c3"
)
# PEB spilled to a stack slot and reloaded into another register
PEB_SPILL_X64 = bytes.fromhex(
    "6548a16000000000000000488944241031c0488b542410488b5218488b5a20488b73500fb74b484531c931c0ac41c1c90d4101c1e2f44181"
    "f95bbc4a6a7405488b1bebdb488b4320c3"
)
# tiny helper returns the PEB; the walk continues at the call site
PEB_HELPER_X64 = bytes.fromhex(
    "eb0c6548a16000000000000000c3e8efffffff488b4018488b5820488b73500fb74b484531c931c0ac41c1c90d4101c1e2f44181f95bbc4a"
    "6a7405488b1bebdb488b4320c3"
)
# TEB read, then Ldr-like offsets on unrelated registers: not a walk
TEB_UNRELATED_X64 = bytes.fromhex(
    "41564883ec206548a130000000000000004531db4c89ce488b4e18488b51204c8b42504c8980781400004883c420415ec3"
)
# fixed-position walk (EXE -> ntdll -> kernel32), DllBase, export directory
PEB_FIXED_X86 = bytes.fromhex("535664a1300000008b400c8b700c8b068b008b58188b433c8b44037801d88b48188b50205e5bc3")


@pytest.mark.parametrize(
    "data, arch, lst",
    [
        (PEB_PUSHPOP_ININIT_X64, "x64", "InInitOrder"),
        (PEB_SPILL_X64, "x64", "InMemoryOrder"),
        (PEB_HELPER_X64, "x64", "InMemoryOrder"),
        (MSF_STYLE_X86, "x86", "InMemoryOrder"),
        (MSF_STYLE_X64, "x64", "InMemoryOrder"),
        (PEB_FIXED_X86, "x86", "InLoadOrder"),
    ],
)
def test_peb_walk_follows_registers(data, arch, lst):
    r = analyse(data, arch=arch)
    assert "peb_walk" in r["tags"] and "peb_access" not in r["tags"], r["tags"]
    walk = next(i for i in r["indicators"] if i["name"] == "peb_walk")
    assert walk["confidence"] == "high" and walk["detail"].startswith(f"{lst} walk")
    ev = next(e for e in r["evidence"] if e["indicator"] == "peb_walk")
    notes = [line[3] for line in ev["context"] if line[2]]
    assert "PEB->Ldr" in notes and any(n.startswith("Ldr.") for n in notes), notes
    # every stage is highlighted in one block, not the segment read twice
    assert len([line for line in ev["context"] if line[2]]) >= 4


def test_peb_walk_stage_details():
    detail = next(i["detail"] for i in analyse(PEB_PUSHPOP_ININIT_X64, arch="x64")["indicators"] if i["name"] == "peb_walk")
    assert "BaseDllName.Buffer" in detail and "Flink to next module" in detail and "ror 0xd" in detail
    detail = next(i["detail"] for i in analyse(PEB_FIXED_X86, arch="x86")["indicators"] if i["name"] == "peb_walk")
    assert "DllBase" in detail and "export walk" in detail


def test_teb_read_with_unrelated_offsets_is_not_a_walk():
    r = analyse(TEB_UNRELATED_X64 * 3, arch="x64")
    assert "peb_walk" not in r["tags"] and "teb_access" in r["tags"]


# --------------------------------------------------------------------------- decoders: candidate / linked / verified
# call $+5; pop esi; add esi, N; mov edi, esi; mov ecx, 0x1000; lodsb; xor al, 0x37; stosb; dec ecx; jnz; ret
DEC_LTS_PE_X86 = bytes.fromhex("e8000000005e83c61389f7b900100000ac3437aa4975f9c3")
# compiled shape: pointer is an argument, not the blob
UNLINKED_XOR_X64 = bytes.fromhex("534889cb31c08034035a48ffc04839d072f44889d85bc3")
# -O0: loop counter kept in a stack slot (add dword ptr [rbp - 8], 1), movsx loads
O0_COUNTER_X64 = bytes.fromhex("554889e54883ec20c745f8000000008b45f84863c80fbe140f0155fc8345f801837df8407ce98b45fcc9c3")


def _pe_file(size=0x1000):
    """Complete x64 DLL file: headers 0x400 + three 0x400 raw sections."""
    pe = bytearray(_fake_pe(x64=True, dll=True, size=size))
    pe[0x86:0x88] = (3).to_bytes(2, "little")
    table = 0x98 + 0xF0
    for k in range(3):
        struct_off = table + 0x28 * k
        pe[struct_off : struct_off + 8] = f".s{k}".encode().ljust(8, b"\0")
        pe[struct_off + 0x10 : struct_off + 0x14] = (0x400).to_bytes(4, "little")  # SizeOfRawData
        pe[struct_off + 0x14 : struct_off + 0x18] = (0x400 * (k + 1)).to_bytes(4, "little")  # PointerToRawData
    pe[0x400:] = _rand(size - 0x400, 9)
    return bytes(pe)


def test_decoder_hiding_pe_is_verified_with_exact_size():
    payload = _pe_file()
    r = analyse(DEC_LTS_PE_X86 + bytes(b ^ 0x37 for b in payload), arch="x86")
    assert r["verdict"] == "shellcode" and {"decoder_stub", "decoded_payload"} <= set(r["tags"])
    region = r["regions"][0]
    assert region["start"] == hex(len(DEC_LTS_PE_X86)) and region["size"] == 0x1000 and region["status"] == "verified"
    assert region["result_type"] == "pe" and "x64 DLL, 0x1000 bytes" in region["result"]
    ev = next(e for e in r["evidence"] if e["indicator"] == "decoder_stub")
    assert any(line[3] == "GetPC" for line in ev["context"]) and any(line[3] == "decode" for line in ev["context"])


def test_jmp_call_pop_decoder_decodes_to_code():
    payload = MSF_STYLE_X86.ljust(0x200, b"\x90")
    r = analyse(JMP_CALL_POP_STUB_X86 + bytes(b ^ 0x5A for b in payload), arch="x86")
    region = r["regions"][0]
    assert (region["start"], region["size"], region["result_type"]) == ("0x16", 0x200, "code")
    assert "peb_walk" in region["result"]  # indicators of the decoded code, one level deep


def test_rolling_key_decoder_is_linked_not_verified():
    r = analyse(FNSTENV_STUB_X86 + _rand(0x200, 1), arch="x86")
    assert "decoder_stub" in r["tags"] and "decoded_payload" not in r["tags"]
    region = r["regions"][0]
    # fnstenv pointer = fldz at 0; [ebx + 0x18], 0x80 dwords
    assert (region["start"], region["size"], region["status"]) == ("0x18", 0x200, "linked")


def test_unlinked_and_compiled_loops_are_not_scored():
    r = analyse(UNLINKED_XOR_X64 * 4, arch="x64")
    assert "decoder_stub" not in r["tags"] and r["verdict"] not in ("shellcode", "likely")
    loop = next(i for i in r["indicators"] if i["name"] == "decoder_loop")
    assert loop["scored"] is False and r["score"] == 0
    r = analyse(O0_COUNTER_X64 * 3, arch="x64")
    assert not {"decoder_loop", "decoder_stub"} & set(r["tags"])


def test_call_over_length_prefixed_data_is_not_donut():
    # E8 <len> <blob starting with len> 59 ... without Donut's loader stub: structure only, no attribution
    instance = (0x2000).to_bytes(4, "little") + _rand(0x2000 - 4, 5)
    loader = bytes.fromhex("5956574889ce4883ec2865488b042560000000488b4018488b7820488b47204883c4285f5ec3")
    r = analyse(b"\xe8" + (0x2000).to_bytes(4, "little") + instance + loader, arch="x64")
    assert "getpc_call_over_data" in r["tags"] and "framework_layout" not in r["tags"]
    assert not r.get("frameworks")


# --------------------------------------------------------------------------- false-positive guards
FNV_ALONE_X86 = bytes.fromhex("5589e5568b4d088b550cb8c59d1c810fb63131f069c093010001414a75f15e5dc3")
GS_FUNC_X64 = bytes.fromhex(
    "534883ec40488b05001000004831e048894424384889cbb910000000ff1500200000488b4c24384831e1ff15002100004883c4405bc3"
)
JIT_LIKE_X64 = bytes.fromhex(
    "554889e54883ec2048b900003412f87f0000ba0000000048b8000000aaf87f0000ffd048b900013412f87f0000ba0100000048b8400000aa"
    "f87f0000ffd048b900023412f87f0000ba0200000048b8800000aaf87f0000ffd048b900033412f87f0000ba0300000048b8c00000aaf87f"
    "0000ffd048b900043412f87f0000ba0400000048b8000100aaf87f0000ffd048b900053412f87f0000ba0500000048b8400100aaf87f0000"
    "ffd048b900063412f87f0000ba0600000048b8800100aaf87f0000ffd048b900073412f87f0000ba0700000048b8c00100aaf87f0000ffd0"
    "48b900083412f87f0000ba0800000048b8000200aaf87f0000ffd048b900093412f87f0000ba0900000048b8400200aaf87f0000ffd048b9"
    "000a3412f87f0000ba0a00000048b8800200aaf87f0000ffd048b9000b3412f87f0000ba0b00000048b8c00200aaf87f0000ffd04883c420"
    "5dc3"
)


def test_generic_hash_loop_needs_a_resolver():
    # MSVC x86 std::hash is FNV-1a: alone it is low, next to a PEB walk / export parse it is high
    r = analyse(FNV_ALONE_X86 * 4, arch="x86")
    assert next(i for i in r["indicators"] if i["name"] == "api_hash_loop")["confidence"] == "low"
    assert r["verdict"] not in ("shellcode", "likely")
    r = analyse(USER_SAMPLE_X64)  # export parse + djb2
    assert next(i for i in r["indicators"] if i["name"] == "api_hash_loop")["confidence"] == "high"


def test_tiny_island_does_not_confirm_a_large_blob():
    blob = _rand(0x8000, 3) + DIRECT_SYSCALL_X64[16:] + _rand(0x8000, 4)
    assert analyse(blob, arch="x64")["verdict"] != "shellcode"
    assert analyse(DIRECT_SYSCALL_X64, arch="x64")["verdict"] == "shellcode"


def test_jit_code_is_not_shellcode():
    r = analyse(JIT_LIKE_X64 + JIT_LIKE_X64, arch="x64")
    assert "jit_code" in r["tags"] and r["verdict"] == "code"
    assert "injected_call_stub" not in r["tags"]


def test_compiled_runtime_stops_weak_traits_adding_up():
    # /GS cookie functions plus a medium trait (cpuid hypervisor check) stay 'code'
    r = analyse(GS_FUNC_X64 * 3 + ANTI_ANALYSIS_X86[:0], arch="x64")
    assert "compiled_runtime" in r["tags"] and r["verdict"] == "code"


def test_mapped_image_with_wiped_headers():
    names = b"".join(len(n).to_bytes(2, "little") + n + b"\0" + (b"\0" if len(n) % 2 == 0 else b"") for n in (
        b"GetProcAddress", b"LoadLibraryW", b"VirtualProtect", b"CreateFileW", b"ReadFile", b"CloseHandle",
        b"GetLastError", b"HeapAlloc", b"HeapFree", b"Sleep",
    ))  # fmt: skip
    r = analyse(GS_FUNC_X64 * 8 + b"\0" * 64 + names, arch="x64")
    assert r["verdict"] == "image" and "mapped_image" in r["tags"]


def test_ntdll_copy_is_an_image_not_syscall_shellcode():
    stubs = b"".join(
        bytes.fromhex("4c8bd1b8") + ssn.to_bytes(4, "little") + bytes.fromhex("f604250803fe7f0175030f05c3cd2ec30f1f840000000000")
        for ssn in range(0x40, 0x80)
    )
    r = analyse(stubs, arch="x64")
    assert r["verdict"] == "image" and "ntdll_copy" in r["tags"]
    assert not {"direct_syscall", "syscall_insn", "int2e_syscall", "kuser_shared_data"} & set(r["tags"])


# --------------------------------------------------------------------------- new indicators
INJECT_X64 = bytes.fromhex("4883ec2848b90001b4a3d201000048b830124d2cfb7f0000ffd031c948b840884e2cfb7f0000ffd04883c428c3")
INJECT_ONE_X86 = bytes.fromhex("680001d200b8c0b2a176ffd0c20400")
APLIB_X86 = bytes.fromhex("608b7424248b7c2428fcb28031dba4b30200d275058a164610d273f22b7c2428897c241c61c3")


def test_injected_call_stubs():
    r = analyse(INJECT_X64, arch="x64")
    assert r["verdict"] == "shellcode" and "injected_call_stub" in r["tags"]
    r = analyse(INJECT_ONE_X86, arch="x86")
    assert r["verdict"] == "likely" and "injected_call_stub" in r["tags"]


def test_aplib_depacker():
    r = analyse(APLIB_X86, arch="x86")
    assert "aplib_depacker" in r["tags"] and r["verdict"] == "likely"


def test_new_api_hashes_and_capabilities():
    from lib.cuckoo.common.integrations.shellcode_check import KNOWN_API_HASHES, _capabilities, _h_ror13

    assert _h_ror13(b"RtlDecompressBuffer") in KNOWN_API_HASHES
    caps = _capabilities({"TpAllocWork", "TpPostWork", "RtlDecompressBuffer", "RtlCreateTimer", "NtContinue"})
    assert {"threadpool_execution", "decompression", "sleep_obfuscation"} <= set(caps)
    assert "threadpool_execution" not in _capabilities({"TpPostWork"})


def test_block_context_renders():
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates"}])
        django.setup()
    from django.template import Context, Engine

    payload = _pe_file()
    file = {"sha256": "x", "static_shellcode_check": analyse(DEC_LTS_PE_X86 + bytes(b ^ 0x37 for b in payload), arch="x86")}
    html = (
        Engine(dirs=["web/templates"], builtins=["django.template.defaultfilters"])
        .get_template("analysis/generic/_shellcode_check.html")
        .render(Context({"file": file}))
    )
    assert "Protected / decoded regions" in html and "verified" in html and "; GetPC" in html


def test_extracted_payloads_render_and_indicator_details_do_not():
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates"}])
        django.setup()
    from django.template import Context, Engine

    check = analyse(PEB_FIXED_X86, arch="x86")
    assert any(i["detail"] for i in check["indicators"])
    check["extracted"] = [{"sha256": "ab" * 32, "size": 4096, "cape_type": "Donut Shellcode Payload", "framework": "Donut",
                           "offset": "0x128d", "description": "Donut module: x64 EXE"}]  # fmt: skip
    html = (
        Engine(dirs=["web/templates"], builtins=["django.template.defaultfilters"])
        .get_template("analysis/generic/_shellcode_check.html")
        .render(Context({"file": {"sha256": "x", "static_shellcode_check": check}, "id": 7}))
    )
    assert "Extracted payloads" in html and "Donut Shellcode Payload" in html and "ab" * 32 in html
    # no raw download link: the payload is downloaded from its own card (zipped, password 'infected')
    assert "<a " not in html[html.index("Extracted payloads") : html.index("ab" * 32) + 64]
    assert "text-info small font-monospace" not in html


# AMSI / ETW / WLDP patching (PEB walk + target name on the stack + patch), assembled with keystone
ETW_48_33 = bytes.fromhex("4883ec286548a16000000000000000488b4018488b7020488b36488b5e2048b94574774576656e7448894c2430b957726974894c243866c744243c6500c7004833c0c3c3")  # fmt: skip
AMSI_SPLIT = bytes.fromhex("4883ec286548a16000000000000000488b4018488b7020488b36488b5e2048b9616d73692e646c6c48894c243048b9416d73695363616e48894c2440b942756666894c2448c700b857000766c7400480c3c3")  # fmt: skip
ETW_X86_RET14 = bytes.fromhex("64a1300000008b400c8b70146a6568577269746876656e74684574774589e3c707c2140000c3")
AMSI_X86_RET18 = bytes.fromhex("64a1300000008b400c8b701468657200006842756666685363616e68416d736989e3c707b8570007c7470480c21800c3")  # fmt: skip
WLDP_PATCH = bytes.fromhex("4883ec286548a16000000000000000488b4018488b7020488b36488b5e2048b9576c64705175657248894c243048b97944796e616d696348894c2438c7442440436f6465c70031c0c300c3")  # fmt: skip
AMSI_CONTEXT = bytes.fromhex("4883ec286548a16000000000000000488b4018488b7020488b36488b5e208138414d53497506c70000000000c3")
AMSI_ARRAY = bytes.fromhex("4883ec286548a16000000000000000488b4018488b7020488b36488b5e2048b9616d73692e646c6c48894c243048b9416d73695363616e48894c2440b942756666894c2448488d350b0000004889c7b906000000f3a4c3b857000780c3")  # fmt: skip


@pytest.mark.parametrize(
    "data, patch",
    [
        (ETW_48_33, "xor rax,rax; ret"),  # the 48 33 c0 encoding
        (AMSI_SPLIT, "E_INVALIDARG (first part)"),  # b8 57 00 07 | 80 c3 written as dword + word
        (ETW_X86_RET14, "ret 0x14"),  # x86 EtwEventWrite cleans up its stdcall arguments
        (AMSI_X86_RET18, "E_INVALIDARG (first part)"),
        (WLDP_PATCH, "xor eax,eax; ret"),
    ],
)
def test_amsi_etw_wldp_patches(data, patch):
    r = analyse(data)
    assert r["verdict"] == "shellcode" and "amsi_etw_patch" in r["tags"]
    assert any(e["indicator"] == "ret_patch_write" and e["insn"].endswith(patch) for e in r["evidence"])


def test_amsi_patch_array_copied_over_the_target():
    r = analyse(AMSI_ARRAY)
    assert "amsi_etw_patch" in r["tags"] and "ret_patch_write" not in r["tags"]
    assert any("patch bytes b8 57 00 07 80 c3" in e["insn"] for e in r["evidence"] if e["indicator"] == "amsi_etw_patch")


def test_amsi_context_corruption():
    assert "amsi_context_patch" in analyse(AMSI_CONTEXT)["tags"]
    # the signature compare alone (amsi.dll itself validates its context this way) is not a patch
    assert "amsi_context_patch" not in analyse(AMSI_CONTEXT.replace(bytes.fromhex("c700"), bytes.fromhex("8b00")))["tags"]


def test_stack_string_staged_through_a_32bit_register():
    # 'EtwEvent' (movabs) + 'Writ' (mov ecx, imm32; mov [rsp+x], ecx) + 'e' (word store)
    assert "EtwEventWrite" in analyse(ETW_48_33)["stack_strings"]


# header wiping: SizeOfHeaders read after e_lfanew, then a zero fill of that length
WIPE_REP_STOS_X64 = bytes.fromhex("4883ec286548a16000000000000000488b4018488b7020488b36488b5e204889df4863433c8b4c035431c0f3aac3")
WIPE_MEMSET_X64 = bytes.fromhex("4883ec286548a16000000000000000488b4018488b7020488b36488b5e204863433c448b44035431d24889d9ff5610c3")
WIPE_MEMSET_X86 = bytes.fromhex("64a1300000008b400c8b70148b5e108b433c8b4c0354516a0053ff5620c3")
# kernel token stealing (KPCR current thread, process list walked for PID 4, token copied)
TOKEN_STEAL_X64 = bytes.fromhex("4831c065488b8088010000488b80b80000004889c1ba04000000488b8048040000482d480400004839904004000075ea488b90b8040000488991b80400004831c0c3")  # fmt: skip
TOKEN_STEAL_X86 = bytes.fromhex("6031c0648b80240100008b405089c18b80b80000002db800000083b8b40000000475ec8b90f80000008991f800000061c3")  # fmt: skip


@pytest.mark.parametrize("data", [WIPE_REP_STOS_X64, WIPE_MEMSET_X64, WIPE_MEMSET_X86])
def test_pe_header_wipe(data):
    r = analyse(data)
    assert "pe_header_wipe" in r["tags"]
    (ev,) = [e for e in r["evidence"] if e["indicator"] == "pe_header_wipe"]
    assert [row[3] for row in ev["context"] if row[2]] == ["e_lfanew", "SizeOfHeaders", "zero fill"]


def test_size_of_headers_read_without_a_zero_fill_is_not_a_wipe():
    # same reads, but the size goes to a copy (rep movsb) rather than a zero fill
    assert (
        "pe_header_wipe"
        not in analyse(WIPE_REP_STOS_X64.replace(bytes.fromhex("31c0f3aa"), bytes.fromhex("90" * 2 + "f3a4")))["tags"]
    )


def test_mapped_x64_image_without_headers_or_import_names_is_an_image():
    # a mapped x64 image: page-aligned .pdata whose unwind RVAs point at UNWIND_INFO v1
    rng = random.Random(9)
    img = bytearray(_rand(0x6000, 21))
    img[:0x1000] = bytes(0x1000)
    funcs, at = [], 0x1000
    for _ in range(64):
        size = rng.randrange(0x20, 0x80)
        funcs.append((at, at + size))
        at += size + rng.randrange(0, 0x10)
    for k, (b, e) in enumerate(funcs):
        unwind = 0x4000 + 8 * k
        img[unwind] = 0x01  # UNWIND_INFO version 1
        img[0x5000 + 12 * k : 0x5000 + 12 * k + 12] = struct.pack("<3I", b, e, unwind)
    r = analyse(bytes(img))
    assert r["verdict"] == "image" and "mapped_image" in r["tags"]
    assert any(".pdata" in e["insn"] for e in r["evidence"] if e["indicator"] == "mapped_image")
    img[0x4000 : 0x4000 + 8 * 64] = bytes(8 * 64)  # unwind info gone: not an exception table
    assert "mapped_image" not in analyse(bytes(img))["tags"]


@pytest.mark.parametrize("data", [TOKEN_STEAL_X64, TOKEN_STEAL_X86])
def test_kernel_token_stealing(data):
    r = analyse(data)
    assert r["verdict"] == "shellcode" and "kernel_token_steal" in r["tags"]


def test_kpcr_read_without_the_process_walk_is_not_token_stealing():
    assert "kernel_token_steal" not in analyse(TOKEN_STEAL_X64[:21] + b"\xc3")["tags"]


def test_xor_mul_zeroing_idiom_is_supporting_weight_only():
    r = analyse(bytes.fromhex("31c9f7e1") + _rand(0x40, 5), arch="x86")
    assert "zero_three_regs" in r["tags"] and r["verdict"] != "shellcode"


def test_donut_reports_its_bypass_and_header_settings():
    d = _framework(analyse(_fixture("donut_x64_enc")), "Donut")["details"]
    assert d["amsi_wldp_etw_bypass"] == "yes (continue if it fails)" and d["pe_headers"] == "overwritten after loading"


# wininet HTTP(S) stagers in Metasploit's reverse_http(s) shape (keystone, from its asm templates):
# classic block_api hashes, and current Metasploit's IV-seeded hashes (IV held in the stub)
STAGER_X86_CLASSIC = bytes.fromhex("fce8070000006089e531c061c35d686e6574006877696e6954684c772607ffd531db5353535353e83d0000004d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e333600683a5679a7ffd553536a03535368901f0000e8280000002f4b7a337861623900506857899fc6ffd589c653680002608453535357535668eb552e3bffd596c35fe8dbffffff31302e392e382e3700")  # fmt: skip
STAGER_X86_IV_HTTPS = bytes.fromhex("fce80c0000006089e531c0bfd3001f5e61c35d686e6574006877696e6954683a063c51ffd531db5353535353e83d0000004d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e33360068ac644174ffd553536a03535368bb010000e82f0000002f6142335f6b782d3951324c6d507a005068aadf1615ffd589c653680032e084535353575356683eaca589ffd596c35fe8dbffffff757064617465732e6578616d706c652e636f6d00")  # fmt: skip
STAGER_X64_IV_HTTPS = bytes.fromhex("fc4883e4f0e80b000000415141b94d3c2b1a4159c35d4831db49be77696e696e65740041564889e141baf723422fffd55353e83d0000004d6f7a696c6c612f352e30202857696e646f7773204e542031302e303b2057696e36343b2078363429204170706c655765624b69742f3533372e33360059535a4d31c04d31c9535341ba6d00f937ffd5e80e0000003139322e3136382e35362e3230005a4889c149c7c0fb2000004d31c953536a035341bae14e9e96ffd5e80a0000002f7a5138772d317254004889c1535a41584d31c95348b80032e0840000000050535341ba761b2d0bffd5c3")  # fmt: skip
STAGER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@pytest.mark.parametrize(
    "data, url, iv",
    [
        (STAGER_X86_CLASSIC, "http://10.9.8.7:8080/Kz3xab9", None),
        (STAGER_X86_IV_HTTPS, "https://updates.example.com:443/aB3_kx-9Q2LmPz", "0x5e1f00d3"),
        (STAGER_X64_IV_HTTPS, "https://192.168.56.20:8443/zQ8w-1rT", "0x1a2b3c4d"),
    ],
)
def test_http_stager_configuration_is_reconstructed(data, url, iv):
    from lib.cuckoo.common.integrations.shellcode_check import find_http_stager

    cfg = find_http_stager(data)
    assert cfg["url"] == url and cfg["user_agent"] == STAGER_UA and cfg.get("block_api_iv") == iv


def test_http_stager_url_becomes_an_ioc():
    r = analyse(STAGER_X86_CLASSIC)
    assert r["verdict"] == "shellcode" and "http_stager_config" in r["tags"]
    assert r["iocs"]["urls"] == ["http://10.9.8.7:8080/Kz3xab9"] and r["iocs"]["user_agents"] == [STAGER_UA]


def test_stager_strings_without_the_connect_call_are_not_a_config():
    from lib.cuckoo.common.integrations.shellcode_check import find_http_stager

    assert find_http_stager(STAGER_X86_CLASSIC.replace(bytes.fromhex("6857899fc6"), bytes.fromhex("6811111111"))) is None


# --------------------------------------------------------------------------- known generators (real output)
FIXTURES = os.path.join(os.path.dirname(__file__), "data", "malware", "shellcodes")


def _fixture(name):
    path = os.path.join(FIXTURES, name + ".b64")
    if not os.path.exists(path):
        pytest.skip(f"Required data file is not present: {path}")
    with open(path) as f:
        return zlib.decompress(base64.b64decode("".join(f.read().split())))


def _framework(r, name):
    return next(f for f in r["frameworks"] if f["name"] == name)


def test_donut_encrypted_instance_is_decrypted_statically():
    r = analyse(_fixture("donut_x64_enc"))
    fw = _framework(r, "Donut")
    assert fw["confidence"] == "identified" and fw["arch"] == "x64" and r["verdict"] == "shellcode"
    assert any("ole32;oleaut32;wininet;mscoree;shell32" in e for e in fw["evidence"])
    assert fw["details"]["payload"] == "x64 EXE" and fw["details"]["payload_size"] == 0x1000
    instance, payload = r["regions"][0], r["regions"][1]
    assert (instance["start"], instance["status"], instance["framework"]) == ("0x5", "structural", "Donut")
    assert (payload["start"], payload["size"], payload["status"]) == (hex(5 + 0xD60 + 0x528), 0x1000, "verified")
    assert "framework_layout" in r["tags"]


def test_donut_plain_and_compressed():
    fw = _framework(analyse(_fixture("donut_x86_plain")), "Donut")
    assert fw["details"]["instance"] == "not encrypted" and fw["details"]["payload"] == "x86 EXE"
    r = analyse(_fixture("donut_x84_aplib"))
    fw = _framework(r, "Donut")
    assert fw["arch"] == "x86+x64" and fw["details"]["compression"].startswith("aPLib (")
    assert fw["details"]["payload_size"] == 0x1000


def test_donut_http_staging_url_is_an_ioc():
    r = analyse(_fixture("donut_http"))
    fw = _framework(r, "Donut")
    assert fw["details"]["instance_type"] == "HTTP" and fw["details"]["staging_url"].startswith("http://10.0.0.5/files/")
    assert fw["label"] == "Donut: staged (HTTP)"
    assert fw["details"]["staging_url"] in r["iocs"]["urls"]


def test_donut_layout_without_known_plaintext_is_not_decoded():
    data = bytearray(_fixture("donut_x64_enc"))
    data[5 + 0x240 : 5 + 0x260] = bytes(0x20)  # break the known plaintext (another Donut version)
    fw = _framework(analyse(bytes(data)), "Donut")
    assert "payload" not in fw["details"] and len(fw["evidence"]) == 2


def test_donut_loader_past_the_scan_window_is_analysed():
    # the instance pushes the loader past the head window: the call target is followed anyway
    r = analyse(_fixture("donut_x64_enc") + bytes.fromhex("4883ec2865488b042560000000488b4018488b7820488b47204883c428c3"),
                max_scan=0x800)  # fmt: skip
    assert r["deep_windows"] and r["deep_windows"][0]["start"] == hex(5 + 0x27C0)


@pytest.mark.parametrize("name, arch", [("srdi_x64", "x64"), ("srdi_x86", "x86")])
def test_srdi_bootstrap_and_dll(name, arch):
    r = analyse(_fixture(name))
    fw = _framework(r, "sRDI")
    assert fw["confidence"] == "identified" and fw["arch"] == arch and r["verdict"] == "shellcode"
    assert fw["details"]["payload"] == f"{arch} DLL" and fw["details"]["payload_size"] == 0x1000
    assert fw["details"]["export_hash"] == "0x30627745" and fw["details"]["user_data"] == "run=1"
    assert fw["details"]["flags"] == "clear header, obfuscate imports"
    region = next(g for g in r["regions"] if g.get("framework") == "sRDI")
    assert region["status"] == "structural" and region["size"] == 0x1000


def test_srdi_template_needs_a_dll_at_the_computed_offset():
    data = bytearray(_fixture("srdi_x64"))
    dll = 5 + int.from_bytes(data[0x2F:0x33], "little")  # add rcx, <dllOffset>
    data[dll : dll + 2] = b"\0\0"
    assert "sRDI" not in [f["name"] for f in analyse(bytes(data)).get("frameworks", [])]


def test_pe2shc_redirection_stub():
    # per pe2shc main.cpp redir_code64: MZER; call $+5; pop rcx; sub rcx, 9; mov rax, rcx; add rax, <raw>; call rax; ret
    pe = bytearray(_pe_file())
    stub = len(pe)
    redir = b"MZER" + bytes.fromhex("e800000000594883e909488bc14805") + stub.to_bytes(4, "little") + b"\xff\xd0\xc3"
    pe[0 : len(redir)] = redir
    r = analyse(bytes(pe) + MSF_STYLE_X64)
    fw = _framework(r, "pe2shc")
    assert fw["confidence"] == "identified" and fw["details"]["payload"] == "x64 DLL" and fw["details"]["payload_size"] == stub
    assert r["verdict"] == "shellcode"


def test_metasploit_block_api_is_an_indicator_not_a_framework():
    r = analyse(MSF_STYLE_X86)
    assert not r.get("frameworks")
    ind = next(i for i in r["indicators"] if i["name"] == "block_api_prologue")
    assert ind["confidence"] == "high" and "not an attribution" in ind["description"]


# Real Metasploit x86/shikata_ga_nai output (Metasploit's generator code on rapid7/rex-encoder's
# Rex::Poly) encoding REVERSE_TCP_X86: one iteration, and three iterations
SGN_1 = bytes.fromhex(
    "be9927262edbc0d97424f45f29c9b13783c70431770f037796c5d3d240801c2b90f395cea121c19b93f581ce1f7dc7fa94f3c00d1db93623"
    "9e0ff7ef5c118bedb0f1b23dc5f0f32025a0ac2f9755d8722b570ef9132f2b3ee785326f57917d97dcfd5da6311ea1e13ed551f0962799c2"
    "d6e4a4eadbf5e1cd0380192ebe93d94c6411fcf7ef8124093c57ae058913e8090cf7823685f644bfdddc409b867dd0416981022dd62748a6"
    "dbe54e37737d3c05dcd5aa2595f32d498c7ddd252f7e1e12477f1f9a9717361afce7b7cf52b817a01268d810fa62d74f1a8d3df8b2b2163f"
    "275b6540b6c7e0a6d2e7a4714a91ec0aeb5e3b31"
)
SGN_3 = bytes.fromhex(
    "dbdfd97424f4babd169f235e33c9b14431561a83c604035616e248aef27f196ed5698405c29d69cdc3efab923bf3e2d3cd0f2e8e985b4092"
    "4f87365f52783d287b8e020ee3ce86ec7b7d88d9590d4a83f7ac5c0cdb006e1ee3d9917aff71f125b2b1e483742c03901f64b3f5efe1cf63"
    "e9cff3ec1a989752294a4e157ed334848a43957e48ce433cf716001f7678ca91c262377f00d9f2ff6d03286e9947a8396cd4aa1d6f2386de"
    "b968ad588f76995dce4779a4b6be91e21dae2ee01ff153d25d5311e239ef1dcb8ab618ea14b88a061a4aee08ad265fe62c0478c2fb580af1"
    "8b68a3db57b45a31875298f7eb133ac4172187f9a5edc1402a6f92fe95303fb6c764b62960e907a242ad32c829818fc409de0e4f778ae293"
    "6cfeb83704bc3c6b8b9ac2792de55f3cd918"
)


@pytest.mark.parametrize("data, layers", [(SGN_1, 1), (SGN_3, 3)])
def test_shikata_ga_nai_is_decoded_and_proven(data, layers):
    # an encoder, not a framework: an indicator, with the payload it wraps decoded
    r = analyse(data)
    assert not r.get("frameworks") and r["verdict"] == "shellcode" and "shikata_ga_nai" in r["tags"]
    enc = r["encoder"]
    assert enc["name"] == ("x86/shikata_ga_nai" if layers == 1 else f"x86/shikata_ga_nai x{layers}")
    assert enc["layers"] == layers and enc["payload_size"] == len(REVERSE_TCP_X86)
    assert enc["payload"] == "x86 code" and "peb_walk" in enc["payload_indicators"]
    (region,) = [g for g in r["regions"] if g["source"].startswith("x86/shikata_ga_nai")]
    assert region["status"] == "verified" and region["framework"] is None
    assert "Metasploit" in INDICATORS["shikata_ga_nai"][1]


def _msf_vectors(allow_missing=False):
    import json

    path = os.path.join(FIXTURES, "msf_encoders.b64")
    if allow_missing and not os.path.exists(path):
        return {}
    return json.loads(_fixture("msf_encoders"))


_MSF_VECTOR_NAMES = sorted(_msf_vectors(allow_missing=True)) or [
    pytest.param("missing", marks=pytest.mark.skip(reason="Required data file is not present: msf_encoders.b64"))
]


@pytest.mark.parametrize("name", _MSF_VECTOR_NAMES)
def test_msfvenom_encoders_are_identified_and_decoded(name):
    v = {k: bytes.fromhex(x) for k, x in _msf_vectors()[name].items()}
    r = analyse(v["blob"], extract_payloads=True)
    (p,) = r.pop("_payloads")
    assert r["verdict"] == "shellcode" and "msf_encoder" in r["tags"] and not r.get("frameworks")
    assert p["data"] == v["payload"] and p["framework"] is None
    if name.startswith("chain"):
        assert r["encoder"]["name"] == "x86/fnstenv_mov -> x86/call4_dword_xor" and r["encoder"]["layers"] == 2
    else:
        assert r["encoder"]["name"] == name.split(" ")[0]


def test_encoder_stub_with_an_unparsed_counter_is_not_decoded():
    v = {k: bytes.fromhex(x) for k, x in _msf_vectors()["x86/fnstenv_mov push"].items()}
    blob = b"\x90\x90\x90" + v["blob"][3:]  # counter load replaced: no exact length, no claim
    r = analyse(blob)
    assert "msf_encoder" not in r["tags"] and not r.get("encoder")


def test_unicode_encoder_is_identified_without_decoding():
    from lib.cuckoo.common.integrations.shellcode_check import _MSF_UNICODE

    core = _MSF_UNICODE[0][0]
    for blob in (b"VVYA" + core + b"PPYAKLZH" * 20, b"".join(bytes([c, 0]) for c in b"VVYA" + core) + b"P\x00" * 64):
        r = analyse(blob, extract_payloads=True)
        assert r["encoder"]["name"] == "x86/unicode_mixed" and r["_payloads"] == []


def test_call4_getpc_is_recognised():
    # call $+4 lands on its own last byte (ff), which starts 'inc eax'; then pop esi
    stub = bytes.fromhex("e8ffffffffc05e") + bytes.fromhex("8b0683c604") * 4 + b"\xc3"
    assert "getpc_call4" in analyse(stub + _rand(0x40, 3), arch="x86")["tags"]


def test_shikata_style_stub_that_does_not_rebuild_its_loop_is_not_identified():
    data = bytearray(SGN_1)
    data[1:5] = bytes(4)  # wrong key: the decoded tail no longer forms the loop
    r = analyse(bytes(data))
    assert not r.get("encoder") and "shikata_ga_nai" not in r["tags"] and "fpu_getpc_decoder" in r["tags"]


# --------------------------------------------------------------------------- payload extraction
# sha256 of the tiny header-only PEs the framework fixtures were generated from
TINY = {
    "tiny32.exe": "ff017f7e1ed24b96b6a210fce6b7c24524a33b732f0e898509f89e58b35c1742",
    "tiny64.exe": "a8e2e497becf950c15677f8835c24a3120e67bab80add34b64528a97b78f5a8e",
    "tiny32.dll": "3b672c35af53edf389177a8d57d8302c664a19d693024dc2fce01f57daaf5755",
    "tiny64.dll": "828a8d266b6149cc9099029fb5934376011fd04374d143167c39827ba85e8398",
}


def _sha(data):
    import hashlib

    return hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize(
    "name, framework, original",
    [
        ("donut_x64_enc", "Donut", "tiny64.exe"),  # Chaskey-CTR decrypted
        ("donut_x86_plain", "Donut", "tiny32.exe"),
        ("donut_x84_aplib", "Donut", "tiny64.exe"),  # decrypted, then aPLib-decompressed
        ("srdi_x64", "sRDI", "tiny64.dll"),
        ("srdi_x86", "sRDI", "tiny32.dll"),
    ],
)
def test_framework_payload_is_extracted_byte_exact(name, framework, original):
    r = analyse(_fixture(name), extract_payloads=True)
    (p,) = r["_payloads"]
    assert p["framework"] == framework and p["family"] == framework and _sha(p["data"]) == TINY[original]


def test_payloads_only_on_request_and_never_in_the_report():
    import json

    r = analyse(_fixture("donut_x64_enc"))
    assert "_payloads" not in r
    r = analyse(_fixture("donut_x64_enc"), extract_payloads=True)
    r.pop("_payloads")
    json.dumps(r)  # no bytes or callables left in the stored result
    assert not any(k.startswith("_") for f in r["frameworks"] for k in f)
    assert not any(k.startswith("_") for g in r["regions"] for k in g)


def test_staged_donut_has_nothing_to_extract():
    assert analyse(_fixture("donut_http"), extract_payloads=True)["_payloads"] == []


def test_pe2shc_payload_is_the_pe_without_its_loader():
    pe = bytearray(_pe_file())
    stub = len(pe)
    redir = b"MZER" + bytes.fromhex("e800000000594883e909488bc14805") + stub.to_bytes(4, "little") + b"\xff\xd0\xc3"
    pe[0 : len(redir)] = redir
    (p,) = analyse(bytes(pe) + MSF_STYLE_X64, extract_payloads=True)["_payloads"]
    assert p["framework"] == "pe2shc" and p["data"] == bytes(pe)


@pytest.mark.parametrize("data", [SGN_1, SGN_3])
def test_shikata_ga_nai_payload_is_the_decoded_shellcode(data):
    (p,) = analyse(data, extract_payloads=True)["_payloads"]
    assert p["framework"] is None and p["family"] is None  # an encoder is not a family detection
    assert (
        p["data"] == REVERSE_TCP_X86
        and p["description"].startswith("x86/shikata_ga_nai")
        and p["description"].endswith("decoded x86 code")
    )


def test_decoded_pe_and_code_regions_are_extracted_without_a_framework():
    payload = _pe_file()
    (p,) = analyse(DEC_LTS_PE_X86 + bytes(b ^ 0x37 for b in payload), arch="x86", extract_payloads=True)["_payloads"]
    assert p["framework"] is None and p["data"] == payload and p["offset"] == hex(len(DEC_LTS_PE_X86))
    code = MSF_STYLE_X86.ljust(0x200, b"\x90")
    (p,) = analyse(JMP_CALL_POP_STUB_X86 + bytes(b ^ 0x5A for b in code), arch="x86", extract_payloads=True)["_payloads"]
    assert p["data"] == code


def test_undecodable_region_is_not_extracted():
    assert analyse(FNSTENV_STUB_X86 + _rand(0x200, 1), arch="x86", extract_payloads=True)["_payloads"] == []


def test_donut_decompressors_match_published_vectors():
    from lib.cuckoo.common.integrations.shellcode_frameworks.donut import _decompress

    # MS-XCA 3.1 plain LZ77 examples
    assert _decompress("Xpress", bytes.fromhex("3f000000") + b"abcdefghijklmnopqrstuvwxyz", 26) == b"abcdefghijklmnopqrstuvwxyz"
    assert _decompress("Xpress", bytes.fromhex("ffffff1f61626317000fff2601"), 300) == b"abc" * 100
    lz = b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot"
    assert _decompress("LZNT1", lz, 64) == b"compressedtestdatacompressedalot"


def test_chaskey_keystreams_agree():
    from lib.cuckoo.common.integrations.shellcode_frameworks import donut as sc

    mk, ctr = bytes(range(16)), (2**128 - 3).to_bytes(16, "big")  # counter wraps mid-stream
    data = _rand(0x3000, 5)
    want = sc._ctr_read(mk, ctr, data, 0, 0x13, 0x2F00)
    assert sc._ctr_decrypt(mk, ctr, data, 0, 0x13, 0x2F00) == want
    if sc.np is not None:
        assert sc._chaskey_stream_np(mk, 2**128 - 3, 0x300) == sc._chaskey_stream(mk, 2**128 - 3, 0x300)


def test_cape_processing_detections_and_extracted_payloads(tmp_path, monkeypatch):
    import hashlib
    import json

    import lib.cuckoo.common.integrations.file_extra_info as fei_mod
    import lib.cuckoo.common.integrations.shellcode_utils as sc_utils
    import modules.processing.CAPE as cape_mod

    if not sc_utils.HAVE_SHELLCODE_CHECK:
        pytest.skip("static_shellcode_check disabled in processing.conf")
    monkeypatch.setattr(cape_mod, "mongo_find_one", lambda *a, **k: None)
    monkeypatch.setattr(cape_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(fei_mod, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(sc_utils, "SHELLCODE_ON_PAYLOADS", True)
    monkeypatch.setattr(sc_utils, "SHELLCODE_DETECTIONS", True)
    monkeypatch.setattr(sc_utils, "SHELLCODE_EXTRACT", True)
    (tmp_path / "CAPE").mkdir()
    with open(tmp_path / "files.json", "w") as fh:
        for data in (_fixture("donut_x64_enc"), SGN_1):
            sha = hashlib.sha256(data).hexdigest()
            (tmp_path / "CAPE" / sha).write_bytes(data)
            proc_path = "C:\\\\Windows\\\\System32\\\\rundll32.exe"
            meta = f"9;?{proc_path};?{proc_path};?0x00790000;?"
            fh.write(json.dumps({"path": f"CAPE/{sha}", "filepath": proc_path, "pids": [3768], "metadata": meta}) + "\n")

    class _Opts(dict):
        __getattr__ = dict.get

    proc = cape_mod.CAPE()
    proc.set_path(str(tmp_path))
    proc.task = {"id": 1, "category": "url", "target": "http://x", "options": ""}
    proc.results = {}
    proc.options = _Opts(buffer=8192, replace_patterns="")
    out = proc.run()

    assert {d["family"] for d in proc.results["detections"]} == {"Donut"}  # Shikata Ga Nai is an encoder
    assert all(next(iter(d["details"][0])) == "Shellcode" for d in proc.results["detections"])
    assert set(proc.results["detections2pid"]["3768"]) == {"Donut"}
    by_type = {p["cape_type"]: p for p in out["payloads"]}
    donut = by_type["Donut Shellcode Payload: 64-bit executable"]
    assert donut["sha256"] == TINY["tiny64.exe"] and donut["pid"] == 3768 and donut["process_name"] == "rundll32.exe"
    assert (tmp_path / "selfextracted" / TINY["tiny64.exe"]).read_bytes()[:2] == b"MZ"
    sgn = by_type["Extracted Shellcode Payload"]
    assert sgn["static_shellcode_check"]["verdict"] == "shellcode"  # decoded shellcode is checked too
    assert "extracted" not in sgn["static_shellcode_check"]  # ... but not extracted from again
    parent = next(p for p in out["payloads"] if p["sha256"] == donut["extracted_from"])
    assert parent["static_shellcode_check"]["extracted"][0]["sha256"] == donut["sha256"]


# Chromium's sandbox broker writes interception thunks (verbatim ntdll stubs) into its children;
# CAPE extracts them as Injected Shellcode/Data (27 bytes, seen from chrome.exe -> chrome.exe)
CHROME_THUNK_X64 = bytes.fromhex("4c8bd1b824000000f604250803fe7f0175030f05c3cd2ec30f1f84")


def test_copied_ntdll_stub_is_an_image_not_shellcode():
    r = analyse(CHROME_THUNK_X64)
    assert r["verdict"] == "image" and r["tags"] == ["syscall_stub_copy"] and "SSN 0x24" in r["reason"]
    # hand-written direct-syscall stubs share the legacy layout and stay shellcode
    r = analyse(bytes.fromhex("4c8bd1b8180000000f05c3") + b"\xcc" * 8)
    assert r["verdict"] == "shellcode" and "direct_syscall" in r["tags"]


def test_paths_without_letters_are_not_iocs():
    data = MSF_STYLE_X64 + b"\\\\33\\\\333333333333333333\\\\330\0" + b"C:\\Users\\Public\\run.dll\0"
    paths = analyse(data).get("iocs", {}).get("paths", [])
    assert paths == ["C:\\Users\\Public\\run.dll"]


def test_x64_encoder_evaluates_inner_payload_as_x64():
    from lib.cuckoo.common.integrations.shellcode_check import _xor_blocks

    inner = MSF_STYLE_X64 + b"\x90" * (-len(MSF_STYLE_X64) % 8)
    blocks = len(inner) // 8
    key = 0x1122334455667788
    stub = (
        b"\x48\x31\xc9\x48\x81\xe9"
        + (-blocks & 0xFFFFFFFF).to_bytes(4, "little")
        + b"\x48\x8d\x05\xef\xff\xff\xff\x48\xbb"
        + key.to_bytes(8, "little")
        + b"\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
    )
    r = analyse(stub + _xor_blocks(inner, key, 8))
    assert r["encoder"]["name"] == "x64/xor" and r["encoder"]["payload"] == "x64 code"
    assert "peb_walk" in r["encoder"]["payload_indicators"]


def test_alpha_encoder_rejects_non_ascii_latin1_bytes():
    from lib.cuckoo.common.integrations.shellcode_check import _MSF_ALPHA

    # 0xb2 ('²') and 0xb3 ('³') satisfy Unicode str.isalnum(), but are not ASCII alpha2 pairs
    blob = _MSF_ALPHA[0][0] + b"\xb2\xb3" * 16 + b"AA"
    assert not analyse(blob).get("encoder")


def test_framework_extract_caps_at_extract_max(monkeypatch):
    from lib.cuckoo.common.integrations import shellcode_check as sc

    monkeypatch.setattr(sc, "EXTRACT_MAX", 128)
    pe = bytearray(_pe_file())
    stub = len(pe)
    redir = b"MZER" + bytes.fromhex("e800000000594883e909488bc14805") + stub.to_bytes(4, "little") + b"\xff\xd0\xc3"
    pe[0 : len(redir)] = redir
    r = sc.analyse(bytes(pe) + MSF_STYLE_X64, extract_payloads=True)
    assert _framework(r, "pe2shc")["confidence"] == "identified"
    assert r["_payloads"] == []


# --- stack strings rebuilt from stack bytes; scored API sets; cipher primitives; custom PE magic
# (assembled with keystone)
PUSH_TAILS_X86 = bytes.fromhex(
    "fce8000000005d31c9648b41308b400c8b70146a74686e746578687265436f68617074756852746c4354ffd66a32686f6e30"
    "33686e63746968656d4675685379737454ffd631c0506845780000686c6c6f636875616c41685669727454ffd631c0506872"
    "790000684d656d6f6863657373686550726f685772697454ffd6c3"
)
WIDE_STACK_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020c744242077006900c74424246e006800c744242874007400"
    "c744242c70002e00c744243064006c00c74424346c000000c74424406e007400c744244464006c00c74424486c002e00c744"
    "244c64006c00c74424506c000000c3"
)
XOR_STACK_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b702048b90c33282e2f3b360a48ba5a5a5a5a5a5a5a5a4831d148"
    "894c242048b928352e3f392e5a5a48ba5a5a5a5a5a5a5a5a4831d148894c242848b9313f28343f36696848ba5a5a5a5a5a5a"
    "5a5a4831d148894c244048b9743e36365a5a5a5a48ba5a5a5a5a5a5a5a5a4831d148894c2448c3"
)
MEMXOR_STACK_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020c7442420615e4543c744242442565b76c74424285b5b5854"
    "c744242c37373737807424203780742421378074242237807424233780742424378074242537807424263780742427378074"
    "24283780742429378074242a378074242b378074242c378074242d378074242e378074242f37c3"
)
UNKNOWN_KEY_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b70208b8c2480000000c744242028353f2ec7442424395a5a5a31" "4c2420c3"
)
SSE_XOR_STACK_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020660f6f0517000000660fef051f000000f30f7f442420488d"
    "4c2420ffd6c3cc0c33282e2f3b360a28352e3f392e5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
)
FRAME_ALIAS_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b702053488d6c24904881ec700100004531ff458d4f65c7442478"
    "4765744ec744247c6174697644884d80c7458153797374c74585656d496e66c74589666fc6458b00c744242056697274c744"
    "242475616c41c74424286c6c6f63c744242c4c6f6164c74424304c696272c744243461727941c7442438536c656566c74424"
    "3c7000ffd6c3"
)
PUSH_POP_BYTES_X86 = bytes.fromhex(
    "fce8000000005d31c9648b41308b400c8b701483ec406a65596a6c5ac64424106b884c2411c644241272c64424136e884c24"
    "1488542415c644241633c644241732c64424182ec6442419648854241a8854241bc644241c00ffd6c3"
)
INJECT_HASHES_X86 = bytes.fromhex("fce8000000005d31c9648b41308b400c8b701468ae87923fffd568c5d8bde7ffd568c6ac9a79ffd5c3")
WRITE_ONLY_HASHES_X86 = bytes.fromhex("fce8000000005d31c9648b41308b400c8b701468ae87923fffd568c5d8bde7ffd5c3")
SLEEP_HASHES_X86 = bytes.fromhex("fce8000000005d31c9648b41308b400c8b701468fb6e0a07ffd5683d4256fcffd5c3")
CONTEXT_ONLY_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b702048b952746c436170747548894c242048b97265436f6e7465"
    "7848894c242848c7c17400000048894c243048b94e74436f6e74696e48894c244048c7c17565000048894c2448c3"
)
TEA_X86 = bytes.fromhex(
    "fce8000000005d31c9648b41308b400c8b7014b92000000031d281c2b979379e89f8c1e0040344241089fbc1eb05035c2414"
    "31d88d1c1731d801c64975dcc3"
)
TEA_ONLY_X86 = bytes.fromhex("b92000000031d281c2b979379e89f8c1e0040344241089fbc1eb05035c241431d88d1c1731d801c64975dcc3")
CUSTOM_MAGIC_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020488bbc248000000066813f4d5a75194863473c4801f86681"
    "384e4f750b8b48508b5028440fb74006c3"
)
STANDARD_MAGIC_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020488bbc248000000066813f4d5a75194863473c4801f86681"
    "385045750b8b48508b5028440fb74006c3"
)
MACHINE_CHECK_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020488bbc248000000066813f4d5a751a4863473c4801f86681"
    "78046486750b8b48508b5028440fb74006c3"
)
AES_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020488d3500020000b940000000f30f6f06660f38dec1660f38"
    "dfc2f30f7f064883c610ffc975e6c3"
)
AES_ONLY_X64 = bytes.fromhex("488d3500020000b940000000f30f6f06660f38dec1660f38dfc2f30f7f064883c610ffc975e6c3")
CHACHA_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020c70765787061c747046e642033c74708322d6279c7470c74" "65206bc3"
)


def _strings(data, arch):
    return analyse(data, arch=arch).get("stack_strings", [])


def test_pushed_strings_keep_short_tails_and_split_on_nul():
    # 'RtlCaptureContext' ends in a 1-byte push; adjacent strings must not run together
    assert _strings(PUSH_TAILS_X86, "x86") == ["RtlCaptureContext", "SystemFunction032", "VirtualAllocEx", "WriteProcessMemory"]


def test_utf16_stack_strings():
    r = analyse(WIDE_STACK_X64, arch="x64")
    assert r["stack_strings"] == ["winhttp.dll", "ntdll.dll"]
    assert any("UTF-16" in e["insn"] for e in r["evidence"] if e["indicator"] == "stack_string_api")


@pytest.mark.parametrize(
    "data, want",
    [
        (XOR_STACK_X64, ["VirtualProtect", "kernel32.dll"]),  # register xor with a constant key
        (MEMXOR_STACK_X64, ["VirtualAlloc"]),  # xor byte ptr [rsp + x], key
        (SSE_XOR_STACK_X64, ["VirtualProtect"]),  # xorstr style: movdqa/pxor rip-relative constants
    ],
)
def test_xor_obfuscated_stack_strings_are_decoded(data, want):
    r = analyse(data, arch="x64")
    assert r["stack_strings"] == want  # decoded, and no encoded junk alongside
    assert "stack_string_api" in r["tags"]


def test_stack_bytes_xored_with_unknown_key_are_not_reported():
    assert _strings(UNKNOWN_KEY_X64, "x64") == []


def test_frame_pointer_aliases_and_counted_names():
    # rbp = rsp - 0x70 taken before the frame is allocated (sRDI): one string spans both bases;
    # counted names laid end to end are split into the API names
    r = analyse(FRAME_ALIAS_X64, arch="x64")
    assert r["stack_strings"] == ["VirtualAlloc", "LoadLibraryA", "Sleep", "GetNativeSystemInfo"]
    assert {"VirtualAlloc", "LoadLibraryA", "Sleep"} <= set(r["apis"])


def test_push_imm_pop_reg_constants_feed_byte_stores():
    assert _strings(PUSH_POP_BYTES_X86, "x86") == ["kernel32.dll"]


@pytest.mark.parametrize(
    "data, arch, tag, present",
    [
        (INJECT_HASHES_X86, "x86", "remote_injection", True),  # VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
        (WRITE_ONLY_HASHES_X86, "x86", "remote_injection", False),  # no execution primitive
        (SLEEP_HASHES_X86, "x86", "sleep_obfuscation", True),  # timer + SystemFunction032
        (PUSH_TAILS_X86, "x86", "sleep_obfuscation", True),  # RtlCaptureContext + SystemFunction032 (stack strings)
        (CONTEXT_ONLY_X64, "x64", "sleep_obfuscation", False),  # RtlCaptureContext + NtContinue: one part only
    ],
)
def test_api_sets(data, arch, tag, present):
    r = analyse(data, arch=arch)
    assert (tag in r["tags"]) is present
    if present:
        assert next(i for i in r["indicators"] if i["name"] == tag)["confidence"] == "medium"


def test_api_sets_ignore_names_lying_in_data():
    # API names as plain strings in the buffer are reported, but are not resolved by the code
    r = analyse(WIDE_STACK_X64 + b"\0" * 16 + b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0", arch="x64")
    assert {"VirtualAllocEx", "CreateRemoteThread"} <= set(r["apis"])
    assert "remote_injection" not in r["tags"]


@pytest.mark.parametrize(
    "data, arch, tag",
    [
        (TEA_X86, "x86", "tea_delta"),
        (AES_X64, "x64", "aes_ni"),
        (CHACHA_X64, "x64", "chacha_constants"),
        (SLEEP_HASHES_X86, "x86", "rc4_systemfunction"),
    ],
)
def test_cipher_primitives_add_supporting_weight_in_shellcode(data, arch, tag):
    r = analyse(data, arch=arch)
    assert r["verdict"] == "shellcode"
    assert next(i for i in r["indicators"] if i["name"] == tag)["confidence"] == "low"


@pytest.mark.parametrize("data, arch", [(TEA_ONLY_X86, "x86"), (AES_ONLY_X64, "x64")])
def test_cipher_primitives_alone_are_not_reported(data, arch):
    r = analyse(data, arch=arch)
    assert r["verdict"] not in ("shellcode", "likely")
    assert not {"tea_delta", "aes_ni", "chacha_constants"} & set(r["tags"])
    assert r["score"] == 0


@pytest.mark.parametrize(
    "data, present",
    [(CUSTOM_MAGIC_X64, True), (STANDARD_MAGIC_X64, False), (MACHINE_CHECK_X64, False)],
)
def test_custom_pe_magic(data, present):
    r = analyse(data, arch="x64")
    assert ("pe_custom_magic" in r["tags"]) is present
    assert "pe_header_parse" in r["tags"]


def test_new_indicators_are_described():
    for tag in (
        "remote_injection",
        "sleep_obfuscation",
        "aes_ni",
        "chacha_constants",
        "tea_delta",
        "rc4_systemfunction",
        "pe_custom_magic",
        "aes_tables",
        "digest_constants",
        "base64_alphabet",
        "crypto_api",
    ):
        assert tag in INDICATORS


# --- framework modules: one folder, shipped and dropped-in modules alike
@pytest.fixture
def dropped_frameworks(tmp_path, monkeypatch):
    """A throwaway package standing in for modules dropped into shellcode_frameworks/ (the shipped
    folder is left untouched); the registry is reloaded around the test."""
    from lib.cuckoo.common.integrations import shellcode_frameworks as fwreg

    pkg = tmp_path / "sc_dropped_frameworks_test"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(fwreg, "PACKAGES", [fwreg.__name__, pkg.name])
    fwreg.reset()
    yield pkg
    fwreg.reset()
    for name in [m for m in sys.modules if m.startswith(pkg.name)]:
        del sys.modules[name]


TEST_LOADER = """
from lib.cuckoo.common.integrations.shellcode_frameworks import api

NAME = "TestLoader"
FAMILY = "TestFamily"


def identify(data):
    if data[:6] != b"TLDR\\x90\\x90":
        return None
    off, size = api.u32(data, 6), api.u32(data, 10)
    if not 14 <= off < off + size <= len(data):
        return None
    return {"name": NAME, "confidence": "identified", "arch": "x64",
            "evidence": ["TLDR header; payload offset and size land inside the buffer"],
            "details": {"payload": "x64 shellcode", "payload_size": size},
            "regions": [api.region(off, size, f"{size} bytes", result_type="shellcode", source="TLDR header")],
            "_payload": api.payload(lambda: bytes(data[off:off + size]), off, "TestLoader payload")}
"""


def _shipped(fwreg):
    return [f for f in fwreg.frameworks() if f.module.startswith(fwreg.__name__ + ".")]


def test_shipped_framework_modules_load_in_priority_order():
    from lib.cuckoo.common.integrations import shellcode_frameworks as fwreg

    shipped = [(f.name, f.family, f.priority) for f in _shipped(fwreg)]
    assert shipped == [("Donut", "Donut", 10), ("sRDI", "sRDI", 20), ("pe2shc", "pe2shc", 30)]


def test_dropped_in_framework_module_is_identified_and_extracted(dropped_frameworks):
    from lib.cuckoo.common.integrations import shellcode_frameworks as fwreg
    from lib.cuckoo.common.integrations.shellcode_check import framework_family

    (dropped_frameworks / "test_loader.py").write_text(TEST_LOADER)
    body = MSF_STYLE_X64
    blob = b"TLDR\x90\x90" + (16).to_bytes(4, "little") + len(body).to_bytes(4, "little") + b"\xcc\xcc" + body
    r = analyse(blob, extract_payloads=True)
    fw = _framework(r, "TestLoader")
    assert fw["confidence"] == "identified" and fw["label"] == "TestLoader: x64 shellcode"
    assert r["verdict"] == "shellcode" and "framework_layout" in r["tags"]
    assert any(g.get("framework") == "TestLoader" for g in r["regions"])
    assert [(p["framework"], p["family"], p["data"]) for p in r["_payloads"]] == [("TestLoader", "TestFamily", body)]
    assert framework_family("TestLoader") == "TestFamily"
    assert fwreg.frameworks()[-1].name == "TestLoader"  # default PRIORITY 100: after the shipped modules


def test_broken_framework_modules_are_isolated(dropped_frameworks):
    from lib.cuckoo.common.integrations import shellcode_frameworks as fwreg

    (dropped_frameworks / "syntax_error.py").write_text("NAME = 'Broken'\ndef identify(data)\n")
    (dropped_frameworks / "no_identify.py").write_text("NAME = 'NoIdentify'\n")
    (dropped_frameworks / "raises.py").write_text(
        "NAME = 'Raises'\nPRIORITY = 1\ndef identify(data):\n    raise ValueError('boom')\n"
    )
    (dropped_frameworks / "bad_result.py").write_text(
        "NAME = 'BadResult'\nPRIORITY = 2\ndef identify(data):\n    return {'confidence': 'certain'}\n"
    )
    (dropped_frameworks / "dup_name.py").write_text(
        "NAME = 'Donut'\nPRIORITY = 3\ndef identify(data):\n    return {'confidence': 'identified'}\n"
    )
    names = {f.name: f.module for f in fwreg.frameworks()}
    assert "Broken" not in names and "NoIdentify" not in names
    assert names["Donut"] == fwreg.__name__ + ".donut"  # a NAME already loaded is not taken over
    # the shipped modules still identify their layouts after modules that raise or misbehave
    pe = bytearray(_pe_file())
    stub = len(pe)
    redir = b"MZER" + bytes.fromhex("e800000000594883e909488bc14805") + stub.to_bytes(4, "little") + b"\xff\xd0\xc3"
    pe[0 : len(redir)] = redir
    assert _framework(analyse(bytes(pe) + MSF_STYLE_X64), "pe2shc")["confidence"] == "identified"


def test_shipped_framework_modules_reject_other_buffers_quickly():
    import time

    from lib.cuckoo.common.integrations import shellcode_frameworks as fwreg

    buffers = [_rand(1 << 20, 7), bytes(1 << 20), b"\xe8" + _rand(1 << 20, 8), _pe_file(), MSF_STYLE_X64, PUSH_TAILS_X86]
    for fw in _shipped(fwreg):
        start = time.perf_counter()
        assert not any(fw.identify(b) for b in buffers), fw.name
        assert time.perf_counter() - start < 1.0, fw.name  # a module must anchor on a cheap check first


# --- key-table decoders and cipher/hash/encoding primitives (stubs assembled with keystone)
XOR_TABLE_DIV_STUB_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b70204c8d153b0000004c8d1d2400000031c989c831d241b81000"
    "000041f7f0418a04134130040affc181f90010000072e141ffe2"
)
XOR_TABLE_AND_STUB_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b70204c8d15330000004c8d1d1c00000031c989ca83e20f418a04"
    "134130040affc181f9fe01000072e941ffe2"
)
JMP_TO_PE_STUB_X64 = bytes.fromhex("4881ec880000006548a16000000000000000488b4018488b7020488d1503000000ffe2cc")
RC4_KSA_X86 = bytes.fromhex("fce8000000005d31c9648b41308b400c8b701481ec0001000031c0880404403d0001000072f581c400010000c3")
AES_SBOX_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020488d15050000000fb6040ac3637c777bf26b6fc53001672b"
    "fed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
)
BASE64_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020488d15050000000fb6040ac34142434445464748494a4b4c"
    "4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839"
    "2b2f00"
)
SHA256_INIT_X64 = bytes.fromhex(
    "4881ec880000006548a16000000000000000488b4018488b7020c70767e6096ac7470485ae67bbc7470872f36e3cc7470c3a" "f54fa5c3"
)
SHA256_TWO_WORDS_X64 = bytes.fromhex("4881ec880000006548a16000000000000000488b4018488b7020c70767e6096ac7470485ae67bbc3")
CRYPT_HASHES_X86 = bytes.fromhex("fce8000000005d31c9648b41308b400c8b701468451b6341ffd56858c0ff24ffd56832c6b30effd5c3")
TABLE_KEY = bytes.fromhex("3a7f19c2e45b8d0611a2f3c4d5e6f708")
AES_SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")


def _xor_key(data, key):
    return bytes(b ^ key[j % len(key)] for j, b in enumerate(data))


@pytest.mark.parametrize(
    "stub, payload, want",
    [
        (XOR_TABLE_DIV_STUB_X64, lambda: _pe_file(), "a PE image"),  # key index = counter % 16 (div)
        (XOR_TABLE_AND_STUB_X64, lambda: MSF_STYLE_X64 * 2, "x64 code"),  # key index = counter & 15
    ],
)
def test_key_table_decoder_is_decoded_and_verified(stub, payload, want):
    body = payload()
    r = analyse(stub + TABLE_KEY + _xor_key(body, TABLE_KEY), arch="x64", extract_payloads=True)
    assert "decoded_payload" in r["tags"]
    stub_ev = next(e["insn"] for e in r["evidence"] if e["indicator"] == "decoder_stub")
    assert "16-byte key table at" in stub_ev
    assert want in next(e["insn"] for e in r["evidence"] if e["indicator"] == "decoded_payload")
    assert [p["data"] for p in r["_payloads"]] == [body]


def test_key_table_with_the_wrong_key_is_not_reported_as_decoded():
    # the loop is still a decoder, but the bytes it would produce do not verify as PE or code
    r = analyse(XOR_TABLE_AND_STUB_X64 + bytes(16) + _xor_key(MSF_STYLE_X64 * 2, TABLE_KEY), arch="x64", extract_payloads=True)
    assert "decoder_stub" in r["tags"] and "decoded_payload" not in r["tags"]
    assert r["_payloads"] == []


@pytest.mark.parametrize(
    "data, arch, tag",
    [
        (RC4_KSA_X86, "x86", "rc4_ksa"),  # no linked decoder: supporting weight
        (AES_SBOX_X64, "x64", "aes_tables"),
        (BASE64_X64, "x64", "base64_alphabet"),
        (SHA256_INIT_X64, "x64", "digest_constants"),
        (CRYPT_HASHES_X86, "x86", "crypto_api"),  # CryptAcquireContextA/CryptImportKey/CryptDecrypt by hash
    ],
)
def test_crypto_primitives_add_supporting_weight_in_shellcode(data, arch, tag):
    r = analyse(data, arch=arch)
    assert r["verdict"] == "shellcode"
    assert next(i for i in r["indicators"] if i["name"] == tag)["confidence"] == "low"


def test_crypto_primitives_need_evidence_of_their_own():
    # two SHA-256 words are not enough; an AES S-box inside a carried PE is the PE's, not the shellcode's
    assert "digest_constants" not in analyse(SHA256_TWO_WORDS_X64, arch="x64")["tags"]
    pe = bytearray(_pe_file())
    pe[0x400 : 0x400 + len(AES_SBOX)] = AES_SBOX
    assert "aes_tables" not in analyse(JMP_TO_PE_STUB_X64 + bytes(pe), arch="x64")["tags"]
    # tables in data that is not shellcode are not reported at all
    r = analyse(_rand(0x400, 11) + AES_SBOX + bytes(0x100), arch="x64")
    assert r["verdict"] not in ("shellcode", "likely") and "aes_tables" not in r["tags"]


def test_crypto_api_names_lying_in_data_do_not_count():
    r = analyse(SHA256_TWO_WORDS_X64 + b"\0" * 16 + b"CryptDecrypt\0BCryptDecrypt\0", arch="x64")
    assert "CryptDecrypt" in r["apis"] and "crypto_api" not in r["tags"]


# --- disassembly hardening: prefixed terminators, always-taken jcc pairs, inline strings, computed
# jumps, jmp-chained blocks, NOP sleds, and PE loader stages that must sit together
# (assembled with keystone; the *_X64/_X86 resolvers walk the PEB, parse exports and hash names)
RESOLVER_X64 = bytes.fromhex(
    "4883ec286548a16000000000000000488b4018488b7020488b5e20488b368b433c8b94038800000085d274eb4801da8b4a18"
    "448b42204901d8e3dcffc9458b14884901da4531c9410fb60249ffc241c1c90d4101c184c075ee4181f94c77260775d7448b"
    "42244901d8410fb70c48448b421c4901d8418b04884801d84883c428ffe0"
)
RESOLVER_X86 = bytes.fromhex(
    "6031c9648b41308b400c8b70148b5e108b368b433c8b54037885d274f001da8b4a188b7a2001dfe3e4498b2c8f01dd5631f6"
    "0fb6450045c1ce0d01c684c075f281fe4c7726075e75de8b7a2401df0fb70c4f8b7a1c01df8b048f01d88944241c61ffe0"
)
JZ_JNZ_JUNK_X64 = bytes.fromhex(
    "4883ec286548a16000000000000000488b4018488b7020740475029ab7488b5e20488b368b433c8b94038800000074047502"
    "f00e85d274e54801da8b4a18448b422074047502667f4901d8e3d0ffc9458b14884901da74047502e8504531c9410fb60249"
    "ffc241c1c90d74047502e9be4101c184c075e84181f9dec0d15a75cb448b422474047502667e4901d8410fb70c48448b421c"
    "4901d874047502c734418b04884801d84883c428ffe0"
)
INLINE_STRING_X64 = bytes.fromhex(
    "4883ec286548a16000000000000000488b4018488b7020488b5e20488b36e80d0000006b65726e656c33322e646c6c004883"
    "c4088b433c8b94038800000085d274d54801da8b4a18448b4220e80d0000006b65726e656c33322e646c6c004883c4084901"
    "d8e3b0ffc9458b14884901da4531c9410fb602e80d0000006b65726e656c33322e646c6c004883c40849ffc241c1c90d4101"
    "c184c075d84181f9dec0d15a75c1448b4224e80d0000006b65726e656c33322e646c6c004883c4084901d8410fb70c48448b"
    "421c4901d8418b04884801d8e80d0000006b65726e656c33322e646c6c004883c4084883c428ffe0"
)
LEA_JMP_X64 = bytes.fromhex(
    "4883ec286548a16000000000000000488b4018488b7020488b5e20488b364c8d1d0700000041ffe3ff066ed08b433c8b9403"
    "8800000085d274dd4801da8b4a18448b42204c8d1d0700000041ffe39a5dc7514901d8e3c0ffc9458b14884901da4531c941"
    "0fb6024c8d1d0700000041ffe3e947e34049ffc241c1c90d4101c184c075e04181f9dec0d15a75c9448b42244c8d1d070000"
    "0041ffe30f00026b4901d8410fb70c48448b421c4901d8418b04884801d84c8d1d0700000041ffe3ff5455944883c428ffe0"
)
PUSH_RET_X64 = bytes.fromhex(
    "4883ec286548a16000000000000000488b4018488b7020488b5e20488b364c8d1d070000004153c3ea65685d8b433c8b9403"
    "8800000085d274dd4801da8b4a18448b42204c8d1d070000004153c3ffc4980b4901d8e3c0ffc9458b14884901da4531c941"
    "0fb6024c8d1d070000004153c3ead4544a49ffc241c1c90d4101c184c075e04181f9dec0d15a75c9448b42244c8d1d070000"
    "004153c39a21a99a4901d8410fb70c48448b421c4901d8418b04884801d84c8d1d070000004153c3e8ad219e4883c428ffe0"
)
CHAINED_X64 = bytes.fromhex(
    "4883ec28e988000000410fb602e9bf0000004181f9dec0d15aeb28448b4224eb53488b36e9950000004901daeb4fffc9e980"
    "0000008b940388000000eb278b4a18eb487534ebd4488b5e20ebd44801daebec488b7020ebef4883c428eb4f410fb70c48eb"
    "4a85d2eb35418b0488eb394101c1eb624901d8ebe5e3ccebb14531c9eb877585eb8c4901d8ebee448b4220ebf56548a16000"
    "000000000000eb0474a7ebab488b4018ebaa4801d8ebabffe0448b421ceb17458b1488e96bffffff8b433ce96fffffff41c1"
    "c90deba34901d8eb9849ffc2ebf084c0eba8"
)
CHAINED_X86 = bytes.fromhex(
    "60eb2e0fb70c4feb4a8b7014eb6e8944241ceb14752ae9a00000008b7a20eb7384c0eb3a01d8ebe661eb0a648b4130eb7031"
    "c9ebf6ffe08b540378eb3749eb4ae33aebf901dfeb1e81fedec0d15aeb4b45eb1c8b7a1cebec0fb64500ebf275f8ebe67418"
    "eb298b048febb901ddeb3ac1ce0deb3885d2ebea01dfeb878b5e10eb168b4a18eb9531f6ebce8b2c8febdc01daebee01dfeb"
    "a98b36eb185ee973ffffff8b400ce960ffffff56ebda01c6e96dffffff8b433ce97cffffff8b7a24ebb8"
)
PLAIN_UNKNOWN_HASH_X64 = bytes.fromhex(
    "4883ec286548a16000000000000000488b4018488b7020488b5e20488b368b433c8b94038800000085d274eb4801da8b4a18"
    "448b42204901d8e3dcffc9458b14884901da4531c9410fb60249ffc241c1c90d4101c184c075ee4181f9dec0d15a75d7448b"
    "42244901d8410fb70c48448b421c4901d8418b04884801d84883c428ffe0"
)
PE_HEADERS_FN_X64 = bytes.fromhex("4863413c4801c88b5050448b4054448b4828c3")
PE_SECTIONS_FN_X64 = bytes.fromhex("0fb748068b530c448b4310448b4b144883c328ffc975edc3")
PE_IMPORTS_FN_X64 = bytes.fromhex("4863413c4801c88b90900000004801ca448b420c448b4a10490fbae23f4883c2144585c075eac3")
FILLER_FN_X64 = bytes.fromhex("534889cb488d045b4883c0074885c07404486bc0034889c15bc3cccc")
NOT_CODE = bytes.fromhex("c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5")
MIXED_SLED = bytes(
    [
        0x40,
        0x41,
        0x42,
        0x43,
        0x46,
        0x47,
        0x48,
        0x49,
        0x4A,
        0x4B,
        0x4E,
        0x4F,
        0x90,
        0x91,
        0x92,
        0x93,
        0x96,
        0x97,
        0x99,
        0x9B,
        0x9F,
        0xF5,
        0xF8,
        0xF9,
        0xFC,
        0xFD,
    ]
)
RESOLVER_TAGS = {"peb_walk", "export_table_parse", "api_hash_loop"}


@pytest.mark.parametrize(
    "terminator", ["c3", "f3c3", "f2c3", "3effe0", "f2ffe0"]
)  # ret, repz ret, bnd ret, notrack jmp rax, bnd jmp rax
def test_prefixed_returns_and_jumps_end_a_path(terminator):
    r = analyse(RESOLVER_X64[:-2] + bytes.fromhex(terminator) + NOT_CODE, arch="x64")
    assert r["verdict"] == "shellcode" and r["structure"]["bad_path_ratio"] == 0


@pytest.mark.parametrize(
    "data",
    [
        JZ_JNZ_JUNK_X64,  # jz X; jnz X; <junk bytes>; X:
        INLINE_STRING_X64,  # call over "kernel32.dll\0", the callee does not pop
        LEA_JMP_X64,  # lea r11, [rip + next]; jmp r11; <junk bytes>
        PUSH_RET_X64,  # lea r11, [rip + next]; push r11; ret; <junk bytes>
    ],
)
def test_anti_disassembly_constructs_do_not_hide_the_code(data):
    r = analyse(data, arch="x64")
    assert r["verdict"] == "shellcode" and r["structure"]["coherent"]
    assert RESOLVER_TAGS <= set(r["tags"])


@pytest.mark.parametrize("data, arch", [(CHAINED_X64, "x64"), (CHAINED_X86, "x86")])
def test_jmp_chained_blocks_are_matched_in_execution_order(data, arch):
    # every instruction is its own block ending in a jmp to the next, blocks shuffled; the hash is not a known one
    r = analyse(data, arch=arch)
    assert r["verdict"] == "shellcode"
    assert RESOLVER_TAGS | {"chained_blocks"} <= set(r["tags"])
    # evidence points at real offsets, inside the buffer
    assert all(int(e["offset"], 16) < len(data) for e in r["evidence"])
    assert "chained_blocks" not in analyse(PLAIN_UNKNOWN_HASH_X64, arch="x64")["tags"]


@pytest.mark.parametrize(
    "sled, arch",
    [
        (b"\x90" * 300000, "x86"),  # longer than the scan window
        (MIXED_SLED * 12000, "x86"),  # one-byte no-ops, longer than the scan window
        (b"\x0c" * 400001, "x86"),  # heap-spray filler (or al, 0xc), odd length
        (MIXED_SLED * 20, "x86"),
        (b"\x90" * 300000, "x64"),
        (b"\x66\x90" * 2000, "x64"),
    ],
)
def test_code_after_a_nop_sled_is_found(sled, arch):
    body = RESOLVER_X64 if arch == "x64" else RESOLVER_X86
    r = analyse(sled + body)  # no architecture hint
    assert r["verdict"] == "shellcode" and r["arch"] == arch
    assert RESOLVER_TAGS <= set(r["tags"])
    assert r["entry"] == hex(len(sled))
    assert next(i for i in r["indicators"] if i["name"] == "nop_sled")["confidence"] == "low"


def test_a_sled_alone_is_not_shellcode():
    assert analyse(b"\x90" * 300000)["verdict"] == "data"
    r = analyse(MIXED_SLED * 12000 + _rand(4096, 3))
    assert r["verdict"] not in ("shellcode", "likely") and "nop_sled" not in r["tags"]
    assert "nop_sled" not in analyse(b"ABCDEFGHIJKLMNO@" * 256 + b"\r\n" * 40)["tags"]  # text, not a sled


def _loader_stages(filler_fns):
    """Entry calling three PE loader stages (headers, sections, imports), with filler functions between them."""
    stages = [PE_HEADERS_FN_X64, PE_SECTIONS_FN_X64, PE_IMPORTS_FN_X64]
    entry_len = 5 * len(stages) + 1
    body, calls = b"", b""
    for i, stage in enumerate(stages):
        target = entry_len + len(body)
        calls += b"\xe8" + (target - (5 * i + 5)).to_bytes(4, "little", signed=True)
        body += stage + b"\xcc" + FILLER_FN_X64 * filler_fns
    return calls + b"\xc3" + body


def test_pe_loader_stages_must_sit_together():
    near = analyse(_loader_stages(20), arch="x64")
    assert near["verdict"] == "shellcode" and "reflective_pe_loader" in near["tags"]
    # the same stages tens of KB apart are unrelated functions: reported one by one, not as a loader
    far = analyse(_loader_stages(600), arch="x64")
    assert {"pe_header_parse", "pe_section_map", "pe_import_resolve"} <= set(far["tags"])
    assert "reflective_pe_loader" not in far["tags"] and far["verdict"] != "shellcode"


def test_new_layout_indicators_are_described():
    assert {"chained_blocks", "nop_sled"} <= set(INDICATORS)


# --- exception-driven control flow: SEH frames and vectored handlers the code sets up itself
# (assembled with keystone; each handler moves CONTEXT.Eip/Rip)
SEH_GETPC_X86 = bytes.fromhex(
    "e8000000005b8d83300000005064ff350000000064892500000000cc8f13c4e922770564a1300000008b400c8b70148b368b"
    "5e10c38b4c2404813903000080750e8b44240c8380b80000000831c0c331c040c3"
)
SEH_CALL_RET_X86 = bytes.fromhex(
    "e81e0000008b4c2404813903000080750e8b44240c8380b80000000831c0c331c040c331c064ff3064892031c9f7f164a130"
    "0000008b400c8b70148b368b5e10c3"
)
VEH_GETPC_X86 = bytes.fromhex(
    "e8000000005b8d8327000000506a01ff5610cc8f13c4e922770564a1300000008b400c8b70148b368b5e10c38b4424048b08"
    "8139050000c075108b48048381b80000000283c8ffc2040031c0c20400"
)
VEH_X64 = bytes.fromhex(
    "4883ec28b901000000488d1527000000ff5310cc058f13c4e92277056548a16000000000000000488b4018488b7020488b36"
    "488b5e20c3488b01813803000080751f488b4108488b90f80000000fb6520180f20d480190f8000000b8ffffffffc331c0c3"
)
SEH_EGG_HUNTER_X86 = bytes.fromhex(
    "e80e0000008b44240c8380b80000000631c0c331c064ff306489206681cbff0f43b89050905089dfaf75f5af75f2ffe7"
)
COMPILER_SEH_X86 = bytes.fromhex(
    "5589e56aff6834124000680015400064a100000000506489250000000083ec20ff15002040008b4df064890d0000000089ec" "5dc3"
)
STRUCT_WRITE_X64 = bytes.fromhex("534889fb488b47084889b0f8000000488b4b104885c974044889412031c05bc3")
HANDLER_NOT_TAKEN_X64 = bytes.fromhex(
    "4883ec28e8050000004883c428c3488b47084801f0c3488b01813803000080751f488b4108488b90f80000000fb6520180f2"
    "0d480190f8000000b8ffffffffc331c0c3"
)


@pytest.mark.parametrize(
    "data, arch, want",
    [
        # call/pop GetPC; lea eax, [ebx + handler]; push eax; push fs:[0]; mov fs:[0], esp; int3
        (SEH_GETPC_X86, "x86", {"seh_handler_install", "exception_context_rewrite", "exception_control_flow", "exception_trigger"}),
        # call over the handler: the return address is the frame's handler
        (SEH_CALL_RET_X86, "x86", {"seh_handler_install", "exception_context_rewrite", "exception_control_flow"}),
        # handler address pushed for AddVectoredExceptionHandler: [[esp + 4] + 4] -> Eip
        (VEH_GETPC_X86, "x86", {"exception_context_rewrite", "exception_control_flow"}),
        # lea rdx, [rip + handler]; the handler checks for a breakpoint and adds to Rip
        (VEH_X64, "x64", {"exception_context_rewrite", "exception_control_flow"}),
        # SEH egg hunter: the handler skips the faulting scasd, pages walked with or bx, 0xfff; inc ebx
        (SEH_EGG_HUNTER_X86, "x86", {"egg_hunter", "seh_handler_install", "exception_control_flow"}),
    ],
)
def test_exception_handlers_set_up_by_the_code(data, arch, want):
    r = analyse(data, arch=arch)
    assert r["verdict"] == "shellcode"
    assert want <= set(r["tags"])
    conf = {i["name"]: i["confidence"] for i in r["indicators"]}
    assert conf["exception_control_flow"] == "high" and conf["exception_context_rewrite"] == "medium"


@pytest.mark.parametrize(
    "data, arch",
    [
        (COMPILER_SEH_X86, "x86"),  # MSVC-style frame: absolute handler address
        (STRUCT_WRITE_X64, "x64"),  # mov rax, [rdi + 8]; mov [rax + 0xf8], rsi: some structure, not a CONTEXT
        (HANDLER_NOT_TAKEN_X64, "x64"),  # handler-shaped function whose address is never taken
    ],
)
def test_ordinary_code_is_not_an_exception_handler(data, arch):
    r = analyse(data, arch=arch)
    assert r["verdict"] not in ("shellcode", "likely")
    assert not {"seh_handler_install", "exception_control_flow", "exception_trigger"} & set(r["tags"])


def test_exception_handler_api_counts_only_when_resolved_by_the_code():
    name = b"RtlAddVectoredExceptionHandler"
    name += b"\0" * (-len(name) % 8)
    chunks = b"".join(b"\x48\xb9" + name[i : i + 8] + b"\x48\x89\x4c\x24" + bytes([0x20 + i]) for i in range(0, len(name), 8))
    r = analyse(RESOLVER_X64[:-2] + chunks + b"\xc3", arch="x64")  # movabs rcx, <8 chars>; mov [rsp + x], rcx
    assert "RtlAddVectoredExceptionHandler" in r["apis"]
    assert next(i for i in r["indicators"] if i["name"] == "exception_handler_api")["confidence"] == "medium"
    r = analyse(RESOLVER_X64 + b"\0" * 16 + b"AddVectoredExceptionHandler\0", arch="x64")  # only a string in the data
    assert "exception_handler_api" not in r["tags"]


def test_exception_indicators_are_described():
    assert {
        "seh_handler_install",
        "exception_context_rewrite",
        "exception_control_flow",
        "exception_trigger",
        "exception_handler_api",
    } <= set(INDICATORS)


# --- stage techniques: image base by backward scan, kernel entry points, self-modifying code, VM
# checks, feedback-keyed decoders, stager API sets, supporting patterns (assembled with keystone)
VMWARE_X86 = bytes.fromhex("b868584d5631dbb90a000000ba58560000ed81fb68584d560f94c0c3")
RED_PILL_X86 = bytes.fromhex("83ec08660f010c248b442402660f010424660f00c0660f00c983c408c3")
KERNEL_LSTAR_X64 = bytes.fromhex("b9820000c00f3248c1e2204809d0482500f0ffff6681384d5a7408482d00100000ebf1c3")
KERNEL_SYSENTER_X86 = bytes.fromhex("b9760100000f322500f0ffff6681384d5a74072d00100000ebf2c3")
KERNEL_IDT_X64 = bytes.fromhex("6548a13800000000000000488b400448c1e80c48c1e00c6681384d5a7408482d00100000ebf1c3")
MZ_SCAN_X64 = bytes.fromhex("488b042448250000ffff6681384d5a750c8b483c813c08504500007408482d00000100ebe5c3")
SEH_CHAIN_SCAN_X86 = bytes.fromhex("64a1000000008338ff74048b00ebf78b4004250000ffff6681384d5a74072d00000100ebf2c3")
SELF_PATCH_X64 = bytes.fromhex("c6050a0000009066c7050200000031c090ccccccc3")
SELF_PATCH_X86 = bytes.fromhex("e8000000005bc64310c3c74311909090909090909090ccccccccccc3")
TRAP_FLAG_X86 = bytes.fromhex("9c810c24000100009d90c3")
RWX_ARGS_X64 = bytes.fromhex("31c9ba0000100041b80030000041b940000000ffd04889c7b900100000f3a4ffe0")
CALLBACK_TABLE_X64 = bytes.fromhex("6548a16000000000000000488b4058488b4810c3")
PARAMS_WRITE_X64 = bytes.fromhex("6548a16000000000000000488b40204889506848894878c3")
EXCEPTION_DIR_X64 = bytes.fromhex("8b433c8b9403a00000004801da31c98b0285c074104801d84839f07408ffc14883c20cebea89c8c3")
MZ_SCAN_FORWARD_X64 = bytes.fromhex("488b042448250000ffff6681384d5a750c8b483c813c08504500007408480500000100ebe5c3")
GLOBAL_STORE_X64 = bytes.fromhex("c7050d00000001000000488b0506000000c3ccffffff170000000000000000")
PRINTABLE_STUB_X86 = bytes.fromhex(
    "50596834343434583534343434505a3441545e2d555555552d33333333504142495158314641684242424258354242303050"
    "596b46414130464250596834343434583534343434505a3441545e2d555555552d3333333350414249515831464168424242"
    "4258354242303050596b46414130464250596834343434583534343434505a3441545e2d555555552d333333335041424951"
    "58314641684242424258354242303050596b46414130464275384149424a4149424a4149424a4149424a4149424a4149424a"
    "4149424a4149424a4149424a4149424a4149424a4149424a4149424a4149424a4149424a4149424a4149424a4149424a4149"
    "424a4149424a"
)
SOCKET_STAGER_X86 = bytes.fromhex("fce8000000005d6829806b00ffd568ea0fdfe0ffd56899a57461ffd56802d9c85fffd568494693ceffd5c3")
BIND_SHELL_X86 = bytes.fromhex("fce8000000005d68ea0fdfe0ffd568c2db3767ffd568b7e938ffffd56874ec3be1ffd56879cc3f86ffd5c3")
HTTP_STAGER_X86 = bytes.fromhex("fce8000000005d683a5679a7ffd56857899fc6ffd568eb552e3bffd5682d06187bffd568129689e2ffd5c3")
DOWNLOAD_EXEC_X86 = bytes.fromhex("fce8000000005d688820fc31ffd568318b6f87ffd5c3")
SOCKET_ONLY_X86 = bytes.fromhex("fce8000000005d68ea0fdfe0ffd56899a57461ffd5c3")
FEEDBACK_CIPHER_STUB_X86 = bytes.fromhex("e8000000005e81c61c000000b919000000bbdec0d15a8b06311e89c383c604e2f5")
FEEDBACK_PLAIN_STUB_X86 = bytes.fromhex("e8000000005e81c61a000000b919000000bbdec0d15a311e8b1e83c604e2f7")
FEEDBACK_ADD_PLAIN_STUB_X86 = bytes.fromhex("e8000000005e81c61a000000b919000000bbdec0d15a311e031e83c604e2f7")
FEEDBACK_ADD_CONST_STUB_X86 = bytes.fromhex("e8000000005e81c61e000000b919000000bbdec0d15a311e81c34433221183c604e2f3")
FEEDBACK_UNKNOWN_STUB_X86 = bytes.fromhex("e8000000005e81c61a000000b919000000bbdec0d15a311e8b1f83c604e2f7")


def _confidence(r, tag):
    return next((i["confidence"] for i in r["indicators"] if i["name"] == tag), None)


@pytest.mark.parametrize(
    "data, arch, tags",
    [
        (MZ_SCAN_X64, "x64", {"image_base_scan"}),  # and rax, ~0xffff; cmp word [rax], 'MZ'; sub rax, 0x10000
        (SEH_CHAIN_SCAN_X86, "x86", {"image_base_scan", "seh_chain_walk"}),  # last SEH handler, then back to 'MZ'
        (KERNEL_LSTAR_X64, "x64", {"kernel_base_discovery", "kernel_msr_read", "image_base_scan"}),  # rdmsr 0xc0000082
        (KERNEL_SYSENTER_X86, "x86", {"kernel_base_discovery", "kernel_msr_read"}),  # rdmsr 0x176
        (KERNEL_IDT_X64, "x64", {"kernel_base_discovery"}),  # gs:[0x38] -> IDT entry -> back to 'MZ'
        (SELF_PATCH_X64, "x64", {"self_modifying_code"}),  # mov byte ptr [rip + next], 0x90
        (SELF_PATCH_X86, "x86", {"self_modifying_code"}),  # call/pop; mov byte ptr [ebx + n], 0xc3
    ],
)
def test_strong_stage_techniques(data, arch, tags):
    r = analyse(data, arch=arch)
    assert r["verdict"] == "shellcode" and tags <= set(r["tags"])
    assert all(_confidence(r, t) == ("medium" if t in ("kernel_msr_read", "seh_chain_walk") else "high") for t in tags)
    assert r["structure"]["bad_path_ratio"] == 0  # rdmsr is not counted against the code


def test_stage_techniques_need_their_whole_shape():
    # scanning forwards for 'MZ' looks for an appended image, not the code's own
    assert "image_base_scan" not in analyse(MZ_SCAN_FORWARD_X64, arch="x64")["tags"]
    # a RIP-relative store to data after the function is an ordinary global
    assert "self_modifying_code" not in analyse(GLOBAL_STORE_X64, arch="x64")["tags"]


def test_privileged_instructions_set_up_on_purpose_do_not_lower_the_verdict():
    r = analyse(RESOLVER_X86[:-2] + VMWARE_X86, arch="x86")
    assert r["verdict"] == "shellcode" and _confidence(r, "vmware_backdoor") == "medium"
    r = analyse(RESOLVER_X86[:-2] + RED_PILL_X86, arch="x86")
    assert r["verdict"] == "shellcode" and _confidence(r, "red_pill") == "low"
    # the same instructions with nothing leading up to them are still noise
    assert (
        analyse(RESOLVER_X86[:-2] + bytes.fromhex("ed0f32c3"), arch="x86")["structure"]["bad_path_ratio"] > 0
    )  # in eax, dx; rdmsr


@pytest.mark.parametrize(
    "data, arch, tag",
    [
        (TRAP_FLAG_X86, "x86", "trap_flag"),
        (RWX_ARGS_X64, "x64", "rwx_alloc_args"),
        (CALLBACK_TABLE_X64, "x64", "kernel_callback_table"),
        (PARAMS_WRITE_X64, "x64", "process_parameters_write"),
        (EXCEPTION_DIR_X64, "x64", "exception_directory_walk"),
    ],
)
def test_supporting_patterns_count_only_inside_shellcode(data, arch, tag):
    resolver = RESOLVER_X64 if arch == "x64" else RESOLVER_X86
    r = analyse(resolver[:-2] + data, arch=arch)
    assert r["verdict"] == "shellcode" and _confidence(r, tag) == "low"
    alone = analyse(data, arch=arch)
    assert alone["verdict"] not in ("shellcode", "likely") and tag not in alone["tags"]


def test_printable_code():
    r = analyse(PRINTABLE_STUB_X86, arch="x86")
    assert r["verdict"] == "likely" and _confidence(r, "printable_code") == "medium"
    for text in (b"ABCDEFGHIJKLMNO@" * 64, b"The quick brown fox jumps over the lazy dog. " * 40, b"0123456789ABCDEF" * 64):
        assert "printable_code" not in analyse(text, arch="x86")["tags"]


@pytest.mark.parametrize(
    "data, tag",
    [
        (SOCKET_STAGER_X86, "socket_stager"),  # WSASocketA + connect + recv
        (BIND_SHELL_X86, "socket_stager"),  # bind + listen + accept
        (HTTP_STAGER_X86, "http_stager"),  # InternetOpenA + InternetConnectA + InternetReadFile
        (DOWNLOAD_EXEC_X86, "download_execute"),  # URLDownloadToFileA + WinExec
    ],
)
def test_stager_api_sets(data, tag):
    r = analyse(data, arch="x86")
    assert _confidence(r, tag) == "medium"
    assert not {"socket_stager", "http_stager", "download_execute"} & set(analyse(SOCKET_ONLY_X86, arch="x86")["tags"])


def test_stack_spoofing_apis_resolved_by_the_code():
    def stack_string(name, at):
        name = name.encode() + b"\0"
        name += b"\0" * (-len(name) % 8)
        return b"".join(b"\x48\xb9" + name[i : i + 8] + b"\x48\x89\x4c\x24" + bytes([at + i]) for i in range(0, len(name), 8))

    r = analyse(
        RESOLVER_X64[:-2] + stack_string("BaseThreadInitThunk", 0x20) + stack_string("RtlUserThreadStart", 0x40) + b"\xc3",
        arch="x64",
    )
    assert _confidence(r, "stack_spoofing") == "medium"
    r = analyse(RESOLVER_X64 + b"\0" * 16 + b"BaseThreadInitThunk\0RtlUserThreadStart\0", arch="x64")  # names in data only
    assert "stack_spoofing" not in r["tags"]


def _feedback_encode(payload, key, mode):
    out = b""
    for (word,) in struct.iter_unpack("<I", payload):
        cipher = word ^ key
        out += struct.pack("<I", cipher)
        key = {
            "cipher": cipher,
            "plain": word,
            "add_plain": (key + word) & 0xFFFFFFFF,
            "add_const": (key + 0x11223344) & 0xFFFFFFFF,
            "unknown": key,
        }[mode]
    return out


@pytest.mark.parametrize(
    "stub, mode",
    [
        (FEEDBACK_CIPHER_STUB_X86, "cipher"),  # mov eax, [esi]; xor [esi], ebx; mov ebx, eax
        (FEEDBACK_PLAIN_STUB_X86, "plain"),  # xor [esi], ebx; mov ebx, [esi]
        (FEEDBACK_ADD_PLAIN_STUB_X86, "add_plain"),  # xor [esi], ebx; add ebx, [esi]
        (FEEDBACK_ADD_CONST_STUB_X86, "add_const"),  # xor [esi], ebx; add ebx, 0x11223344
    ],
)
def test_feedback_keyed_decoders_are_decoded_and_extracted(stub, mode):
    payload = RESOLVER_X86 + b"\x90" * (-len(RESOLVER_X86) % 4)
    r = analyse(stub + _feedback_encode(payload, 0x5AD1C0DE, mode), arch="x86", extract_payloads=True)
    assert "decoded_payload" in r["tags"]
    assert [p["data"] for p in r["_payloads"]] == [payload]
    if mode != "cipher":  # (ciphertext feedback resynchronises after one element whatever the start key)
        # a wrong start key decodes to nothing recognisable: reported as a stub only
        r = analyse(stub + _feedback_encode(payload, 0x11111111, mode), arch="x86", extract_payloads=True)
        assert "decoder_stub" in r["tags"] and "decoded_payload" not in r["tags"] and r["_payloads"] == []


def test_key_taken_from_memory_is_not_guessed():
    payload = RESOLVER_X86 + b"\x90" * (-len(RESOLVER_X86) % 4)
    r = analyse(FEEDBACK_UNKNOWN_STUB_X86 + _feedback_encode(payload, 0x5AD1C0DE, "unknown"), arch="x86", extract_payloads=True)
    assert "decoder_stub" in r["tags"] and "decoded_payload" not in r["tags"] and r["_payloads"] == []


def test_stage_indicators_are_described():
    from lib.cuckoo.common.integrations.shellcode_check import GROUPS

    for tag in ("image_base_scan", "seh_chain_walk", "kernel_msr_read", "kernel_base_discovery", "self_modifying_code", "vmware_backdoor", "red_pill",
                "trap_flag", "exception_directory_walk", "kernel_callback_table", "process_parameters_write", "rwx_alloc_args", "printable_code",
                "socket_stager", "http_stager", "download_execute", "stack_spoofing"):  # fmt: skip
        assert tag in INDICATORS and INDICATORS[tag][0] in GROUPS
