# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Fast static confirmation that an extracted CAPE payload is real shellcode.

No emulation. Three cheap tiers:

  Tier 0  byte statistics (padding / text / high-entropy blobs)
  Tier 1  structural validity: recursive descent from candidate entry points.
          "Decodes as x86" is meaningless (random data decodes ~95-99%), so
          validity means a coherent control-flow island: enough instructions,
          clean terminators, in-bounds branches, no privileged/legacy opcodes.
  Tier 2  shellcode semantics matched on the *reachable* instruction stream
          (PEB/Ldr walk, export-table parsing, API hashing, GetPC, decoder
          loops, direct/indirect syscalls, SSN harvesting, heaven's gate,
          stack strings, reflective PE loading, ...).

Scan depth: the first ``max_scan`` bytes are analysed fully (0 = everything);
larger payloads are never skipped. With ``deep_scan`` the analysis follows
branch targets that leave that window and shellcode anchors further in (e.g. a
pe2shc stub appended to a multi-MB PE), and embedded PE headers are located
across ``deep_bytes`` beyond the window. ``max_insns`` bounds the recursive
descent per code island.

Verdicts:
  shellcode  coherent code + at least one strong indicator (alertable)
  likely     coherent code + medium/weak indicators only
  code       coherent code, no shellcode traits (e.g. JIT, compiled code)
  image      a mapped PE image with its headers wiped, or a copy of ntdll's
             syscall stubs (unhooking): compiled code, not shellcode
  trampoline tiny stub that jumps/returns out of the buffer (hooks)
  data       not coherent code

Multi-stage constructs are matched by following the registers involved
(PEB walk: TEB -> PEB -> Ldr -> module list -> entry fields -> name/hash;
decoders: GetPC/RIP -> pointer -> loop) and reported as one evidence block.
A decoder loop counts only when its pointer comes from the blob itself; with a
constant key the region is decoded (no emulation) and checked for a PE, code
or text, giving the exact protected range where it can be proven.

Pure function of the bytes (+ optional VA hint) so it is cheap to re-run and
safe to cache by sha256. Only dependency is capstone (already a CAPE dep).
"""

import bisect
import math
import re
import struct
from collections import Counter
from timeit import default_timer

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    HAVE_CAPSTONE = True
except ImportError:  # pragma: no cover
    HAVE_CAPSTONE = False

try:  # optional: vectorised Chaskey for decrypting large Donut modules
    import numpy as np
except ImportError:  # pragma: no cover
    np = None

MAX_SCAN_DEFAULT = 256 * 1024
MAX_INSNS_DEFAULT = 8000
DEEP_BYTES_DEFAULT = 16 * 1024 * 1024
DEEP_WINDOWS = 4
DEEP_WINDOW_SIZE = 64 * 1024
TRUNCATION_SLACK = 0x1000
MAX_EMBEDDED_PE = 8
MAX_EVIDENCE_PER_INDICATOR = 8  # match locations kept per indicator (each indicator always keeps its first)
# capstone's disasm_lite decodes its whole input eagerly, so feed it small
# chunks: most paths end within a handful of instructions.
WINDOW = 512
CHUNK_INSNS = 32

VERDICT_RANK = {"data": 0, "trampoline": 1, "code": 2, "image": 2, "likely": 3, "shellcode": 4}
STRONG, MEDIUM, WEAK, INFO = 3, 2, 1, 0
# Shellcode confidence: how strongly an indicator on its own shows the blob is
# shellcode (not how malicious it is - that is what signature severity is for)
CONFIDENCE = {STRONG: "high", MEDIUM: "medium", WEAK: "low", INFO: "info"}
# Shown for context but never counted towards the score or the verdict
UNSCORED = frozenset({"decoder_loop"})
# Evidence that ties the code to shellcode behaviour by construction (followed
# registers, or exact structure). JIT / compiled-runtime fingerprints never
# override these.
LINKED = frozenset(
    {
        "peb_walk", "export_table_parse", "decoder_stub", "decoded_payload", "reflective_pe_loader", "syscall_stub_scan",
        "heavens_gate", "framework_layout", "executable_pe_header", "staged_pe", "getpc_self_base", "shikata_ga_nai",
        "fpu_getpc_decoder", "msf_encoder", "kernel_token_steal", "amsi_context_patch",
    }
)  # fmt: skip
MAX_BLOCK_LINES = 22
# indicators whose first match is summarised in the indicator table
DETAILED = frozenset(
    {
        "peb_walk", "decoder_stub", "decoded_payload", "encoded_payload", "framework_layout", "injected_call_stub",
        "ntdll_copy", "syscall_stub_copy", "mapped_image", "jit_code", "compiled_runtime", "reflective_pe_loader", "decoder_loop", "block_api_prologue",
    }
)  # fmt: skip
JIT_MIN_POINTERS = 8  # 64-bit absolute pointers loaded into registers
JIT_POINTER_RATIO = 0.01  # ... per instruction reached
DECODE_VERIFY_MAX = 0x10000  # bytes decoded to check a linked decoder's output

# Indicator groups (shown alongside each indicator)
GROUPS = {
    "peb_walk": "PEB/TEB access and loader-list walking to find modules",
    "export_parse": "Manual export-table parsing and MZ/PE checks to resolve APIs",
    "api_hashing": "API hashing loops, seeds and known API hash constants",
    "getpc": "GetPC / self-location (call-pop, jmp-call-pop, fnstenv, own base)",
    "decoders": "In-place decoder loops and encoders (e.g. Shikata Ga Nai, msfvenom encoders)",
    "syscalls": "Direct/indirect syscalls, SSN harvesting, hook checks, WoW64, ntdll remapping",
    "heavens_gate": "x86 to x64 far transitions",
    "stack_strings": "Strings built on the stack from immediates",
    "pe_loader": "Reflective/manual PE mapping, pe2shc headers, embedded and staged PEs",
    "egg_hunter": "Egg-hunter memory page walks",
    "patching": "In-memory function patching (AMSI/ETW/WLDP) and AMSI context corruption",
    "kernel": "Kernel-mode payload constructs (token stealing)",
    "anti_analysis": "Anti-debug, anti-VM, timing and KUSER_SHARED_DATA checks",
    "network": "Literal sockaddr_in (IP:port) of bind/reverse shells, and HTTP(S) stager configuration",
    "framework": "Output layout of known shellcode generators, matched exactly",
    "injection": "Injector-built stubs that call API addresses inside the target process",
    "layout": "Layout and origin hints (stack alignment, position dependence, JIT/compiled code)",
}

# tag -> (group, description shown to analysts)
INDICATORS = {
    "peb_access": ("peb_walk", "Reads the PEB pointer (fs:[0x30] / gs:[0x60], or via the TEB) but no loader walk follows"),
    "teb_access": ("peb_walk", "Reads the TEB self pointer (fs:[0x18] / gs:[0x30]) and nothing PEB-related follows"),
    "peb_walk": (
        "peb_walk",
        "Walks the loader lists, following the register: TEB/PEB -> Ldr -> module list -> entry fields -> name/hash",
    ),
    "module_name_compare": (
        "peb_walk",
        "Matches module/API names by 4-byte chunks ('kern', 'ntdl', 'Virt'...) or OR 0x20202020 case folding",
    ),
    "export_table_parse": ("export_parse", "Parses a module export directory (names/ordinals/functions)"),
    "pe_magic_check": ("export_parse", "Checks MZ/PE signatures of a module or image in memory"),
    "known_api_hash": ("api_hashing", "Uses a known API/module name hash constant"),
    "api_hash_loop": ("api_hashing", "Byte loop hashing API/module names (ror13, djb2, FNV, sdbm, ...)"),
    "hash_constant": ("api_hashing", "Hash algorithm seed or multiplier constant"),
    "speck_hash": ("api_hashing", "Speck ARX round (ror 8 / rol 3) - Maru-style API hashing (Donut)"),
    "getpc_call_pop": ("getpc", "call $+5; pop - obtains its own address"),
    "getpc_jmp_call_pop": ("getpc", "jmp/call/pop - obtains the address of trailing data"),
    "getpc_call4": ("getpc", "call $+4 (e8 ff ff ff ff) into its own last byte, then pop - obtains its own address"),
    "getpc_fnstenv": ("getpc", "fnstenv [esp-0xc] - obtains EIP via the FPU environment"),
    "getpc_self_base": ("getpc", "Computes its own start address (call/pop then -5), typical of loader bootstraps"),
    "getpc_call_over_data": (
        "getpc",
        "call forward over embedded data/code, then pop - obtains its address (Donut instance, MSF block_api)",
    ),
    "decoder_loop": ("decoders", "Loop with a decoder's shape whose pointer is not tied to the blob"),
    "decoder_stub": ("decoders", "Decoder loop whose pointer comes from GetPC/RIP: it decodes bytes of the blob itself"),
    "decoded_payload": ("decoders", "Linked decoder's region decoded statically: gives a PE, code or text (exact range)"),
    "fpu_getpc_decoder": (
        "decoders",
        "FPU instruction + fnstenv [esp-0xc] GetPC: the stub of an FPU GetPC decoder (Shikata Ga Nai, fnstenv_mov, alpha_mixed...)",
    ),
    "shikata_ga_nai": (
        "decoders",
        "Shikata Ga Nai decoder proven by decoding it (XOR additive feedback; the decoded tail rebuilds the stub's own loop). "
        "Metasploit's x86/shikata_ga_nai encoder; other implementations of it exist",
    ),
    "msf_encoder": (
        "decoders",
        "Exact decoder stub of a Metasploit (msfvenom) encoder, decoded statically: x64/xor, xor_dynamic, zutto_dekiru, "
        "call4_dword_xor, fnstenv_mov, countdown, jmp_call_additive, alpha_mixed/upper, unicode_mixed/upper",
    ),
    "encoded_payload": ("decoders", "High-entropy region a linked decoder works on (that region's own entropy)"),
    "framework_layout": (
        "framework",
        "Exact output layout of a known shellcode generator (Donut, sRDI, pe2shc); see Frameworks",
    ),
    "block_api_prologue": (
        "api_hashing",
        "Classic Metasploit block_api resolver prologue. Shared public code (also Cobalt Strike stagers and others), "
        "so not an attribution; current Metasploit shuffles this code",
    ),
    "rc4_ksa": ("decoders", "RC4 key schedule (256-entry init + swap loop) alongside a linked decoder"),
    "aplib_depacker": ("decoders", "aPLib depacker (cld; mov dl, 0x80; ...; movsb; mov bl, 2): unpacks a compressed payload"),
    "chaskey_cipher": ("decoders", "Chaskey ARX rotations (5/7/8/13/16) - Donut-style instance decryption"),
    "direct_syscall": ("syscalls", "mov r10, rcx; mov eax, SSN; syscall - bypasses user-mode hooks"),
    "indirect_syscall": ("syscalls", "mov r10, rcx; mov eax, SSN; jmp into ntdll's syscall gadget"),
    "syscall_insn": ("syscalls", "Executes syscall/sysenter directly"),
    "syscall_stub_scan": ("syscalls", "Reads syscall numbers out of ntdll stubs (Hell's/Halo's Gate)"),
    "gadget_scan": (
        "syscalls",
        "Searches memory for syscall / jmp [rbx] / jmp|call rbx gadgets (indirect syscalls, return-address spoofing)",
    ),
    "syscall_ssn_sort": (
        "syscalls",
        "Selects Zw* exports ('Zw' = 0x775a) to derive syscall numbers (SysWhispers2 / FreshyCalls style)",
    ),
    "hook_check": ("syscalls", "Tests a function prologue for an inline-hook jmp (0xe9)"),
    "int2e_syscall": ("syscalls", "Legacy int 0x2e system call"),
    "wow64_transition": ("syscalls", "Calls the WoW64 transition (fs:[0xc0]) directly"),
    "unhooking_string": ("syscalls", "References a clean ntdll source (KnownDlls / System32 ntdll path)"),
    "heavens_gate": ("heavens_gate", "Far transfer to the 0x33/0x23 code segment (heaven's gate)"),
    "stack_string": ("stack_strings", "String assembled on the stack from immediates"),
    "stack_string_api": ("stack_strings", "Stack-built string naming an API, DLL or interpreter"),
    "pe_header_parse": ("pe_loader", "Reads PE optional-header fields (SizeOfImage, ImageBase, EntryPoint)"),
    "pe_section_map": ("pe_loader", "Loops over section headers (0x28 stride) copying raw data"),
    "pe_reloc_fixup": ("pe_loader", "Applies base relocations (word entries, >>12 / &0xfff)"),
    "pe_import_resolve": ("pe_loader", "Resolves an import directory (descriptors, ordinal flag)"),
    "reflective_pe_loader": ("pe_loader", "Maps a PE image itself: headers + sections + relocs/imports"),
    "executable_pe_header": ("pe_loader", "DOS header is executable and jumps to a loader (pe2shc style)"),
    "staged_pe": ("pe_loader", "Loader or bootstrap carrying an embedded PE image"),
    "embedded_pe": ("pe_loader", "Contains a PE image (by NT header)"),
    "mapped_image": (
        "pe_loader",
        "A mapped PE image whose headers were wiped: its import hint/name table, or its x64 exception (.pdata) table, is in the blob",
    ),
    "pe_header_wipe": ("pe_loader", "Zero-fills SizeOfHeaders bytes of a mapped image: erases its MZ/PE headers from memory"),
    "kernel_token_steal": (
        "kernel",
        "Kernel payload: current thread from the KPCR (gs:[0x188] / fs:[0x124]), process list walked for PID 4, token copied",
    ),
    "zero_three_regs": ("layout", "xor ecx, ecx; mul ecx - zeroes eax, ecx and edx at once (hand-written shellcode idiom)"),
    "injected_call_stub": (
        "injection",
        "Small stub calling absolute API addresses in the target process (CreateRemoteThread/APC loader stub)",
    ),
    "ntdll_copy": ("syscalls", "Copy of ntdll's syscall stubs, 0x20 apart (clean ntdll mapped for unhooking)"),
    "syscall_stub_copy": (
        "syscalls",
        "The buffer is only verbatim ntdll syscall stub code: hook-bypass copies, or a browser sandbox's "
        "interception thunks (Chromium writes these into its child processes)",
    ),
    "egg_hunter": ("egg_hunter", "Walks memory pages looking for an egg marker"),
    "ret_patch_write": ("patching", "Writes ret / xor eax,eax;ret / E_INVALIDARG;ret / ret N patch bytes into memory"),
    "amsi_etw_patch": (
        "patching",
        "Patches AMSI/ETW/WLDP: patch bytes written (or an E_INVALIDARG patch array) + the target named on the stack or by hash",
    ),
    "amsi_context_patch": ("patching", "Checks the AMSI context's 'AMSI' signature, then overwrites it (AMSI context corruption)"),
    "anti_debug_peb": ("anti_analysis", "Reads PEB.BeingDebugged or PEB.NtGlobalFlag"),
    "hwbp_context": ("patching", "Sets CONTEXT_DEBUG_REGISTERS: hardware-breakpoint (patchless) AMSI/ETW bypass or hook evasion"),
    "anti_vm_cpuid": ("anti_analysis", "cpuid hypervisor bit / hypervisor vendor leaf check"),
    "rdtsc_timing": ("anti_analysis", "Paired rdtsc timing check"),
    "kuser_shared_data": ("anti_analysis", "Reads KUSER_SHARED_DATA (0x7ffe0000) directly"),
    "sockaddr_literal": ("network", "Literal sockaddr_in (AF_INET + port + IP) for connect/bind"),
    "http_stager_config": (
        "network",
        "wininet HTTP(S) stager (block_api style): host, port, URI and User-Agent reconstructed from its call-over-strings",
    ),
    "stack_align": ("layout", "Aligns the stack to 16 bytes on entry (and rsp, -16)"),
    "position_dependent": ("layout", "Absolute references into its own region (relocated / not PIC)"),
    "jit_code": ("layout", "JIT output: many absolute pointers into the process loaded and called (V8, CLR, HotSpot)"),
    "compiled_runtime": ("layout", "Compiled-runtime code: MSVC /GS cookie checks, __chkstk probes or Go stack checks"),
}

# Privileged / legacy opcodes that essentially never appear in user-mode
# shellcode but are extremely common when decoding random bytes.
RARE_MNEMONICS = frozenset(
    (
        "in out insb insw insd outsb outsw outsd hlt cli sti iret iretd iretq int1 arpl bound les lds into "
        "aaa aas daa das aam aad salc xlatb lgdt lidt lldt ltr clts rdmsr wrmsr invd wbinvd invlpg rsm lmsw "
        "sgdt sidt sldt lar lsl verr verw lss lfs lgs fdisi8087_nop feni8087_nop"
    ).split()
)
FAR_TRANSFERS = frozenset({"retf", "retfq", "ljmp", "lcall"})
COND_BRANCHES = frozenset("ja jae jb jbe je jg jge jl jle jne jno jnp jns jo jp js jcxz jecxz jrcxz loop loope loopne".split())
TERMINATORS = frozenset({"ret", "retn", "jmp", "ud2", "int3", "hlt"})
# Mnemonics that dominate real code. Data that happens to decode is mostly
# add/or/adc/sbb/and against memory, so the share of these separates the two.
CORE_MNEMONICS = frozenset(
    (
        "mov push pop call lea cmp test jmp ret xor sub movzx movsx movsxd shl shr sar imul nop inc dec cdq "
        "cqo leave lodsb lodsd stosb stosd ror rol xchg int3 sete setne cmove cmovne movabs movaps movups "
        "movdqa movdqu movq movd pushal popal pushfd popfd neg not bt div idiv mul syscall add and or"
    ).split()
)
_MEM_ALU = frozenset({"add", "or", "adc", "sbb", "and"})
_REG16 = frozenset("ax bx cx dx si di bp r8w r9w r10w r11w r12w r13w r14w r15w".split())
_IMM_MNEMONICS = frozenset("push mov movabs cmp xor sub imul add and or test lea".split())
_REG32 = frozenset("eax ebx ecx edx esi edi ebp r8d r9d r10d r11d r12d r13d r14d r15d".split())
# Common REX prefixes (0x48 REX.W, 0x49, 0x4c, 0x4d, 0x41, 0x44, 0x45) as x86 sees them
_REX_AS_X86 = frozenset(
    {("dec", "eax"), ("dec", "ecx"), ("dec", "esp"), ("dec", "ebp"), ("inc", "ecx"), ("inc", "esp"), ("inc", "ebp")}
)

# Byte patterns used as extra descent seeds (shellcode is often not at offset 0
# of an unpacked region). These only nominate entry points; indicators are
# still decided on decoded, reachable instructions.
SEED_PATTERNS = [
    re.compile(rb"\xfc\x48\x83\xe4\xf0"),  # cld; and rsp,-16 (MSF/CS x64)
    re.compile(rb"\xfc\xe8.\x00\x00\x00", re.S),  # cld; call (MSF/CS x86)
    re.compile(rb"\x55\x8b\xec"),  # push ebp; mov ebp,esp
    re.compile(rb"\x55\x89\xe5"),
    re.compile(rb"\x55\x48\x89\xe5"),
    re.compile(rb"\xe8\x00\x00\x00\x00[\x58-\x5f]"),  # call $+5; pop r32
    re.compile(rb"\xd9[\x74\x64]\x24\xf4"),  # fnstenv [esp-0xc]
    re.compile(rb"\x64\xa1\x30\x00\x00\x00"),  # mov eax, fs:[0x30]
    re.compile(rb"\x64\x8b[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]\x30\x00\x00\x00"),
    re.compile(rb"\x64\x8b[\x40-\x47\x49-\x4f\x50-\x57\x59-\x5f\x70-\x7f]\x30"),  # mov r, fs:[r+0x30]
    re.compile(rb"\x65[\x48\x4c]\x8b[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]\x25\x60\x00\x00\x00"),
    re.compile(rb"\x65[\x48\x49\x4c\x4d]\x8b[\x40-\x7f]\x60"),  # mov r, gs:[r+0x60]
    re.compile(rb"\x65\x48\xa1\x60\x00\x00\x00\x00\x00\x00\x00"),  # movabs rax, gs:[0x60]
    re.compile(rb"(?:\x4c\x8b\xd1|\x49\x89\xca)\xb8"),  # mov r10, rcx; mov eax, imm (syscall stub)
    re.compile(rb"\xe8[\x80-\xfb]\xff\xff\xff"),  # short backward call (jmp/call/pop GetPC)
    re.compile(rb"\x6a[\x23\x33]\xe8"),  # push 0x33/0x23; call (heaven's gate)
    re.compile(rb"\xe8\x00\x00\x00\x00[\x58-\x5f]\x48\x8d"),  # call $+5; pop rcx; lea rcx,[rcx-5] (own base)
    re.compile(rb"\x81[\x38-\x3f\x78-\x7f].?\x4c\x8b\xd1\xb8", re.S),  # cmp [r], 0xb8d18b4c (SSN harvest)
    re.compile(rb"\x66\x81\xca\xff\x0f"),  # or dx, 0xfff (egg hunter)
    re.compile(rb"[\x48\x49][\xb8-\xbf][\x20-\x7e]{6}"),  # movabs r64, "<ascii>" (x64 stack string)
]
DEEP_ANCHOR_RE = re.compile(b"|".join(p.pattern for p in SEED_PATTERNS), re.S)

# API hash table, generated rather than hand-typed. Each algorithm is checked
# against published constants in tests (e.g. ror13 LoadLibraryA 0xEC0E4E8E,
# MSF kernel32!LoadLibraryA 0x0726774C, Fewer KERNEL32.DLL 0x6A4ABC5B).
_HASH_APIS = {
    "kernel32.dll": (
        "LoadLibraryA LoadLibraryW LoadLibraryExA LoadLibraryExW GetProcAddress GetModuleHandleA GetModuleHandleW "
        "VirtualAlloc VirtualAllocEx VirtualProtect VirtualProtectEx VirtualFree VirtualQuery ExitProcess ExitThread "
        "WinExec CreateProcessA CreateProcessW CreateThread CreateRemoteThread WriteProcessMemory ReadProcessMemory "
        "OpenProcess Sleep WaitForSingleObject CloseHandle CreateFileA CreateFileW ReadFile WriteFile GetTempPathA "
        "GetVersion SetUnhandledExceptionFilter FlushInstructionCache CreateFileMappingA MapViewOfFile "
        "QueueUserAPC ResumeThread GetThreadContext SetThreadContext CreateTimerQueueTimer CreateFiber "
        "ConvertThreadToFiber SwitchToFiber EnumSystemLocalesA CreateNamedPipeA ConnectNamedPipe CreatePipe "
        "PeekNamedPipe GetComputerNameA GetUserNameA DeleteFileA MoveFileExA CreateToolhelp32Snapshot "
        "Process32First Process32Next AddVectoredExceptionHandler"
    ),
    "ntdll.dll": (
        "NtAllocateVirtualMemory NtProtectVirtualMemory NtWriteVirtualMemory NtCreateThreadEx NtMapViewOfSection "
        "NtCreateSection NtUnmapViewOfSection NtQueueApcThread NtFlushInstructionCache NtClose NtDelayExecution "
        "RtlExitUserThread RtlCreateUserThread LdrLoadDll LdrGetProcedureAddress LdrGetDllHandle "
        "RtlAddFunctionTable NtTraceEvent EtwEventWrite NtContinue RtlCaptureContext NtTestAlert "
        "NtQuerySystemInformation NtOpenProcess NtResumeThread NtGetContextThread NtSetContextThread "
        "RtlAddVectoredExceptionHandler RtlCreateTimer RtlCreateTimerQueue RtlRegisterWait "
        "NtSignalAndWaitForSingleObject NtWaitForSingleObject TpAllocWork TpPostWork TpReleaseWork "
        "RtlDecompressBuffer RtlDecompressBufferEx RtlGetCompressionWorkSpaceSize"
    ),
    "kernelbase.dll": "VirtualAlloc VirtualProtect LoadLibraryExA LoadLibraryExW GetProcAddress",
    "ws2_32.dll": "WSAStartup WSASocketA socket connect recv send bind listen accept closesocket",
    "wininet.dll": (
        "InternetOpenA InternetOpenW InternetConnectA InternetConnectW HttpOpenRequestA HttpOpenRequestW "
        "HttpSendRequestA HttpSendRequestW InternetReadFile InternetSetOptionA InternetErrorDlg"
    ),
    "winhttp.dll": (
        "WinHttpOpen WinHttpConnect WinHttpOpenRequest WinHttpSendRequest WinHttpReceiveResponse "
        "WinHttpReadData WinHttpQueryDataAvailable"
    ),
    "advapi32.dll": "RegOpenKeyExA RegSetValueExA CryptAcquireContextA SystemFunction032 SystemFunction033 OpenProcessToken",
    "mscoree.dll": "CLRCreateInstance CorBindToRuntime",
    "oleaut32.dll": "SafeArrayCreate SafeArrayCreateVector SysAllocString",
    "user32.dll": "MessageBoxA MessageBoxW",
    "shell32.dll": "ShellExecuteA ShellExecuteW",
    "urlmon.dll": "URLDownloadToFileA URLDownloadToFileW",
    "amsi.dll": "AmsiScanBuffer AmsiInitialize",
    "wldp.dll": "WldpQueryDynamicCodeTrust WldpIsClassInApprovedList",
}

# Capability classes inferred from APIs resolved by hash or named in strings
CAPABILITIES = {
    "memory_alloc_exec": ("VirtualAlloc", "VirtualProtect", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"),
    "remote_injection": (
        "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "NtWriteVirtualMemory", "CreateRemoteThread",
        "NtCreateThreadEx", "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "NtSetContextThread",
        "NtMapViewOfSection", "RtlCreateUserThread",
    ),
    "process_execution": ("WinExec", "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW"),
    "http_download": (
        "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WinHttpReadData", "URLDownloadToFileA", "URLDownloadToFileW",
    ),
    "raw_socket": ("WSAStartup", "WSASocketA", "socket", "connect", "bind", "listen", "accept", "recv", "send"),
    "named_pipe": ("CreateNamedPipeA", "ConnectNamedPipe", "PeekNamedPipe"),
    "dynamic_loading": ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LdrLoadDll", "GetProcAddress", "LdrGetProcedureAddress"),
    "amsi_etw_evasion": (
        "AmsiScanBuffer", "AmsiInitialize", "EtwEventWrite", "NtTraceEvent", "WldpQueryDynamicCodeTrust",
        "WldpIsClassInApprovedList",
    ),
    "veh_hwbp": ("AddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler"),
    "sleep_obfuscation": (
        "CreateTimerQueueTimer", "NtContinue", "RtlCaptureContext", "SystemFunction032", "SystemFunction033",
        "RtlCreateTimer", "RtlCreateTimerQueue", "RtlRegisterWait", "NtSignalAndWaitForSingleObject",
    ),
    "threadpool_execution": ("TpAllocWork", "TpPostWork", "TpReleaseWork"),
    "decompression": ("RtlDecompressBuffer", "RtlDecompressBufferEx", "RtlGetCompressionWorkSpaceSize"),
    "dotnet_hosting": ("CLRCreateInstance", "CorBindToRuntime", "SafeArrayCreate", "SafeArrayCreateVector"),
    "callback_execution": ("EnumSystemLocalesA", "CreateFiber", "ConvertThreadToFiber", "SwitchToFiber"),
    "discovery": ("GetComputerNameA", "GetUserNameA", "CreateToolhelp32Snapshot", "NtQuerySystemInformation"),
}  # fmt: skip
_API_NAMES = {n.lower(): n for names in _HASH_APIS.values() for n in names.split()}


def _ror32(v, n):
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def _h_ror13(data):
    h = 0
    for c in data:
        h = (_ror32(h, 13) + c) & 0xFFFFFFFF
    return h


def _h_djb2(data):
    h = 5381
    for c in data:
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def _h_djb2_xor(data):
    h = 5381
    for c in data:
        h = ((h * 33) ^ c) & 0xFFFFFFFF
    return h


def _h_sdbm(data):
    h = 0
    for c in data:
        h = (c + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def _h_fnv1a(data):
    h = 0x811C9DC5
    for c in data:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h


def _h_crc32(data):
    import zlib

    return zlib.crc32(data) & 0xFFFFFFFF


_HASH_ALGOS = {"ror13": _h_ror13, "djb2": _h_djb2, "djb2a": _h_djb2_xor, "sdbm": _h_sdbm, "fnv1a": _h_fnv1a, "crc32": _h_crc32}


def _build_api_hashes():
    table = {}

    def put(value, label):
        # tiny values collide with ordinary constants; never seen as real hashes
        if value >= 0x10000:
            table.setdefault(value, label)

    for module, names in _HASH_APIS.items():
        mod_ror13 = _h_ror13((module.upper() + "\0").encode("utf-16le"))
        for name in names.split():
            raw = name.encode()
            # MSF / Cobalt Strike block_api: ror13(module utf16 upper + NUL) + ror13(function + NUL)
            put((mod_ror13 + _h_ror13(raw + b"\0")) & 0xFFFFFFFF, f"block_api ror13: {module[:-4]}!{name}")
            for algo, fn in _HASH_ALGOS.items():
                for variant, label in ((raw, name), (raw.lower(), name), (raw.upper(), name)):
                    put(fn(variant), f"{algo}: {label}")
                put(fn(raw + b"\0"), f"{algo}+nul: {name}")
        for variant in (module, module.upper(), module[:-4], module[:-4].upper()):
            for enc in (variant.encode(), variant.encode("utf-16le")):
                for algo, fn in _HASH_ALGOS.items():
                    put(fn(enc), f"{algo}: module {module}")
    return table


KNOWN_API_HASHES = _build_api_hashes()
_KNOWN_HASH_SET = frozenset(KNOWN_API_HASHES)

HASH_SEEDS = {
    0x1505: "djb2 seed",
    0x1003F: "sdbm multiplier",
    0x811C9DC5: "FNV-1a 32 offset",
    0x01000193: "FNV 32 prime",
    0xCBF29CE484222325: "FNV-1a 64 offset",
    0x100000001B3: "FNV 64 prime",
    0xEDB88320: "CRC32 poly",
}

PAD_RUN_RE = re.compile(rb"(?:\x00{16,}|\xcc{8,}|\x90{8,})")
PAD_BYTES = frozenset({0x90, 0xCC})
# Strings that turn a stack string into evidence of API resolution
API_STRING_HINTS = (
    "clr.dll", "mscoree", "wldp", "v4.0.30319", "v2.0.50727",
    "kernel32", "ntdll", "kernelbase", ".dll", "virtualalloc", "virtualprotect", "loadlibrary", "getprocaddress",
    "createthread", "writeprocessmemory", "wininet", "winhttp", "ws2_32", "amsi", "etwevent", "nttraceevent",
    "urlmon", "shell32", "cmd.exe", "powershell",
)  # fmt: skip
AMSI_ETW_HINTS = ("amsi", "etwevent", "nttraceevent", "wldp")
AMSI_ETW_APIS = frozenset(
    {"AmsiScanBuffer", "AmsiInitialize", "AmsiOpenSession", "EtwEventWrite", "NtTraceEvent", "WldpQueryDynamicCodeTrust",
     "WldpIsClassInApprovedList"}
)  # fmt: skip
AMSI_SIGNATURE = 0x49534D41  # 'AMSI': first dword of the AMSI context AmsiScanBuffer validates
# 'Zw' as a little-endian word: export-name filter used to sort syscalls
ZW_WORD = 0x775A
# gadgets loaders look for: syscall (0f 05), jmp [rbx] (ff 23), jmp rbx (ff e3), call rbx (ff d3)
GADGET_WORDS = {0x050F: "syscall", 0x23FF: "jmp [rbx]", 0xE3FF: "jmp rbx", 0xD3FF: "call rbx"}
# patch bytes written over AMSI/ETW/WLDP functions (x86 forms clean up stdcall arguments:
# EtwEventWrite ret 0x14, AmsiScanBuffer ret 0x18)
PATCH_BYTES = (
    (b"\xb8\x57\x00\x07\x80\xc2\x18\x00", "mov eax, E_INVALIDARG; ret 0x18"),
    (b"\xb8\x57\x00\x07\x80\xc3", "mov eax, E_INVALIDARG; ret"),
    (b"\x48\x31\xc0\xc3", "xor rax,rax; ret"),
    (b"\x48\x33\xc0\xc3", "xor rax,rax; ret"),
    (b"\x31\xc0\xc2\x14\x00", "xor eax,eax; ret 0x14"),
    (b"\x33\xc0\xc2\x14\x00", "xor eax,eax; ret 0x14"),
    (b"\x31\xc0\xc3", "xor eax,eax; ret"),
    (b"\x33\xc0\xc3", "xor eax,eax; ret"),
    (b"\xc2\x14\x00", "ret 0x14"),
    (b"\xc2\x18\x00", "ret 0x18"),
)
_PATCH_FIRST = frozenset(seq[0] for seq, _ in PATCH_BYTES) | {0xC3}  # ret alone: byte stores
# returning E_INVALIDARG is distinctive enough to look for as raw bytes copied over the target
PATCH_ARRAYS = (b"\xb8\x57\x00\x07\x80\xc3", b"\xb8\x57\x00\x07\x80\xc2\x18\x00")


_OPERAND_WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


def _find_all(buf, needle, limit=8):
    out, at = [], buf.find(needle)
    while at != -1 and len(out) < limit:
        out.append(at)
        at = buf.find(needle, at + 1)
    return out


def _patch_write(v, width):
    """Name of the patch an immediate store writes: its bytes start with a patch sequence (rest
    padding), or are the first 4+ bytes of one written in pieces (mov dword 0x070057b8; mov word...)."""
    if v & 0xFF not in _PATCH_FIRST:
        return None
    raw = (v & ((1 << 8 * width) - 1)).to_bytes(width, "little")
    if width == 1:
        return "ret" if raw == b"\xc3" else None
    for seq, name in PATCH_BYTES:
        if raw.startswith(seq) and all(b in (0, 0x90, 0xCC) for b in raw[len(seq) :]):
            return name
        if width >= 4 and len(seq) > width and seq.startswith(raw):
            return name.split(";")[0] + " (first part)"  # the rest is written separately
    return None


def _name_chunks():
    """4-byte chunks of module/API names as compared by name-matching resolvers."""
    names = ["kernel32", "kernelbase", "ntdll", "advapi32", "ws2_32", "wininet", "winhttp", "user32", "amsi.dll",
             "virtualalloc", "virtualprotect", "loadlibrary", "getprocaddress", "createthread", "ntallocatevirtualmemory",
             "ntprotectvirtualmemory", "etweventwrite", "amsiscanbuffer", "ldrloaddll"]  # fmt: skip
    chunks = {}
    for name in names:
        for variant in (name, name.upper(), name[:1].upper() + name[1:]):
            for off in (0, 4):
                part = variant[off : off + 4]
                if len(part) == 4 and part.isalpha():
                    chunks[int.from_bytes(part.encode(), "little")] = f"'{part}'"
            wide = variant[:2]
            chunks[int.from_bytes(wide.encode("utf-16le"), "little")] = f"L'{wide}'"
    return chunks


NAME_CHUNKS = _name_chunks()
_REG_CANON = {}
for _full, _subs in {"a": ("rax", "eax", "ax", "al"), "b": ("rbx", "ebx", "bx", "bl"), "c": ("rcx", "ecx", "cx", "cl"),
                     "d": ("rdx", "edx", "dx", "dl"), "si": ("rsi", "esi", "si", "sil"), "di": ("rdi", "edi", "di", "dil"),
                     "bp": ("rbp", "ebp", "bp", "bpl"), "sp": ("rsp", "esp", "sp", "spl")}.items():  # fmt: skip
    for _r in _subs:
        _REG_CANON[_r] = _full
for _n in range(8, 16):
    for _sfx in ("", "d", "w", "b"):
        _REG_CANON[f"r{_n}{_sfx}"] = f"r{_n}"


def _canon(reg):
    return _REG_CANON.get(reg.strip())


_IMM_RE = re.compile(r"0x[0-9a-f]+|\b\d+\b")
_DISP_RE = re.compile(r"\[([a-z0-9]+)[^\]]*? ([+-]) (0x[0-9a-f]+)\]")
_STACK_BASES = frozenset({"esp", "ebp", "rsp", "rbp"})


def _parse_int(text):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def _entropy(counts, n):
    if not n:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def byte_stats(buf):
    n = len(buf)
    counts = Counter(buf)
    printable = sum(c for b, c in counts.items() if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return {
        "size": n,
        "entropy": round(_entropy(counts, n), 3),
        "zero_ratio": round(counts.get(0, 0) / n, 3) if n else 0.0,
        "printable_ratio": round(printable / n, 3) if n else 0.0,
        "distinct_bytes": len(counts),
    }


def _disp(op):
    """Signed displacements of non-stack memory operands in op (stack-frame
    slots such as [esp + 0x3c] say nothing about structure walking)."""
    out = []
    for base, sign, val in _DISP_RE.findall(op):
        if base in _STACK_BASES:
            continue
        v = int(val, 16)
        out.append(-v if sign == "-" else v)
    return out


_MEM_RE = re.compile(r"(?:(byte|word|dword|qword) ptr )?(?:([cdefgs]s):)?\[([^\]]+)\]")
_WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


def _mem(op):
    """First memory operand of op_str as (seg, base, index, scale, disp, width, text) or None.
    base/index are canonical register names ('rip' kept as such)."""
    m = _MEM_RE.search(op)
    if not m:
        return None
    size, seg, inner = m.groups()
    base = index = None
    scale = 1
    disp = 0
    for tok in inner.replace(" - ", " + -").split(" + "):
        tok = tok.strip()
        if "*" in tok:
            r, s = tok.split("*", 1)
            index, scale = _canon(r), _parse_int(s) or 1
        elif tok in ("rip", "eip"):
            base = "rip"
        elif _canon(tok):
            if base is None:
                base = _canon(tok)
            else:
                index = _canon(tok)
        else:
            v = _parse_int(tok)
            if v is not None:
                disp += v
    return seg, base, index, scale, disp, _WIDTH.get(size), m.group(0)


def _reg_bits(reg):
    reg = reg.strip()
    if reg in ("al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl") or (reg.startswith("r") and reg.endswith("b")):
        return 8
    if reg in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp") or (reg.startswith("r") and reg.endswith("w")):
        return 16
    if reg.startswith("e") or (reg.startswith("r") and reg.endswith("d")):
        return 32
    return 64


# Process structures (offsets from https://moval0x1.github.io/posts/the-peb-walk-anatomy/)
#   teb_peb  TEB.ProcessEnvironmentBlock      teb_self  TEB.NtTib.Self
#   ldr      PEB.Ldr                          heads     PEB_LDR_DATA list heads -> link offset in the entry
#   entry    LDR_DATA_TABLE_ENTRY fields, relative to the entry start
PEB_LAYOUT = {
    True: {
        "teb_peb": 0x60, "teb_self": 0x30, "ldr": 0x18, "dbg": 0x02, "gflag": 0xBC, "image_base": 0x10,
        "heads": {0x10: (0x00, "InLoadOrderModuleList"), 0x20: (0x10, "InMemoryOrderModuleList"),
                  0x30: (0x20, "InInitializationOrderModuleList")},
        "entry": {0x30: "DllBase", 0x38: "EntryPoint", 0x40: "SizeOfImage", 0x48: "FullDllName.Length",
                  0x50: "FullDllName.Buffer", 0x58: "BaseDllName.Length", 0x60: "BaseDllName.Buffer"},
        "links": (0x00, 0x10, 0x20), "names": (0x48, 0x58), "str_buf": 0x08,
    },
    False: {
        "teb_peb": 0x30, "teb_self": 0x18, "ldr": 0x0C, "dbg": 0x02, "gflag": 0x68, "image_base": 0x08,
        "heads": {0x0C: (0x00, "InLoadOrderModuleList"), 0x14: (0x08, "InMemoryOrderModuleList"),
                  0x1C: (0x10, "InInitializationOrderModuleList")},
        "entry": {0x18: "DllBase", 0x1C: "EntryPoint", 0x20: "SizeOfImage", 0x24: "FullDllName.Length",
                  0x28: "FullDllName.Buffer", 0x2C: "BaseDllName.Length", 0x30: "BaseDllName.Buffer"},
        "links": (0x00, 0x08, 0x10), "names": (0x24, 0x2C), "str_buf": 0x04,
    },
}  # fmt: skip
EXPORT_FIELDS = {0x18: "NumberOfNames", 0x1C: "AddressOfFunctions", 0x20: "AddressOfNames", 0x24: "AddressOfNameOrdinals"}
_LIST_SHORT = {
    "InLoadOrderModuleList": "InLoadOrder",
    "InMemoryOrderModuleList": "InMemoryOrder",
    "InInitializationOrderModuleList": "InInitOrder",
}
# Depth of a PEB walk stage (deepest one reached is reported)
_STAGE_DEPTH = {"TEB": 0, "PEB": 1, "Ldr": 2, "list": 3, "entry": 4, "name": 5}
_XFORMS = frozenset({"xor", "add", "sub", "rol", "ror", "not", "neg"})
_STRING_LOADS = {"lodsb": 1, "lodsw": 2, "lodsd": 4, "lodsq": 8}
_STRING_STORES = {"stosb": 1, "stosw": 2, "stosd": 4, "stosq": 8}
_WRITES_DST = frozenset(
    "mov movzx movsx movsxd movabs lea add sub xor or and adc sbb imul shl shr sar rol ror not neg inc dec pop xchg "
    "cmove cmovne cmovz cmovnz bswap".split()
)
_NAME_HASH_RE = re.compile(r"ror|rol|imul|shl|crc32")


class _Values:
    """Tiny forward tracker of register values over a straight-line window:
    constants, offsets into the blob (from GetPC / RIP) and symbolic structure
    pointers. No branches are followed; anything not understood is forgotten."""

    def __init__(self, is64):
        self.is64 = is64
        self.regs = {}  # canonical reg -> (kind, value)
        self.stack = []  # pushed values
        self.slots = {}  # (stack base, disp) -> value (spilled registers)

    def get(self, reg):
        return self.regs.get(_canon(reg) or reg)

    def put(self, reg, val, bits=64):
        c = _canon(reg)
        if not c:
            return
        if val is None:
            self.regs.pop(c, None)
            return
        if bits in (8, 16) and val[0] == "const":
            old = self.regs.get(c)
            if old and old[0] == "const":
                mask = (1 << bits) - 1
                val = ("const", (old[1] & ~mask) | (val[1] & mask))
            else:
                self.regs.pop(c, None)
                return
        self.regs[c] = val

    def addr(self, mem):
        """Value of base + index*scale + disp when it is known, else None."""
        seg, base, index, scale, disp, _, _ = mem
        val = ("const", 0) if base is None else self.regs.get(base)
        if val is None or base == "rip":
            return None
        if index is not None:
            iv = self.regs.get(index)
            if iv is None or iv[0] != "const":
                return None
            disp += iv[1] * scale
        return (val[0], val[1] + disp) if val[0] in ("const", "ptr") else (val[0], val[1], val[2] + disp)

    @staticmethod
    def _shift(val, delta):
        if val is None:
            return None
        if val[0] == "const":
            return ("const", (val[1] + delta) & 0xFFFFFFFFFFFFFFFF)
        if val[0] == "ptr":
            return ("ptr", val[1] + delta)
        return (val[0], val[1], val[2] + delta)

    def step(self, off, size, mn, op, load=None, getpc=None):
        """Apply one instruction. load(mem, addr_value) returns the value a memory
        load produces (structure walking); getpc(off) gives the blob offset a pop
        at off receives (call/pop GetPC)."""
        parts = op.split(", ", 1) if op else [""]
        dst = parts[0]
        src = parts[1] if len(parts) > 1 else ""
        cd = _canon(dst)
        bits = _reg_bits(dst) if cd else 64
        regs = self.regs
        if mn == "push":
            self.stack.append(regs.get(cd) if cd else (("const", _parse_int(op)) if _parse_int(op) is not None else None))
            del self.stack[:-16]
            return
        if mn == "pop":
            if cd:
                g = getpc(off) if getpc else None
                self.put(dst, ("ptr", g) if g is not None else (self.stack.pop() if self.stack else None))
            return
        if mn == "call":
            for r in ("a", "c", "d", "r8", "r9", "r10", "r11") if self.is64 else ("a", "c", "d"):
                regs.pop(r, None)
            return
        if mn in _STRING_LOADS:
            regs.pop("a", None)
            regs["si"] = self._shift(regs.get("si"), _STRING_LOADS[mn])
            return
        if mn in _STRING_STORES:
            regs["di"] = self._shift(regs.get("di"), _STRING_STORES[mn])
            return
        if not cd:
            # store: remember registers spilled to stack slots
            m = _mem(dst)
            if mn == "mov" and m and m[1] in ("sp", "bp") and m[2] is None and _canon(src):
                self.slots[(m[1], m[4])] = regs.get(_canon(src))
            return
        if mn in ("mov", "movabs", "movzx", "movsx", "movsxd", "lea"):
            m = _mem(src)
            if mn == "lea":
                if m and m[1] == "rip":
                    val = ("ptr", off + size + m[4])
                elif m:
                    val = self.addr(m)
                else:
                    val = None
            elif m:
                if m[0] is None and m[1] in ("sp", "bp") and m[2] is None and (m[1], m[4]) in self.slots:
                    val = self.slots[(m[1], m[4])]
                else:
                    val = load(m, self.addr(m)) if load else None
            elif _canon(src):
                val = regs.get(_canon(src))
                if val is not None and val[0] != "const" and self.is64 and bits == 32:
                    val = None  # a 32-bit copy truncates a pointer
            else:
                v = _parse_int(src)
                val = ("const", v & ((1 << bits) - 1)) if v is not None else None
            self.put(dst, val, bits if mn != "lea" else 64)
            return
        cur = regs.get(cd)
        if mn in ("add", "sub"):
            v = _parse_int(src)
            if v is None and _canon(src) and (regs.get(_canon(src)) or ("",))[0] == "const":
                v = regs[_canon(src)][1]
            if v is not None and cur is not None:
                regs[cd] = self._shift(cur, v if mn == "add" else -v)
            elif mn == "sub" and _canon(src) == cd:
                regs[cd] = ("const", 0)
            else:
                regs.pop(cd, None)
        elif mn in ("inc", "dec"):
            regs[cd] = self._shift(cur, 1 if mn == "inc" else -1) if cur is not None else None
            if regs[cd] is None:
                del regs[cd]
        elif mn == "xor" and _canon(src) == cd:
            regs[cd] = ("const", 0)
        elif mn in ("shl", "shr", "and", "or") and cur is not None and cur[0] == "const" and _parse_int(src) is not None:
            k = _parse_int(src)
            v = {"shl": cur[1] << (k & 63), "shr": cur[1] >> (k & 63), "and": cur[1] & k, "or": cur[1] | k}[mn]
            regs[cd] = ("const", v & 0xFFFFFFFFFFFFFFFF)
        elif mn == "xchg" and _canon(src):
            a, b = regs.get(cd), regs.get(_canon(src))
            self.put(dst, b)
            self.put(src, a)
        elif mn in _WRITES_DST:
            regs.pop(cd, None)


def _printable4(v, width=4):
    try:
        raw = v.to_bytes(width, "little")
    except (OverflowError, AttributeError):
        return None
    if all(0x20 <= b < 0x7F for b in raw) or (all(0x20 <= b < 0x7F or b == 0 for b in raw) and raw[0] != 0):
        return raw.rstrip(b"\x00").decode("ascii", "replace")
    return None


def _apply_xforms(data, width, keys):
    """Run a decoder's transform chain over data, element by element (no
    emulation: only constant keys). keys: [(op, key)]."""
    bits = 8 * width
    mask = (1 << bits) - 1

    def one(v):
        for op, k in keys:
            k &= mask
            if op == "xor":
                v ^= k
            elif op == "add":
                v = (v + k) & mask
            elif op == "sub":
                v = (v - k) & mask
            elif op == "not":
                v = ~v & mask
            elif op == "neg":
                v = -v & mask
            elif op in ("rol", "ror"):
                r = (k % bits) if op == "rol" else (bits - k % bits) % bits
                v = ((v << r) | (v >> (bits - r))) & mask
        return v

    if width == 1:
        return data.translate(bytes(one(b) for b in range(256)))
    n = len(data) // width
    fmt = {2: "H", 4: "I", 8: "Q"}[width]
    out = struct.pack(f"<{n}{fmt}", *(one(v) for v in struct.unpack_from(f"<{n}{fmt}", data)))
    return out + data[n * width :]


def _pe_raw_size(buf, nt):
    """Size of a PE file from its headers: end of the last section's raw data."""
    try:
        nsec = _u16(buf, nt + 6)
        opt = nt + 0x18
        size = _u32(buf, opt + 0x3C)  # SizeOfHeaders
        table = opt + _u16(buf, nt + 0x14)
        for k in range(min(nsec, 96)):
            sec = table + 0x28 * k
            if sec + 0x28 > len(buf):
                break
            raw_size, raw_ptr = _u32(buf, sec + 0x10), _u32(buf, sec + 0x14)
            if raw_size:
                size = max(size, raw_ptr + raw_size)
        return size or None
    except (IndexError, struct.error):
        return None


class _Descent:
    """Recursive descent over a buffer for one mode."""

    def __init__(self, buf, mode, max_insns, extent=None):
        self.buf = buf
        self.n = len(buf)
        # branch targets in [n, far_limit) are 'beyond the window' (rest of the
        # payload, or just past a page-truncated dump), not evidence of garbage
        self.far_limit = max(extent or 0, self.n + TRUNCATION_SLACK)
        self.md = Cs(CS_ARCH_X86, mode)
        self.md.skipdata = False
        self.max_insns = max_insns
        self.insns = {}  # offset -> (size, mnemonic, op_str)
        self.paths = 0
        self.bad_paths = 0
        self.clean_paths = 0
        self.rare = 0
        self.branches = 0
        self.oob = []  # (offset, target)
        self.targets = set()
        self.backedges = []  # (branch_off, target)
        self.far = []  # branch targets past the end of buf (followed by deep scan)
        self.spec = []  # bytes skipped by call-to-pop: walked only if they decode as code

    def run(self, entries):
        work = list(dict.fromkeys(entries))
        work.reverse()
        while len(self.insns) < self.max_insns:
            if not work:
                if not self.spec:
                    break
                start = self.spec.pop(0)
                if start not in self.insns and self._looks_like_code(start):
                    work.append(start)
                continue
            start = work.pop()
            if start in self.insns or not 0 <= start < self.n:
                continue
            self.paths += 1
            self._walk(start, work)

    def _looks_like_code(self, start, limit=48):
        """Trial linear decode: a clean run to a terminator, no legacy opcodes."""
        k = -1
        core = 0
        for k, (_, _, mn, op) in enumerate(self.md.disasm_lite(self.buf[start : start + 512], start, limit)):
            if mn in RARE_MNEMONICS or mn in FAR_TRANSFERS or (mn == "add" and op.endswith("], al")):
                return False
            core += mn in CORE_MNEMONICS or mn in COND_BRANCHES
            if mn in TERMINATORS:
                return k >= 2
        # no terminator yet, but a long clean run of ordinary instructions is code
        return k + 1 >= limit and core >= 0.7 * limit

    def _walk(self, start, work):
        off = start
        padding_run = 0
        gate = 0  # instructions left in which a far return counts as heaven's gate
        while True:
            window_end = min(off + WINDOW, self.n)
            last_end = off
            stop = None  # "clean" | "bad" | "merge" | "end"
            decoded = 0
            for addr, size, mn, op in self.md.disasm_lite(self.buf[off:window_end], off, CHUNK_INSNS):
                decoded += 1
                if addr in self.insns:
                    stop = "merge"
                    break
                self.insns[addr] = (size, mn, op)
                last_end = addr + size

                if mn == "add" and op in ("byte ptr [eax], al", "byte ptr [rax], al"):
                    padding_run += 1
                    if padding_run >= 4:
                        stop = "end"  # ran into zero padding (e.g. after a noreturn call)
                        break
                else:
                    padding_run = 0

                if mn in RARE_MNEMONICS:
                    self.rare += 1
                    stop = "bad"
                    break
                if mn == "push" and op in ("0x33", "0x23"):
                    gate = 6
                elif gate:
                    gate -= 1
                if mn in FAR_TRANSFERS:
                    # heaven's gate is the legitimate use; anything else is noise
                    if gate or "0x33:" in op or "0x23:" in op:
                        stop = "clean"
                    else:
                        self.rare += 1
                        stop = "bad"
                    break

                is_jmp = mn == "jmp"
                tgt = None
                if is_jmp or mn == "call" or mn in COND_BRANCHES:
                    tgt = _parse_int(op)
                    if tgt is not None:
                        self.branches += 1
                        if 0 <= tgt < self.n:
                            self.targets.add(tgt)
                            if tgt <= addr:
                                self.backedges.append((addr, tgt))
                            if tgt not in self.insns:
                                work.append(tgt)
                        elif self.n <= tgt < self.far_limit:
                            self.far.append(tgt)
                        else:
                            self.oob.append((addr, tgt))
                if mn == "call" and tgt is not None and addr + size < tgt < self.n:
                    b0 = self.buf[tgt]
                    if 0x58 <= b0 <= 0x5F or (b0 == 0x41 and tgt + 1 < self.n and 0x58 <= self.buf[tgt + 1] <= 0x5F):
                        # call forward to a pop: the skipped bytes are data (Donut instance) or
                        # code reached only indirectly (MSF block_api). Try them later on trial.
                        self.spec.append(addr + size)
                        stop = "clean"
                        break
                if mn in TERMINATORS:
                    stop = "clean"
                    self._gap_seed(addr + size, work)
                    break

            if stop is None:
                if last_end >= self.n:
                    stop = "end"
                elif decoded == CHUNK_INSNS or (window_end - last_end < 16 and window_end < self.n):
                    off = last_end  # chunk/window boundary, keep walking
                    continue
                elif window_end == self.n and self.n - last_end < 15:
                    stop = "end"  # last instruction cut off by the end of the buffer
                else:
                    stop = "bad"  # invalid instruction

            if stop == "bad":
                self.bad_paths += 1
            elif stop in ("clean", "merge"):
                self.clean_paths += 1
            return

    def _gap_seed(self, end, work):
        """After a terminator, nop/int3 alignment padding usually precedes the
        next function (e.g. a resolver placed after the entry stub)."""
        p = end
        while p < self.n and p - end < 32:
            if self.buf[p] in PAD_BYTES:
                p += 1
                continue
            filler = next(self.md.disasm_lite(self.buf[p : p + 15], p, 1), None)
            if filler is None or filler[2] not in ("nop", "int3", "ud2"):
                break
            p += filler[1]
        pad = p - end
        if p < self.n and p not in self.insns and (pad >= 2 or (pad == 1 and p % 16 == 0)):
            work.append(p)

    def misaligned_targets(self):
        if not self.targets:
            return 0
        starts = sorted(self.insns)
        bad = 0
        for t in self.targets:
            if t in self.insns:
                continue
            i = bisect.bisect_right(starts, t) - 1
            if i >= 0:
                s = starts[i]
                if s < t < s + self.insns[s][0]:
                    bad += 1
        return bad


class _Indicators:
    def __init__(self, is64, va, size, buf=b""):
        self.is64 = is64
        self.va = va
        self.size = size
        self.buf = buf
        self.hits = {}  # name -> weight
        self.evidence = []
        self.stack_strings = []
        self.apis = set()
        self.sockaddrs = []
        self.regions = []  # protected / decoded regions (decoders, Donut instance)
        self.va_hits = 0
        self.abs_refs = 0
        self.ext_refs = 0  # RIP-relative references outside the blob (imports, .rdata of an image)
        self.limit = size + TRUNCATION_SLACK
        self.jit_ptrs = 0  # 64-bit absolute pointers into the process (JIT code)
        self.runtime = Counter()  # compiled-runtime fingerprints
        self.ptr_calls = []  # (call offset, pointer) calls through a register loaded with an API address

    def add(self, name, weight, off, text, block=None):
        if name not in self.hits or weight > self.hits[name]:
            self.hits[name] = weight
        h = hex(off)
        same = [e for e in self.evidence if e["indicator"] == name]
        if len(same) < MAX_EVIDENCE_PER_INDICATOR and not any(e["offset"] == h for e in same):
            e = {"offset": h, "indicator": name, "insn": text}
            if block:
                e["block"] = sorted(dict((b[0], b) for b in block).values())[: MAX_BLOCK_LINES * 2]
            self.evidence.append(e)

    def _call4_pop(self, tgt):
        """(offset, 'pop reg') when the bytes at a call $+4 target are ff c0-cf (inc/dec reg), then pop."""
        if self.buf[tgt : tgt + 1] != b"\xff" or not 0xC0 <= (self.buf[tgt + 1 : tgt + 2] or b"\0")[0] <= 0xCF:
            return None
        md = Cs(CS_ARCH_X86, CS_MODE_64 if self.is64 else CS_MODE_32)
        for a, _, m, o in md.disasm_lite(self.buf[tgt : tgt + 12], tgt, 3):
            if m == "pop" and _canon(o):
                return a, f"pop {o}"
        return None

    def demote(self, name, weight):
        if name in self.hits and self.hits[name] > weight:
            self.hits[name] = weight

    def line(self, k, note=""):
        """(offset, text, note) of sequence index k, for evidence blocks."""
        off, (_, m, o) = self._seq[k]
        return (off, f"{m} {o}".strip(), note)

    def scan(self, insns):
        seq = sorted(insns.items())
        n = len(seq)
        is64 = self.is64
        exp_off = 0x88 if is64 else 0x78
        seg_starts = []  # sequence indexes of segment-relative reads (PEB walk start points)
        pushes = []  # running printable push immediates for stack strings
        movs = []
        va_hits = 0
        self._lfanew_reads = []  # sequence indexes of [r + 0x3c] loads (e_lfanew)
        reg_consts = {}  # canonical register -> (constant, seq index) from 'mov reg, imm'
        self._seq = seq
        scasd = any(m == "scasd" for _, (_, m, _) in seq)

        ptr_regs = {}  # canonical register -> (absolute API-like pointer, sequence index)
        self._call_targets = {}  # call target offset -> sequence indexes of the calls
        for i, (off, (size, mn, op)) in enumerate(seq):
            if mn == "call":
                t = _parse_int(op)
                if t is not None:
                    self._call_targets.setdefault(t, []).append(i)
        for i, (off, (size, mn, op)) in enumerate(seq):
            text = mn + " " + op if op else mn
            has_hex = "0x" in op
            dst = src = None
            if ", " in op:
                dst, src = op.split(", ", 1)

            # --- segment-relative operands: start points for the PEB walk tracker
            if "s:[" in op or mn in ("rdgsbase", "rdfsbase"):
                seg_starts.append(i)
                if mn == "call" and "fs:[0xc0]" in op:
                    self.add("wow64_transition", MEDIUM, off, text)

            # --- export directory parsing: e_lfanew (+0x3c) -> DataDirectory[0]
            # (+0x78/+0x88) -> NumberOfNames/AddressOf* (+0x18..+0x24)
            if "+ 0x3c]" in op and mn in ("mov", "add", "movsxd") and 0x3C in _disp(op):
                if mn != "movsxd":
                    for j in range(i + 1, min(n, i + 6)):
                        if exp_off in _disp(seq[j][1][2]):
                            fields = {}
                            for k in range(j + 1, min(n, j + 14)):
                                for d in _disp(seq[k][1][2]):
                                    if d in EXPORT_FIELDS and d not in fields:
                                        fields[d] = k
                            if len(fields) >= 2:
                                block = [self.line(i, "e_lfanew"), self.line(j, "DataDirectory[0]: export directory")]
                                block += [self.line(k, EXPORT_FIELDS[d]) for d, k in fields.items()]
                                self.add("export_table_parse", STRONG, off, text, block)
                            break
                if not op.startswith(("dword ptr [", "qword ptr [")):
                    self._lfanew_reads.append(i)

            if mn == "call":
                tgt = _parse_int(op)
                if tgt is not None:
                    nxt = seq[i + 1] if i + 1 < n else None
                    getpc_reg = None
                    if nxt and tgt == off + size:
                        if nxt[1][1] == "pop" and nxt[1][2] not in ("esp", "rsp"):
                            getpc_reg = nxt[1][2]
                        elif nxt[1][1] == "mov" and nxt[1][2].endswith((", dword ptr [esp]", ", qword ptr [rsp]")):
                            getpc_reg = nxt[1][2].split(",")[0]
                    if getpc_reg:
                        self.add("getpc_call_pop", STRONG, off, text)
                        reg = getpc_reg
                        after = seq[i + 2][1][1:] if i + 2 < n else ("", "")
                        if after in (("lea", f"{reg}, [{reg} - 5]"), ("sub", f"{reg}, 5")):
                            self.add("getpc_self_base", STRONG, off, f"{text}; pop {reg}; {after[0]} {after[1]}")
                    elif tgt == off + size - 1 and self._call4_pop(tgt):
                        # call $+4: lands on its own last byte (ff), which starts inc/dec reg; then pop
                        self.add("getpc_call4", STRONG, off, f"{text}  ; call $+4, then {self._call4_pop(tgt)[1]}")
                    elif tgt < off and tgt in insns and insns[tgt][1] == "pop":
                        self.add("getpc_jmp_call_pop", STRONG, off, text)
                    elif tgt > off + size + 3 and tgt in insns and insns[tgt][1] == "pop":
                        skipped = tgt - off - size
                        self.add("getpc_call_over_data", STRONG, off, f"{text}  ; skips {skipped} bytes, then pop {insns[tgt][2]}")
            elif mn in ("fnstenv", "fstenv"):
                if "sp - 0xc]" in op:
                    self.add("getpc_fnstenv", STRONG, off, text)
                    if any(seq[j][1][1][0] == "f" and seq[j][1][1] not in ("fnstenv", "fstenv") for j in range(max(0, i - 3), i)):
                        self.add("fpu_getpc_decoder", STRONG, seq[max(0, i - 3)][0], f"FPU op + {text}")

            # --- constants (immediates and displacements)
            if has_hex and mn in _IMM_MNEMONICS:
                for tok in _IMM_RE.findall(op):
                    v = _parse_int(tok)
                    if v is None or v < 0x100:
                        continue
                    v32 = v & 0xFFFFFFFF  # imm32 operands print sign-extended in 64-bit ops
                    if v32 in KNOWN_API_HASHES and mn in ("push", "mov", "cmp", "movabs", "xor", "sub"):
                        label = KNOWN_API_HASHES[v32]
                        self.add("known_api_hash", STRONG, off, f"{text}  ; {label}")
                        name = label.split(": ", 1)[-1].split("!")[-1]
                        if not name.startswith("module "):
                            self.apis.add(name)
                    if 0x7FFE0000 <= v32 < 0x7FFE1000 and v == v32:
                        # the Go runtime and some CRTs read it directly too, so it is weak on its own
                        self.add("kuser_shared_data", WEAK, off, f"{text}  ; KUSER_SHARED_DATA+{v32 - 0x7FFE0000:#x}")
                    elif v in HASH_SEEDS and mn in ("mov", "imul", "xor", "push", "movabs"):
                        self.add("hash_constant", WEAK, off, f"{text}  ; {HASH_SEEDS[v]}")
                    if v32 == 0xB8D18B4C and mn in ("cmp", "mov"):
                        # 4c 8b d1 b8 = 'mov r10, rcx; mov eax, SSN': reading syscall numbers out of ntdll stubs
                        self.add("syscall_stub_scan", STRONG, off, f"{text}  ; ntdll stub bytes (Hell's/Halo's Gate)")
                    if self.va is not None and self.va <= v < self.va + self.size:
                        va_hits += 1

            # --- absolute pointers loaded into registers: JIT code (many, all over), or an
            # injector-built stub (a few, each called straight away)
            if mn in ("mov", "movabs") and dst is not None and src and "[" not in src and _canon(dst):
                v = _parse_int(src)
                if v is not None and self._api_pointer(v):
                    ptr_regs[_canon(dst)] = (v, i)
                    if is64:
                        self.jit_ptrs += 1
            elif mn == "call" and _canon(op) in ptr_regs and i - ptr_regs[_canon(op)][1] <= 4:
                self.ptr_calls.append((i, ptr_regs[_canon(op)][0]))

            # --- compiled-runtime fingerprints (never shellcode traits)
            if mn == "xor" and src in ("rsp", "esp", "ebp") and i and seq[i - 1][1][1] == "mov":
                prev = seq[i - 1][1][2]
                if prev.startswith(dst + ", ") and ("ptr [rip" in prev or "dword ptr [0x" in prev):
                    self.runtime["MSVC /GS cookie"] += 1  # prologue: cookie ^ stack pointer
                elif prev.startswith(dst + ", ") and i + 1 < n and seq[i + 1][1][1] == "call":
                    self.runtime["MSVC /GS cookie"] += 1  # epilogue: __security_check_cookie
            elif mn == "sub" and op == "rsp, rax" and i >= 2 and seq[i - 1][1][1] == "call":
                p2 = seq[i - 2][1]
                if p2[1] == "mov" and p2[2].startswith("eax, ") and (_parse_int(p2[2][5:]) or 0) >= 0x1000:
                    self.runtime["__chkstk probe"] += 1
            elif mn == "cmp" and op.startswith(("rsp, qword ptr [r14 + 0x10]", "esp, dword ptr [ecx + 8]")):
                self.runtime["Go stack check"] += 1
            elif (
                mn == "cmp"
                and op == "rsp, qword ptr [rcx + 0x10]"
                and any("gs:[0x28]" in seq[j][1][2] for j in range(max(0, i - 3), i))
            ):
                self.runtime["Go stack check"] += 1

            # --- RIP-relative operands: inside the blob is self-contained; outside means the
            # code relies on an image around it (IAT, .rdata), as compiled x64 code does
            if is64 and "[rip" in op:
                d = _parse_int(op.split("[rip", 1)[1].split("]", 1)[0].replace(" ", "").replace("+", "") or "0")
                if d is not None:
                    t = off + size + d
                    if not 0 <= t < self.limit:
                        self.ext_refs += 1
                    elif t == 0 and mn == "lea" and off < 0x20:
                        self.add("getpc_self_base", STRONG, off, f"{text}  ; resolves to its own first byte")

            if has_hex and (op.endswith(", 0x100010") or (not is64 and op.endswith(", 0x10010"))):
                if mn == "mov" and "ptr [" in op and op.split("[", 1)[1].split(" ")[0].rstrip("]") not in ("esp",):
                    self.add("hwbp_context", MEDIUM, off, f"{text}  ; CONTEXT_DEBUG_REGISTERS")

            # --- absolute memory operands ([0x401000]) need relocation: not position independent
            if "ptr [0x" in op:
                a = _parse_int(op.split("ptr [", 1)[1].split("]", 1)[0])
                if a is not None and a >= 0x10000 and not 0x7FFE0000 <= a < 0x7FFF0000:
                    self.abs_refs += 1

            # --- xor r, r; mul r: zeroes eax, edx and r in two instructions (compilers never use mul for this)
            if mn == "mul" and i and _canon(op) and seq[i - 1][1][1] == "xor" and seq[i - 1][1][2] == f"{op}, {op}":
                self.add("zero_three_regs", WEAK, seq[i - 1][0], f"xor {op}, {op}; mul {op}")

            # --- AMSI context corruption: check its 'AMSI' signature, then overwrite it
            if mn == "cmp" and op.startswith("dword ptr [") and op.endswith(f", {AMSI_SIGNATURE:#x}"):
                mem = op.rsplit(", ", 1)[0]
                for k in range(i + 1, min(i + 12, n)):
                    km, ko = seq[k][1][1:]
                    if km in ("mov", "and", "xor", "or", "add", "sub", "inc", "dec", "not") and ko.split(", ")[0] == mem:
                        self.add("amsi_context_patch", STRONG, off, f"{text}  ; then {km} {ko}",
                                 [self.line(i, "AMSI context signature"), self.line(k, "overwritten")])  # fmt: skip
                        break

            push_s = mov_s = None
            if mn in ("mov", "movabs", "push"):
                v = _parse_int(src if src is not None else op) if has_hex or (src or op).isdigit() else None
                if mn != "push" and dst is not None:
                    cd = _canon(dst)
                    if cd:
                        if v is not None:
                            reg_consts[cd] = (v, i)
                        else:
                            reg_consts.pop(cd, None)
                if v is not None:
                    # --- literal sockaddr_in: AF_INET (2) + port (network order) [+ IPv4]
                    if v & 0xFFFF == 2 and (v >> 16) & 0xFFFF and not op.startswith(("byte", "word")):
                        port = ((v >> 16) & 0xFF) << 8 | (v >> 24) & 0xFF
                        ip = None
                        if v > 0xFFFFFFFF:  # x64: whole sockaddr in one imm64
                            ip = (v >> 32).to_bytes(4, "little")
                        elif mn == "push" and i > 0 and seq[i - 1][1][1] == "push":
                            prev = _parse_int(seq[i - 1][1][2])
                            if prev is not None and 0 < prev <= 0xFFFFFFFF:
                                ip = prev.to_bytes(4, "little")
                        if ip is not None and ip[0] not in (0, 255):
                            addr = f"{'.'.join(map(str, ip))}:{port}"
                            self.sockaddrs.append(addr)
                            self.add("sockaddr_literal", MEDIUM, off, f"{text}  ; sockaddr_in {addr}")
                    # --- in-memory patch of a resolved function (AMSI/ETW/WLDP style)
                    if mn != "push" and v >= 0xC3:
                        width = _OPERAND_WIDTH.get(dst.split(" ptr [", 1)[0]) if "[" in dst else (8 if mn == "movabs" else 4)
                        kind = _patch_write(v, width) if width and (width > 1 or "[" in dst) else None
                        base = dst.split("[")[-1].split(" ")[0].rstrip("]") if "[" in dst else None
                        if kind and base not in _STACK_BASES and (base is not None or width >= 4):
                            self.add("ret_patch_write", WEAK, off, f"{text}  ; {kind}")
                    # --- stack strings
                    if mn == "push":
                        if v >= 0x2020:
                            push_s = _printable4(v)
                    elif v >= 0x01000000 and (mn == "movabs" or dst.startswith(("dword ptr [", "qword ptr ["))):
                        mov_s = _printable4(v, 8 if v > 0xFFFFFFFF else 4)
                    elif v >= 0x01000000 and mn == "mov" and _canon(dst) and i + 1 < n:
                        # staged through a 32-bit register: mov ecx, 'Writ'; mov dword ptr [rsp+x], ecx
                        nm, no = seq[i + 1][1][1:]
                        if nm == "mov" and "ptr [" in no.split(",")[0] and _canon(no.rsplit(", ", 1)[-1]) == _canon(dst):
                            mov_s = _printable4(v, 8 if v > 0xFFFFFFFF else 4)
                    elif movs and 0x20 <= v & 0xFF < 0x7F and dst.startswith(("word ptr [", "byte ptr [")):
                        # the short tail of a run: mov word ptr [rsp+x], 'e\0'
                        mov_s = _printable4(v, 2 if dst.startswith("word") else 1)

            elif mn == "cmp" and dst is not None:
                v = _parse_int(src)
                if v is None and _canon(src) in reg_consts and i - reg_consts[_canon(src)][1] <= 16:
                    v = reg_consts[_canon(src)][0]
                if v is None and _canon(dst) in reg_consts and "[" in src and i - reg_consts[_canon(dst)][1] <= 16:
                    v = reg_consts[_canon(dst)][0]
                if v is not None:
                    # gadget / 'Zw' searches compare a *word* of scanned (non-stack) memory
                    mem = dst if "[" in dst else src
                    word = mem.startswith("word ptr [") or (src in _REG16 or dst in _REG16)
                    scanned = "[" in mem and mem.split("[", 1)[1].split(" ")[0].rstrip("]") not in _STACK_BASES
                    if word and scanned and v in GADGET_WORDS:
                        self.add("gadget_scan", MEDIUM, off, f"{text}  ; {GADGET_WORDS[v]} gadget bytes")
                    if word and scanned and v == ZW_WORD:
                        self.add("syscall_ssn_sort", STRONG, off, f"{text}  ; 'Zw' export filter")
                    v32 = v & 0xFFFFFFFF
                    if v32 > 0xFFFF and v32 in NAME_CHUNKS:
                        self.add("module_name_compare", STRONG, off, f"{text}  ; {NAME_CHUNKS[v32]}")
                    if v in (0x5A4D, 0x4550):
                        self.add("pe_magic_check", WEAK, off, text)
                    elif v == 0x4D and dst.startswith("byte ptr ["):
                        base = dst[dst.index("[") + 1 : dst.index("]")]
                        for j in range(i + 1, min(n, i + 6)):
                            if seq[j][1][1] == "cmp" and seq[j][1][2] == f"byte ptr [{base} + 1], 0x5a":
                                self.add("pe_magic_check", WEAK, off, text)  # byte-wise 'M' 'Z'
                                break
                    elif v == 0x4C and dst.startswith("byte ptr ["):
                        base = dst[dst.index("[") + 1 : dst.index("]")]
                        want = {f"byte ptr [{base} + 1], 0x8b", f"byte ptr [{base} + 2], 0xd1"}
                        if want <= {seq[j][1][2] for j in range(i + 1, min(n, i + 8)) if seq[j][1][1] == "cmp"}:
                            self.add("syscall_stub_scan", STRONG, off, f"{text}  ; byte-wise ntdll stub check")
                    elif v == 0xE9 and dst.startswith("byte ptr ["):
                        self.add("hook_check", WEAK, off, f"{text}  ; inline hook test")

            elif mn == "or":
                if op.endswith(", 0x20202020"):
                    self.add("module_name_compare", MEDIUM, off, f"{text}  ; lower-case 4 chars at once")
                elif op == "dx, 0xfff":
                    self.add("egg_hunter", STRONG if scasd else MEDIUM, off, text)
            elif mn == "and":
                if is64 and op == "rsp, 0xfffffffffffffff0":
                    self.add("stack_align", WEAK, off, text)
            elif mn in ("syscall", "sysenter"):
                self.add("syscall_insn", MEDIUM, off, text)
            elif mn == "int":
                if op == "0x2e":
                    self.add("int2e_syscall", MEDIUM, off, text)
            elif mn == "cpuid":
                near = [seq[j][1][1:] for j in range(max(0, i - 3), min(n, i + 8)) if j != i]
                if (
                    any(o.endswith(("ecx, 0x1f", "ecx, 0x80000000")) and m in ("bt", "test", "and") for m, o in near)
                    or ("mov", "eax, 0x40000000") in near
                ):
                    self.add("anti_vm_cpuid", MEDIUM, off, f"{text}  ; hypervisor check")
            elif mn in FAR_TRANSFERS:
                recent = [(seq[j][0], *seq[j][1]) for j in range(max(0, i - 6), i)]
                if "0x33:" in op or "0x23:" in op:
                    self.add("heavens_gate", STRONG, off, text)
                elif any(m == "push" and o in ("0x33", "0x23") for _, _, m, o in recent):
                    # canonical: push 0x33; call $+5; add [esp], N; retf
                    canonical = any(m == "call" and _parse_int(o) == a + sz for a, sz, m, o in recent) or any(
                        m == "add" and o.startswith(("dword ptr [esp]", "qword ptr [rsp]")) for _, _, m, o in recent
                    )
                    self.add("heavens_gate", STRONG if canonical else WEAK, off, text)

            # --- aPLib depacker prologue: cld; mov dl, 0x80; xor ebx, ebx; movsb; mov bl, 2
            if mn == "movsb" and 3 <= i < n - 1:
                prev = [seq[j][1][1:] for j in range(i - 3, i)]
                if (
                    prev[0][0] == "cld"
                    and prev[1] == ("mov", "dl, 0x80")
                    and prev[2][0] in ("xor", "sub")
                    and prev[2][1] == "ebx, ebx"
                    and seq[i + 1][1][1:] == ("mov", "bl, 2")
                ):
                    block = [self.line(j) for j in range(i - 3, i + 2)]
                    self.add("aplib_depacker", MEDIUM, seq[i - 3][0], "cld; mov dl, 0x80; xor ebx, ebx; movsb; mov bl, 2", block)

            # --- syscall stubs
            if is64 and op == "r10, rcx" and mn == "mov":
                win = [seq[j][1][1:] for j in range(i + 1, min(n, i + 4))]
                ssn = [_parse_int(o[5:]) for m, o in win if m == "mov" and o.startswith("eax, ")]
                # an immediate system-call number must be a real one (ntdll < 0x1000, win32u < 0x2000);
                # numbers loaded from a table or register (Hell's Gate) are accepted as they are
                plausible = all(v is None or 0 <= v < 0x2000 for v in ssn)
                if plausible and any(m == "syscall" for m, _ in win):
                    self.add("direct_syscall", STRONG, off, text)
                elif plausible and ssn and any(m == "jmp" and _parse_int(o) is None for m, o in win):
                    # SSN set up, then jump into ntdll's own 'syscall; ret' gadget
                    self.add("indirect_syscall", STRONG, off, text)

            # --- stack-string runs
            if push_s:
                pushes.append((off, push_s))
            elif pushes:
                self._flush_stack(pushes, reverse=True)
            if mov_s:
                movs.append((off, mov_s))
            elif movs and not (mn == "mov" and op.startswith(("dword ptr [", "qword ptr [")) and _canon(op.rsplit(", ", 1)[-1])):
                self._flush_stack(movs, reverse=False)

        self._flush_stack(pushes, reverse=True)
        self._flush_stack(movs, reverse=False)
        rd = [k for k, (_, (_, m, _)) in enumerate(seq) if m == "rdtsc"]
        if any(b - a <= 40 for a, b in zip(rd, rd[1:])):
            self.add("rdtsc_timing", WEAK, seq[rd[0]][0], "rdtsc ... rdtsc")
        self._peb_walks(seq, seg_starts)
        self._loops(seq, insns)
        self._decoders(seq)
        self._pe_loader(seq)
        self._kernel_token_steal(seq)
        self._injected_stub(seq)
        self._link_resolvers()
        named = sorted({s for s in self.stack_strings if any(h in s.lower() for h in AMSI_ETW_HINTS)} | (self.apis & AMSI_ETW_APIS))
        if named:
            arrays = [(o, p) for p in PATCH_ARRAYS for o in _find_all(self.buf, p)]
            if "ret_patch_write" in self.hits or arrays:
                how = (
                    "patch write" if "ret_patch_write" in self.hits else f"patch bytes {arrays[0][1].hex(' ')} at {arrays[0][0]:#x}"
                )
                at = next((int(e["offset"], 16) for e in self.evidence if e["indicator"] == "ret_patch_write"), None)
                at = arrays[0][0] if at is None else at
                self.add("amsi_etw_patch", STRONG, at, f"{how} + {', '.join(named[:3])}")
        self.va_hits = va_hits
        if self.va is not None and va_hits >= 3:
            self.add("position_dependent", 0, 0, f"{va_hits} absolute refs into own region")

    def attach_context(self, lines):
        """Disassembly around each match so the analyst sees where it fired.
        Multi-stage matches (PEB walk, decoder, PE loader, export parse) carry a
        block: every stage instruction highlighted with its note, the
        instructions in between elided as '...'. Lines are
        [offset, text, highlighted, note]."""
        if not self.evidence:
            return
        seq = self._seq
        offs = [o for o, _ in seq]
        for e in self.evidence:
            block = e.pop("block", None)
            if block and lines > 0:
                ctx = []
                prev = None
                for off, text, note in block:
                    k = bisect.bisect_left(offs, off)
                    if prev is not None and k > prev + 1:
                        if k == prev + 2:
                            o, (_, m, op) = seq[prev + 1]
                            ctx.append([hex(o), f"{m} {op}".strip(), False, ""])
                        else:
                            ctx.append(["", "...", False, f"{k - prev - 1} instructions"])
                    ctx.append([hex(off), text, True, note])
                    prev = k
                e["context"] = ctx[:MAX_BLOCK_LINES]
                continue
            if lines <= 0:
                continue
            off = int(e["offset"], 16)
            k = bisect.bisect_left(offs, off)
            if k >= len(offs) or offs[k] != off:
                k = max(0, k - 1)
            e["context"] = [[hex(o), f"{m} {op}".strip(), o == off, ""] for o, (_, m, op) in seq[max(0, k - lines) : k + lines + 1]]

    def _api_pointer(self, v):
        """Looks like an absolute address in another module/heap of the process
        (not a string, hash or small constant)."""
        if v in _KNOWN_HASH_SET or v in HASH_SEEDS:
            return False
        if self.is64:
            return 0xFFFFFFFF < v < 0x800000000000 and _printable4(v, 8) is None
        return 0x00400000 <= v < 0x80000000 and _printable4(v) is None

    # ------------------------------------------------------------ PEB walk
    def _peb_walks(self, seq, starts, window=64):
        """Follow the register(s) holding TEB/PEB pointers from each segment read
        through the loader structures, and report the deepest stage reached as
        one walk with every stage instruction (see PEB_LAYOUT)."""
        if not starts:
            return
        lay = PEB_LAYOUT[self.is64]
        seg = "gs" if self.is64 else "fs"
        n = len(seq)
        walks = []
        done = set()
        jobs = []
        for i in starts:
            mm = _mem(seq[i][1][2])
            # a fixed segment offset that is neither TEB nor PEB (TLS slots, Go's g pointer ...)
            if mm and mm[0] == seg and mm[1] is None and mm[2] is None and mm[4] not in (lay["teb_peb"], lay["teb_self"]):
                continue
            if mm and mm[0] is not None and mm[0] != seg:
                continue
            jobs.append((i, None))
        while jobs:
            start, carried = jobs.pop(0)
            if (start, carried is not None) in done:
                continue
            done.add((start, carried is not None))
            vals = _Values(self.is64)
            events = []  # (seq index, note, depth, kind)
            continued = False

            def ev(k, note, depth, kind="stage"):
                if not any(e[0] == k and e[1] == note for e in events):
                    events.append((k, note, depth, kind))

            if carried is not None:
                vals.regs["a"] = carried[1]
                events.extend(carried[2])  # the helper's own stages
                ev(start - 1, carried[0], _STAGE_DEPTH[carried[1][1]] if carried[1][1] in _STAGE_DEPTH else 1)
                k = start
            else:
                k = max(0, start - 6)  # constants feeding the segment offset (push 0x60; pop rcx ...)
            end = min(n, start + window)
            while k < end:
                off, (size, mn, op) = seq[k]
                cur = k
                if k < start and mn in TERMINATORS:
                    vals = _Values(self.is64)  # previous function: nothing carries over
                    k += 1
                    continue

                def load(mem, a, k=cur):
                    s, _, _, _, _, width, _ = mem
                    if s is not None:
                        if s != seg or a is None or a[0] != "const":
                            return None
                        if a[1] == lay["teb_peb"]:
                            ev(k, f"PEB ({seg}:[{a[1]:#x}])", 1)
                            return ("struct", "PEB", 0)
                        if a[1] == lay["teb_self"]:
                            ev(k, f"TEB ({seg}:[{a[1]:#x}])", 0)
                            return ("struct", "TEB", 0)
                        return None
                    if a is None or a[0] != "struct":
                        return None
                    kind, field = a[1], a[2]
                    if kind == "TEB":
                        if field == lay["teb_peb"]:
                            ev(k, "TEB->ProcessEnvironmentBlock", 1)
                            return ("struct", "PEB", 0)
                        if field == lay["teb_self"]:
                            return ("struct", "TEB", 0)
                    elif kind == "PEB":
                        if field == lay["ldr"]:
                            ev(k, "PEB->Ldr", 2)
                            return ("struct", "LDR", 0)
                        if field == lay["dbg"] and width == 1:
                            ev(k, "PEB->BeingDebugged", 1, "anti")
                        elif field == lay["gflag"]:
                            ev(k, "PEB->NtGlobalFlag", 1, "anti")
                    elif kind == "LDR" and field in lay["heads"]:
                        link, name = lay["heads"][field]
                        ev(k, f"Ldr.{name}.Flink: first module", 3, name)
                        return ("struct", "ENTRY", link)
                    elif kind == "ENTRY":
                        if field in lay["links"]:
                            ev(k, "Flink: next module", 4)
                            return ("struct", "ENTRY", field)
                        if field in lay["entry"]:
                            label = lay["entry"][field]
                            ev(k, label, 4)
                            if label.endswith("Buffer"):
                                return ("struct", "NAME", 0)
                            if label == "DllBase":
                                return ("struct", "DLLBASE", 0)
                            if label.endswith("Length"):
                                return ("struct", "NAMELEN", 0)
                    elif kind == "NAME":
                        ev(k, "reads the module name", 5)
                        return ("struct", "NAMEVAL", 0)
                    elif kind == "DLLBASE" and field == 0x3C:
                        ev(k, "module e_lfanew: export walk", 5)
                    return None

                # uses of values the walk produced (name compare / hash)
                parts = op.split(", ", 1)
                srcv = vals.get(parts[1]) if len(parts) > 1 and _canon(parts[1]) else None
                dstv = vals.get(parts[0]) if _canon(parts[0]) else None
                m = _mem(op) if "[" in op else None
                memv = vals.addr(m) if m and m[0] is None else None
                if mn in _STRING_LOADS and (vals.get("rsi") or ("",))[1:2] == ("NAME",):
                    ev(k, "reads the module name", 5)
                    vals.step(off, size, mn, op)
                    vals.regs["a"] = ("struct", "NAMEVAL", 0)
                    k += 1
                    continue
                if mn in ("cmp", "test") and (
                    (dstv and dstv[0] == "struct" and dstv[1] == "NAMEVAL") or (memv and memv[0] == "struct" and memv[1] == "NAME")
                ):
                    ev(k, "compares the module name", 5)
                elif mn == "or" and dstv and dstv[1:2] == ("NAMEVAL",) and parts[1].startswith("0x2020"):
                    ev(k, "case-folds the module name", 5)
                elif (
                    mn in ("add", "xor", "imul", "crc32", "sub")
                    and srcv
                    and srcv[1:2] == ("NAMEVAL",)
                    and _canon(parts[0]) != _canon(parts[1])
                ):
                    rot = next(
                        (
                            f"{seq[j][1][1]} {seq[j][1][2].rsplit(', ', 1)[-1]}"
                            for j in range(max(start, k - 3), min(n, k + 3))
                            if _NAME_HASH_RE.match(seq[j][1][1]) and ", " in seq[j][1][2]
                        ),
                        mn,
                    )
                    ev(k, f"hashes the module name ({rot})", 5)
                elif mn in ("rdgsbase", "rdfsbase") and _canon(op):
                    ev(k, f"TEB ({mn})", 0)
                    vals.regs[_canon(op)] = ("struct", "TEB", 0)
                    k += 1
                    continue
                vals.step(off, size, mn, op, load=load)
                if k > start and not any(v and v[0] == "struct" for v in (*vals.regs.values(), *vals.slots.values(), *vals.stack)):
                    break  # nothing PEB-related is held any more
                if mn == "ret":
                    ret_val = vals.regs.get("a")
                    if carried is None and ret_val and ret_val[0] == "struct" and k - start <= 6:
                        # tiny helper returning TEB/PEB: continue at each call site
                        for b in range(max(0, start - 3), start + 1):
                            for c in self._call_targets.get(seq[b][0], ()):
                                if c + 1 < n:
                                    note = f"call helper: returns {ret_val[1]}"
                                    jobs.append((c + 1, (note, ret_val, list(events))))
                                    continued = True
                    break
                k += 1
            if not events or continued:
                continue  # a helper's stages are reported with the walk at its call site
            walks.append(events)

        # one report per walk, deepest first; drop walks contained in another
        walks.sort(key=lambda ev_: (-max(e[2] for e in ev_ if e[3] != "anti"), ev_[0][0]))
        seen = []
        for events in walks:
            ks = {e[0] for e in events}
            if any(ks <= s for s in seen):
                continue
            seen.append(ks)
            stages = [e for e in events if e[3] != "anti"]
            anti = [e for e in events if e[3] == "anti"]
            depth = max((e[2] for e in stages), default=-1)
            block = [self.line(e[0], e[1]) if e[0] >= 0 else None for e in sorted(events)]
            block = [b for b in block if b]
            first = min(e[0] for e in events)
            anchor = seq[max(first, 0)][0]
            if anti:
                pre = [self.line(e[0], e[1]) for e in sorted(stages) if e[2] <= 1]
                for e in anti:
                    self.add(
                        "anti_debug_peb", MEDIUM, seq[e[0]][0], f"{self.line(e[0])[1]}  ; {e[1]}", pre + [self.line(e[0], e[1])]
                    )
            if depth >= 2:
                self.add("peb_walk", STRONG, anchor, self._walk_summary(stages), block)
            elif depth == 1:
                self.add("peb_access", WEAK, anchor, self.line(first)[1], block)
            elif depth == 0:
                self.add("teb_access", WEAK, anchor, self.line(first)[1], block)

    @staticmethod
    def _walk_summary(stages):
        """'InMemoryOrder walk -> BaseDllName.Buffer, DllBase -> Flink loop -> hashes the module name (ror 0xd)'"""
        lists = [_LIST_SHORT[e[3]] for e in stages if e[3] in _LIST_SHORT]
        parts = [f"{lists[0]} walk" if lists else "PEB->Ldr"]
        fields = [e[1] for e in stages if e[2] == 4 and not e[1].startswith("Flink")]
        if fields:
            parts.append(", ".join(dict.fromkeys(fields)))
        if any(e[1].startswith("Flink: next") for e in stages):
            parts.append("Flink to next module")
        uses = [e[1] for e in stages if e[2] == 5 and e[1] != "reads the module name"]
        if uses:
            parts.append(", ".join(dict.fromkeys(uses)))
        elif any(e[1] == "reads the module name" for e in stages):
            parts.append("reads the module name")
        return " -> ".join(parts)

    def _pe_loader(self, seq):
        """Manual PE mapping (reflective loader / sRDI / pe2shc / Donut-style).

        Groups, each cheap to see in the instruction stream:
          headers  e_lfanew read, then SizeOfImage/SizeOfHeaders/EntryPoint/ImageBase
          sections loop with 0x28 stride touching VirtualAddress/SizeOfRawData/PointerToRawData
          relocs   loop: movzx word, shr 0xc, and 0xfff (IMAGE_BASE_RELOCATION entries)
          imports  import directory + ordinal-flag test or 0x14-byte descriptor stride
        The MSVC CRT walks sections itself (_FindPESection), so headers/sections
        alone are weak; relocations or imports make it a loader.
        """
        n = len(seq)
        is64 = self.is64
        image_base = 0x30 if is64 else 0x34
        reloc_dir, import_dir = (0xB0, 0x90) if is64 else (0xA0, 0x80)
        header_fields = {0x06: "NumberOfSections", 0x14: "SizeOfOptionalHeader", 0x28: "AddressOfEntryPoint",
                         image_base: "ImageBase", 0x50: "SizeOfImage", 0x54: "SizeOfHeaders",
                         import_dir: "DataDirectory[1]: imports", reloc_dir: "DataDirectory[5]: relocations"}  # fmt: skip
        groups = {}  # group -> list of (seq index, note); first entry is the anchor
        index = {o: k for k, (o, _) in enumerate(seq)}

        for i in self._lfanew_reads:
            fields = {}
            for j in range(i + 1, min(n, i + 120)):
                for d in _disp(seq[j][1][2]):
                    if d in header_fields and d not in fields:
                        fields[d] = j
            if (
                fields.keys() & {0x50, 0x54, 0x28, image_base}
                and len(fields.keys() & {0x06, 0x14, 0x50, 0x54, 0x28, image_base}) >= 2
            ):
                groups.setdefault(
                    "headers",
                    [(i, "e_lfanew")] + [(j, header_fields[d]) for d, j in fields.items() if d not in (import_dir, reloc_dir)],
                )
            if import_dir in fields:
                groups.setdefault("_import_dir", [(i, "e_lfanew"), (fields[import_dir], header_fields[import_dir])])
            if reloc_dir in fields:
                groups.setdefault("_reloc_dir", [(i, "e_lfanew"), (fields[reloc_dir], header_fields[reloc_dir])])

        ordinal = None
        for k, (off, (_, mn, op)) in enumerate(seq):
            if (
                (mn == "bt" and op.endswith((", 0x3f", ", 0x1f")))
                or (mn == "test" and op.endswith(", 0x80000000"))
                or (mn == "movabs" and op.endswith(", 0x8000000000000000"))
            ):
                ordinal = k
                break

        for b_off, tgt in self._backedges:
            if b_off - tgt > 0x180 or tgt not in index or b_off not in index:
                continue
            ks = range(index[tgt], index[b_off] + 1)

            def pick(pred, note, ks=ks):
                return next(((k, note) for k in ks if pred(seq[k][1][1], seq[k][1][2])), None)

            disps = {d for k in ks for d in _disp(seq[k][1][2])}
            stride = pick(lambda m, o: (m in ("add", "imul") and o.endswith(", 0x28")) or (m == "lea" and "+ 0x28]" in o),
                          "next section header (0x28)")  # fmt: skip
            if stride and len(disps & {0x0C, 0x10, 0x14}) >= 2:
                sec = [stride] + [
                    pick(lambda m, o, d=d: d in _disp(o), note)
                    for d, note in ((0x0C, "VirtualAddress"), (0x10, "SizeOfRawData"), (0x14, "PointerToRawData"))
                ]
                groups.setdefault("sections", [s for s in sec if s])
            rel = [
                pick(lambda m, o: m == "movzx" and "word ptr [" in o, "relocation entry (word)"),
                pick(lambda m, o: m == "shr" and o.endswith(", 0xc"), "type = entry >> 12"),
                pick(lambda m, o: m == "and" and o.endswith(", 0xfff"), "offset = entry & 0xfff"),
            ]
            if all(rel):
                groups.setdefault("relocs", rel)
            step = pick(lambda m, o: m == "add" and o.endswith(", 0x14"), "next import descriptor (0x14)")
            if step and len(disps & {0x0C, 0x10}) == 2:
                groups.setdefault("_import_stride", [step])
        if "_import_dir" in groups and (ordinal is not None or "_import_stride" in groups):
            imp = list(groups["_import_dir"])
            if ordinal is not None:
                imp.append((ordinal, "ordinal flag test"))
            imp += groups.get("_import_stride", [])
            groups["imports"] = imp

        names = {"headers": ("pe_header_parse", WEAK), "sections": ("pe_section_map", WEAK),
                 "relocs": ("pe_reloc_fixup", MEDIUM), "imports": ("pe_import_resolve", MEDIUM)}  # fmt: skip
        found = [g for g in names if g in groups]
        for g in found:
            tag, w = names[g]
            if g == "imports" and len(found) == 1:
                w = WEAK  # the MSVC delay-load helper walks import descriptors on its own too
            lines = sorted(groups[g])
            self.add(tag, w, seq[groups[g][0][0]][0], g, [self.line(k, note) for k, note in lines])
        if len(found) >= 3 and ("relocs" in found or "imports" in found):
            lines = sorted({k: (k, note) for g in found for k, note in groups[g]}.values())
            anchor = min(seq[groups[g][0][0]][0] for g in found)
            self.add("reflective_pe_loader", STRONG, anchor, "+".join(found), [self.line(k, note) for k, note in lines])
        self._header_wipe(seq)

    def _kernel_token_steal(self, seq):
        """Kernel-mode token stealing: the current KTHREAD (gs:[0x188] x64 / fs:[0x124] x86, KPCR
        in kernel mode), a loop over the process list comparing a PID with 4 (System), then a
        store (the Token copy). User-mode code never reads these KPCR slots and walks EPROCESS."""
        n = len(seq)
        kpcr = "gs:[" if self.is64 else "fs:["
        slot = "0x188]" if self.is64 else "0x124]"
        for i, (off, (_, mn, op)) in enumerate(seq):
            if mn != "mov" or kpcr not in op or not op.endswith(slot):
                continue
            cmp4 = loop = store = None
            four = set()  # registers loaded with 4
            for k in range(i + 1, min(n, i + 40)):
                o_k, (_, km, ko) = seq[k]
                last = ko.rsplit(", ", 1)[-1]
                if km == "mov" and last in ("4", "0x4") and _canon(ko.split(", ")[0]):
                    four.add(_canon(ko.split(", ")[0]))
                elif km == "cmp" and (last in ("4", "0x4") or _canon(last) in four) and cmp4 is None:
                    cmp4 = k
                elif km in ("jne", "jnz") and cmp4 is not None and (_parse_int(ko) or o_k) < o_k and loop is None:
                    loop = k
                elif (
                    loop is not None
                    and km == "mov"
                    and ko.split(", ")[0].endswith("]")
                    and "ptr [" in ko
                    and _canon(ko.rsplit(", ", 1)[-1])
                ):
                    store = k
                    break
            if cmp4 is not None and loop is not None:
                block = [self.line(i, "current KTHREAD (KPCR)"), self.line(cmp4, "PID 4 (System)"), self.line(loop, "next process")]
                if store is not None:
                    block.append(self.line(store, "token copied"))
                self.add("kernel_token_steal", STRONG, off, f"{mn} {op}  ; walks the process list for PID 4", block)
                return

    def _header_wipe(self, seq):
        """SizeOfHeaders (read after e_lfanew) used as the length of a zero fill: rep stos with that
        count, or a memset(base, 0, SizeOfHeaders) call - the loader erasing the mapped image's
        headers so memory scanners find no MZ/PE."""
        n = len(seq)
        for i in self._lfanew_reads:
            for j in range(i + 1, min(n, i + 60)):
                m, o = seq[j][1][1:]
                if m != "mov" or 0x54 not in _disp(o) or ", " not in o or not _canon(o.split(", ")[0]):
                    continue
                size_reg = _canon(o.split(", ")[0])
                held = {size_reg}
                zeroed = set()
                for k in range(j + 1, min(n, j + 16)):
                    km, ko = seq[k][1][1:]
                    parts = ko.split(", ")
                    dst = _canon(parts[0]) if parts and parts[0] else None
                    if km == "mov" and len(parts) == 2 and _canon(parts[1]) in held and dst:
                        held.add(dst)
                    elif km in ("xor", "sub") and len(parts) == 2 and parts[0] == parts[1] and dst:
                        zeroed.add(dst)
                        held.discard(dst)
                    elif km == "mov" and len(parts) == 2 and parts[1] == "0" and dst:
                        zeroed.add(dst)
                    hit = None
                    if km.startswith("rep stos") and _canon("ecx") in held and _canon("eax") in zeroed:
                        hit = f"{km} with ecx = SizeOfHeaders, eax = 0"
                    elif km == "call" and self.is64 and _canon("r8") in held and _canon("edx") in zeroed:
                        hit = "call with r8 = SizeOfHeaders, edx = 0 (memset(base, 0, SizeOfHeaders))"
                    elif km == "push" and _canon(ko) in held and k + 2 < n:
                        nxt = [seq[x][1][1:] for x in (k + 1, k + 2)]
                        if nxt[0] == ("push", "0") and nxt[1][0] in ("push", "call"):
                            hit = "push SizeOfHeaders; push 0; ... call (memset(base, 0, SizeOfHeaders))"
                    if hit:
                        self.add("pe_header_wipe", MEDIUM, seq[j][0], hit,
                                 [self.line(i, "e_lfanew"), self.line(j, "SizeOfHeaders"), self.line(k, "zero fill")])  # fmt: skip
                        return
                break

    # ------------------------------------------------------------ decoders
    def _decoder_shape(self, seq, ks):
        """Structure of a decoder loop body, or None:
          in-place              op [P], key        (xor/add/sub/rol/ror/not/neg)
          load/transform/store  load r, [P]; op r, key...; store [Q], r  (lods/stos too)
        Rejected: stack-slot targets with no index (loop counters), add/sub 1
        (counters, histograms), zero padding, a pointer that never advances."""
        body = [(k, seq[k][1][1], seq[k][1][2]) for k in ks]

        def advance(reg):
            total = 0
            for _, m, o in body:
                parts = o.split(", ", 1)
                if _canon(parts[0]) != reg:
                    continue
                if m in ("inc", "dec"):
                    total += 1 if m == "inc" else -1
                elif m in ("add", "sub") and len(parts) == 2 and _parse_int(parts[1]) is not None:
                    total += _parse_int(parts[1]) * (1 if m == "add" else -1)
                elif m == "lea":
                    mm = _mem(parts[1]) if len(parts) == 2 else None
                    if mm and mm[1] == reg and mm[2] is None:
                        total += mm[4]
            if reg == "si":
                total += sum(_STRING_LOADS.get(m, 0) for _, m, _ in body)
            if reg == "di":
                total += sum(_STRING_STORES.get(m, 0) for _, m, _ in body)
            return total

        inplace = []
        for k, m, o in body:
            dst = o.split(", ", 1)[0]
            if m in _XFORMS and "[" in dst:
                mm = _mem(dst)
                src = o.split(", ", 1)[1] if ", " in o else None
                if mm is None or mm[0] is not None or mm[1] in (None, "rip"):
                    continue
                if m == "add" and src == "al" and mm[1] == "a" and mm[2] is None and mm[4] == 0:
                    continue  # 00 00 padding decodes as add byte ptr [rax], al
                inplace.append((k, m, src, mm))
        if inplace:
            k0, _, _, mm = inplace[0]
            same = [x for x in inplace if x[3][1:5] == mm[1:5]]
            if mm[1] in ("sp", "bp") and mm[2] is None:
                return None  # stack slot: a counter or local, not a buffer
            step = {r: advance(r) for r in (mm[1], mm[2]) if r}
            if not any(step.values()):
                return None
            xf = [(m, src, k) for k, m, src, _ in same]
            if any(m in ("add", "sub") and _parse_int(src or "") in (1, -1) for m, src, _ in xf):
                return None
            return {"kind": "in-place", "mem": mm, "width": mm[5] or 1, "xforms": xf, "anchor": k0, "step": step}

        load = None
        for k, m, o in body:
            if m in _STRING_LOADS:
                w = _STRING_LOADS[m]
                load = (k, "a", (None, "si", None, 1, 0, w, "[rsi]"), w)
                break
            if m in ("mov", "movzx", "movsx") and ", " in o:
                d, s = o.split(", ", 1)
                mm = _mem(s)
                if (
                    _canon(d)
                    and mm
                    and mm[0] is None
                    and mm[1] not in (None, "rip")
                    and not (mm[1] in ("sp", "bp") and mm[2] is None)
                ):
                    load = (k, _canon(d), mm, mm[5] or 1)
                    break
        if load is None:
            return None
        lk, reg, mm, width = load
        xf = []
        store = None
        for k, m, o in body:
            if k <= lk:
                continue
            parts = o.split(", ", 1)
            if m in _XFORMS and _canon(parts[0]) == reg:
                src = parts[1] if len(parts) > 1 else None
                if src and _canon(src) == reg:
                    return None
                xf.append((m, src, k))
            elif m in _STRING_STORES and reg == "a":
                store = k
                break
            elif m == "mov" and len(parts) == 2 and "[" in parts[0] and _canon(parts[1]) == reg:
                sm = _mem(parts[0])
                if sm and sm[0] is None and not (sm[1] in ("sp", "bp") and sm[2] is None):
                    store = k
                    break
            elif _canon(parts[0]) == reg and m in _WRITES_DST:
                return None  # value replaced before it was stored back
        if not xf or store is None:
            return None
        if any(m in ("add", "sub") and _parse_int(src or "") in (1, -1) for m, src, _ in xf):
            return None
        step = {r: advance(r) for r in (mm[1], mm[2]) if r}
        if not any(step.values()):
            return None
        return {"kind": "load/transform/store", "mem": mm, "width": width, "xforms": xf, "anchor": xf[0][2], "step": step,
                "load": lk, "store": store}  # fmt: skip

    def _decoders(self, seq):
        """Decoder loops: shape -> link to the blob -> exact range -> static decode."""
        n = len(seq)
        index = {o: k for k, (o, _) in enumerate(seq)}
        insn_at = dict(seq)
        # pops that receive a return address: call $+5 / jmp-call-pop / call over data
        call_ret = {}
        call_of = {}
        for t, calls in self._call_targets.items():
            if t in insn_at and insn_at[t][1] == "pop":
                off_c, (sz_c, _, _) = seq[calls[0]]
                call_ret[t] = off_c + sz_c
                call_of[t] = calls[0]
        # call $+4 (into its own last byte, ff c0-cf), then pop r: r = the return address
        for k, (off, (size, mn, op)) in enumerate(seq):
            if mn == "call" and _parse_int(op) == off + size - 1:
                hit = self._call4_pop(off + size - 1)
                if hit and hit[0] in insn_at:
                    call_ret.setdefault(hit[0], off + size)
                    call_of.setdefault(hit[0], k)
        # fnstenv [esp-0xc]; pop r: r = address of the last FPU instruction
        for k, (off, (_, mn, op)) in enumerate(seq):
            if mn in ("fnstenv", "fstenv") and "sp - 0xc]" in op:
                fpu = next(
                    (
                        seq[j][0]
                        for j in range(k - 1, max(-1, k - 8), -1)
                        if seq[j][1][1][0] == "f" and seq[j][1][1] not in ("fnstenv", "fstenv")
                    ),
                    None,
                )
                nxt = next((j for j in range(k + 1, min(n, k + 4)) if seq[j][1][1] == "pop"), None)
                if fpu is not None and nxt is not None:
                    call_ret.setdefault(seq[nxt][0], fpu)
                    call_of.setdefault(seq[nxt][0], k)
        # call $+5; mov r, [esp]
        stack_getpc = {}
        for k, (off, (size, mn, op)) in enumerate(seq[:-1]):
            if mn == "call" and _parse_int(op) == off + size:
                nm, no = seq[k + 1][1][1:]
                if nm == "mov" and no.endswith(("ptr [esp]", "ptr [rsp]")):
                    stack_getpc[seq[k + 1][0]] = off + size

        rc4 = self._rc4_ksa(seq, index)
        for b_off, tgt in self._backedges:
            if not 0 < b_off - tgt <= 0x60 or tgt not in index or b_off not in index:
                continue
            ks = list(range(index[tgt], index[b_off] + 1))
            if len(ks) > 16:
                continue
            shape = self._decoder_shape(seq, ks)
            if shape is None:
                continue
            # values at loop entry, from a straight-line window before it
            vals = _Values(self.is64)
            lo = max(0, ks[0] - 32)
            for j in range(lo, ks[0]):
                o, (sz, m, op) = seq[j]
                if m in TERMINATORS and m != "jmp":
                    vals = _Values(self.is64)
                    continue
                if o in stack_getpc:
                    vals.put(op.split(", ", 1)[0], ("ptr", stack_getpc[o]))
                    continue
                vals.step(o, sz, m, op, getpc=call_ret.get)
            mm = shape["mem"]
            start = vals.addr(mm)
            linked = start is not None and start[0] == "ptr" and 0 <= start[1] < self.size
            body_writes = {_canon(seq[k][1][2].split(", ", 1)[0]) for k in ks if seq[k][1][1] in _WRITES_DST}
            keys = []
            for m, src, k in shape["xforms"]:
                if src is None:
                    keys.append((m, 0))
                elif _parse_int(src) is not None:
                    keys.append((m, _parse_int(src)))
                elif _canon(src) and _canon(src) not in body_writes and (vals.get(src) or ("",))[0] == "const":
                    keys.append((m, vals.get(src)[1]))
                else:
                    keys.append((m, None))  # rolling or table key: cannot be decoded without stepping
            desc = self._xform_desc(shape, keys)
            loop_block = [self.line(k, "decode") if k == shape["anchor"] else self.line(k) for k in ks
                          if k in (shape["anchor"], shape.get("load"), shape.get("store")) or k == ks[-1]]  # fmt: skip
            if not linked:
                self.add("decoder_loop", WEAK, seq[shape["anchor"]][0], f"{desc} loop; pointer not tied to the blob", loop_block)
                continue
            start = start[1]
            nbytes = self._decoder_length(seq, ks, shape, vals)
            origin = self._pointer_origin(seq, lo, ks[0], mm, call_ret, call_of, stack_getpc)
            block = origin + loop_block
            region = {"start": start, "size": nbytes, "source": f"{desc} loop at {seq[shape['anchor']][0]:#x}",
                      "status": "linked", "result_type": None, "result": "", "decoded_entropy": None}  # fmt: skip
            end = min(self.size, start + nbytes) if nbytes else self.size
            enc = self.buf[start:end]
            if nbytes:
                region["entropy"] = round(_entropy(Counter(enc), len(enc)), 2) if enc else None
            if all(k is not None for _, k in keys) and enc and not getattr(self, "nested", False):
                dec = _apply_xforms(enc[:DECODE_VERIFY_MAX] if not nbytes else enc, shape["width"], keys)
                verdict = self._classify_decoded(dec, enc)
                if verdict:
                    rtype, rtext, rsize = verdict
                    region.update({"status": "verified", "result_type": rtype, "result": rtext,
                                   "decoded_entropy": round(_entropy(Counter(dec), len(dec)), 2) if dec else None})  # fmt: skip
                    if rsize and not nbytes:
                        region["size"] = nbytes = rsize
                    # keep the decoded bytes when their extent is exact: a PE sized by its
                    # headers, or code whose length the loop itself proves
                    if rtype == "pe" and rsize:
                        if len(dec) < rsize and start + rsize <= len(self.buf):
                            dec = _apply_xforms(self.buf[start : start + rsize], shape["width"], keys)
                        if len(dec) >= rsize:
                            region["_data"] = bytes(dec[:rsize])
                    elif rtype == "code" and nbytes and len(dec) == nbytes:
                        region["_data"] = bytes(dec)
            elif not all(k is not None for _, k in keys):
                region["result"] = "rolling/table key: not decodable without stepping the loop"
            rng = f"{start:#x}-{start + nbytes:#x} ({nbytes} bytes)" if nbytes else f"{start:#x} (length not provable statically)"
            self.add("decoder_stub", STRONG, seq[shape["anchor"]][0], f"{desc}: decodes {rng}", block)
            if region["status"] == "verified":
                self.add("decoded_payload", STRONG, seq[shape["anchor"]][0], f"{rng} decodes to {region['result']}", block)
            if nbytes and region.get("entropy") is not None and region["status"] != "verified":
                if region["entropy"] >= min(7.0, 0.9 * math.log2(max(nbytes, 2))):
                    self.add("encoded_payload", WEAK, start, f"{rng}: entropy {region['entropy']}")
            if rc4 is not None:
                self.add("rc4_ksa", MEDIUM, rc4[0], "256-entry S-box init + swap loop", rc4[1])
            region["start"] = start
            self.regions.append(region)

    @staticmethod
    def _xform_desc(shape, keys):
        size = {1: "byte", 2: "word", 4: "dword", 8: "qword"}.get(shape["width"], f"{shape['width']}-byte")
        parts = []
        for (m, src, _), (_, key) in zip(shape["xforms"], keys):
            if m in ("not", "neg"):
                parts.append(m)
            elif key is None:
                parts.append(f"{m} rolling key ({src})")
            else:
                parts.append(f"{m} {key & ((1 << (8 * shape['width'])) - 1):#x}")
        return f"{shape['kind']} {size} {', '.join(parts)}"

    def _decoder_length(self, seq, ks, shape, vals):
        """Bytes the loop processes, when its bound is a constant: a counter
        (loop / dec+jnz / sub 1+jnz) or a compare of the index or pointer."""
        mm = shape["mem"]
        step = shape["step"]
        width = shape["width"]
        _, m, o = seq[ks[-1]][1]
        moved = [r for r in step if step[r]]
        per_iter = abs(step[moved[0]]) * (mm[3] if moved[0] == mm[2] else 1) if moved else width
        iters = None
        if m.startswith("loop"):
            c = vals.get("rcx")
            iters = c[1] if c and c[0] == "const" else None
        else:
            flag = next((k for k in reversed(ks[:-1]) if seq[k][1][1] in ("cmp", "test", "dec", "sub", "inc", "add")), None)
            if flag is None:
                return None
            fm, fo = seq[flag][1][1:]
            parts = fo.split(", ", 1)
            r = _canon(parts[0])
            if fm in ("dec", "sub") and r not in step:
                if fm == "dec" or (len(parts) == 2 and _parse_int(parts[1]) == 1):
                    c = vals.get(parts[0])
                    iters = c[1] if c and c[0] == "const" else None
            elif fm == "cmp" and len(parts) == 2 and r in step and step[r]:
                cur = vals.get(parts[0])
                bound = _parse_int(parts[1])
                other = vals.get(parts[1]) if _canon(parts[1]) else None
                if bound is None and other is not None and other[0] == "const":
                    bound = other[1]
                if cur and cur[0] == "const" and bound is not None:
                    iters = (bound - cur[1]) // step[r] if step[r] else None
                elif cur and cur[0] == "ptr" and other and other[0] == "ptr":
                    return other[1] - cur[1] if other[1] > cur[1] else None
        if iters is None or iters <= 0 or iters > 1 << 26:
            return None
        return iters * per_iter

    def _pointer_origin(self, seq, lo, hi, mm, call_ret, call_of, stack_getpc):
        """Instructions that set the decoder's pointer: GetPC / RIP and adjustments."""
        regs = {r for r in (mm[1], mm[2]) if r}
        out = []
        for j in range(hi - 1, lo - 1, -1):
            o, (_, m, op) = seq[j]
            dst = _canon(op.split(", ", 1)[0]) if op else None
            if dst not in regs:
                continue
            if m == "pop" and o in call_ret:
                c = call_of.get(o)
                if c is not None and c != j:
                    out.append(self.line(c, "GetPC" if seq[c][1][1] == "call" else "GetPC (FPU environment)"))
                out.append(self.line(j, f"pointer = {call_ret[o]:#x}"))
                break
            if o in stack_getpc:
                out.append(self.line(j - 1, "GetPC"))
                out.append(self.line(j, f"pointer = {stack_getpc[o]:#x}"))
                break
            if m == "lea" and "[rip" in op:
                out.append(self.line(j, "pointer from RIP"))
                break
            out.append(self.line(j, "pointer setup"))
            if m in ("mov", "lea") and len(op.split(", ", 1)) == 2:
                src = op.split(", ", 1)[1]
                nr = _canon(src) or (_mem(src) or (None, None))[1]
                if nr and nr != "rip":
                    regs = {nr}
            if len(out) >= 4:
                break
        return out[::-1]

    def _classify_decoded(self, dec, enc):
        """What a statically decoded region is: a PE (exact size from its
        headers), code (coherent island, one level deep), text or plain data."""
        if b"PE\x00\x00" in dec[:0x400]:
            pes = find_embedded_pes(dec, min(len(dec), 0x1000), 1)
            if pes and int(pes[0]["offset"], 16) == 0:
                nt = int(pes[0]["nt_offset"], 16)
                size = _pe_raw_size(dec, nt)
                kind = f"{pes[0]['arch']} {'DLL' if pes[0]['dll'] else 'EXE'}"
                return "pe", f"a PE image ({kind}, {size:#x} bytes on disk)" if size else f"a PE image ({kind})", size
        head = dec[:8192]
        for mode in (CS_MODE_64,) if self.is64 else (CS_MODE_32,):
            d = _Descent(head, mode, 1500)
            d.run(_seeds(head, d.md, 8))
            r = _evaluate_island(head, d, self.is64, None, {"context": 0}, nested=True)
            if r["structure"]["coherent"]:
                tags = [t for t in r["tags"] if t not in UNSCORED and r["_weights"].get(t, 0) >= MEDIUM]
                return "code", f"{'x64' if self.is64 else 'x86'} code" + (f" ({', '.join(tags[:5])})" if tags else ""), None
        st = byte_stats(head)
        if st["printable_ratio"] >= 0.85:
            preview = head[:48].decode("latin-1").encode("unicode_escape").decode()
            return "text", f"text: '{preview}'", None
        before = _entropy(Counter(enc[: len(head)]), min(len(enc), len(head)))
        if before - st["entropy"] >= 1.5 and st["entropy"] <= 6.0:
            return "lowentropy", f"structured data (entropy {before:.2f} -> {st['entropy']:.2f})", None
        return None

    def _rc4_ksa(self, seq, index):
        """RC4 key schedule: a loop storing the index into a 256-entry table."""
        for b_off, tgt in self._backedges:
            if tgt not in index or b_off not in index or not 0 < b_off - tgt <= 0x40:
                continue
            ks = range(index[tgt], index[b_off] + 1)
            ops = [seq[k][1][1:] for k in ks]
            store = next((k for k in ks if seq[k][1][1] == "mov" and seq[k][1][2].startswith("byte ptr [")
                          and _canon(seq[k][1][2].rsplit(", ", 1)[-1]) in (_mem(seq[k][1][2]) or (0, 0, 0))[1:3]), None)  # fmt: skip
            if store is not None and any(m == "cmp" and o.endswith((", 0x100", ", 0xff")) for m, o in ops):
                return seq[store][0], [self.line(store, "S[i] = i"), self.line(ks[-1], "256 entries")]
        return None

    def _injected_stub(self, seq):
        """Injector-built stub: loads absolute API addresses and calls them."""
        if not self.ptr_calls or self.size > 1024 or self.jit_ptrs >= 8:
            return
        block = []
        for k, v in self.ptr_calls[:6]:
            load = next((j for j in range(k - 1, max(-1, k - 5), -1) if _parse_int(seq[j][1][2].split(", ")[-1]) == v), None)
            if load is not None:
                block.append(self.line(load, "absolute address in the target"))
            block.append(self.line(k, "call it"))
        w = STRONG if len(self.ptr_calls) >= 2 else MEDIUM
        self.add(
            "injected_call_stub",
            w,
            seq[self.ptr_calls[0][0]][0],
            f"{len(self.ptr_calls)} call(s) through absolute addresses",
            block,
        )

    def _link_resolvers(self):
        """Generic hash loops and name-chunk compares are common in compiled code;
        they are high only when the same code also resolves modules or APIs."""
        resolver = any(k in self.hits for k in ("peb_walk", "export_table_parse", "known_api_hash"))
        if not resolver and self._hash_kinds and "ror13" not in self._hash_kinds:
            self.demote("api_hash_loop", WEAK)
        if "peb_walk" not in self.hits and "export_table_parse" not in self.hits:
            self.demote("module_name_compare", MEDIUM)

    def _flush_stack(self, run, reverse):
        if len(run) >= 2:
            parts = [s for _, s in run]
            string = "".join(reversed(parts) if reverse else parts)
            if len(string) >= 6:
                self.stack_strings.append(string[:64])
                low = string.lower()
                if low in _API_NAMES:
                    self.apis.add(_API_NAMES[low])
                if any(h in low for h in API_STRING_HINTS):
                    self.add("stack_string_api", MEDIUM, run[0][0], f"'{string[:64]}'")
                else:
                    self.add("stack_string", WEAK, run[0][0], f"'{string[:64]}'")
        run.clear()

    def _loops(self, seq, insns):
        """Name-hash loops: small backward branches that walk a name byte by byte.
        ror13 is reported as high on its own; the other algorithms (djb2, FNV,
        sdbm, CRC32...) are common in compiled hash tables (MSVC std::hash is
        FNV-1a), so they are high only when a resolver ties them in, and low
        otherwise (see _link_resolvers)."""
        index = {o: k for k, (o, _) in enumerate(seq)}
        self._hash_kinds = set()

        def hash_hit(body_ks, pred, text, ror13=False):
            k_at = next((k for k in body_ks if pred(seq[k][1][1], seq[k][1][2])), body_ks[0])
            load = next((k for k in body_ks if seq[k][1][1] in ("lodsb", "lodsw") or "byte ptr [" in seq[k][1][2]), None)
            block = [self.line(k_at, text.split("  ; ")[-1])] + ([self.line(load, "reads the name")] if load is not None else [])
            block.append(self.line(body_ks[-1], "next character"))
            self.add("api_hash_loop", STRONG, seq[k_at][0], text, block)
            self._hash_kinds.add("ror13" if ror13 else "generic")

        for b_off, tgt in self._backedges:
            if b_off - tgt > 0x40 or tgt not in index or b_off not in index:
                continue
            body_ks = list(range(index[tgt], index[b_off] + 1))
            mns = [seq[k][1][1] for k in body_ks]
            ops = [seq[k][1][1:] for k in body_ks]
            byte_load = any(m == "lodsb" or (m in ("movzx", "movsx", "mov") and "byte ptr [" in o) for m, o in ops)
            # a name-hash loop always walks the name: its pointer must advance
            name_ptrs = set()
            for m, o in ops:
                if "byte ptr [" in o or (m == "crc32" and "[" in o):
                    inner = o.split("[", 1)[1].split("]", 1)[0]
                    name_ptrs.update(c for c in (_canon(x) for x in re.split(r"[\s+*-]+", inner)) if c)
            walks = (
                "lodsb" in mns
                or "lodsw" in mns
                or any(m in ("inc", "dec", "add", "sub", "lea") and _canon(o.split(",")[0]) in name_ptrs for m, o in ops)
            )
            byte_load = byte_load and walks
            crc_byte = any(m == "crc32" and (o.endswith("l") or "byte ptr [" in o) for m, o in ops)
            if crc_byte and (byte_load or (walks and any(m == "crc32" and "[" in o for m, o in ops))):
                hash_hit(body_ks, lambda m, o: m == "crc32", "crc32 instruction name hash loop")
                continue
            if not byte_load:
                continue
            rot = next(((m, o) for m, o in ops if m in ("ror", "rol") and re.search(r", (0x[0-9a-f]+|\d+)$", o)), None)
            mul = next((o.rsplit(", ", 1)[-1] for m, o in ops if m == "imul" and o.endswith((", 0x21", ", 0x83", ", 0x1003f"))), None)  # fmt: skip
            if rot:
                amount = int(rot[1].rsplit(", ", 1)[-1], 0)
                ror13 = (rot[0] == "ror" and amount == 13) or (rot[0] == "rol" and amount == 19)
                hash_hit(body_ks, lambda m, o: (m, o) == rot, f"{rot[0]} {rot[1]}  ; ror/rol-{amount} name hash loop", ror13)
            elif any(m == "shl" and o.endswith(", 5") for m, o in ops) and "add" in mns:
                hash_hit(body_ks, lambda m, o: m == "shl" and o.endswith(", 5"), "shl 5 / add  ; djb2 name hash loop")
            elif any(m == "imul" and "0x1000193" in o for m, o in ops):
                hash_hit(body_ks, lambda m, o: m == "imul" and "0x1000193" in o, "imul 0x1000193  ; FNV name hash loop")
            elif mul and "add" in mns:
                algo = {"0x21": "djb2 (*33)", "0x83": "BKDR (*131)", "0x1003f": "sdbm (*65599)"}[mul]
                hash_hit(body_ks, lambda m, o: m == "imul" and o.endswith(", " + mul), f"imul {mul}  ; {algo} name hash loop")
            else:
                shl = [o for m, o in ops if m == "shl"]
                if {"sub", "add"} <= set(mns) and any(o.endswith(", 6") for o in shl) and any(o.endswith(", 0x10") for o in shl):
                    hash_hit(body_ks, lambda m, o: m == "shl", "shl 6 / shl 16 / sub  ; sdbm name hash loop")
        # software CRC32 (reflected polynomial) inside or under a byte loop
        crc_at = next((o for o, (_, m, op) in seq if "0xedb88320" in op and m in ("xor", "mov", "cmovne", "cmove")), None)
        if crc_at is not None:
            loops = [(t, b) for b, t in self._backedges if t <= b and t in index and b in index]
            byte_loops = [
                (t, b)
                for t, b in loops
                if any(
                    m == "lodsb" or (m in ("movzx", "movsx", "mov") and "byte ptr [" in op)
                    for _, (_, m, op) in seq[index[t] : index[b] + 1]
                )
            ]
            if any(t <= crc_at <= b for t, b in byte_loops):
                self.add("api_hash_loop", STRONG, crc_at, "xor 0xedb88320  ; software CRC32 name hash loop")
                self._hash_kinds.add("generic")
        # ARX ciphers by their rotation amounts (as left rotations of 32-bit words)
        rots = {}
        for o, (_, m, op) in seq:
            if m in ("rol", "ror") and ", " in op and op.split(", ")[0] in _REG32:
                k = _parse_int(op.rsplit(", ", 1)[1])
                if k:
                    rots.setdefault(k if m == "rol" else (32 - k) % 32, o)
        if {5, 7, 8, 13, 16} <= set(rots):
            self.add("chaskey_cipher", MEDIUM, rots[13], "rotations 5/7/8/13/16")
        for b_off, tgt in self._backedges:
            if (
                0 < b_off - tgt <= 0x60
                and any(tgt <= o <= b_off and r == 24 for r, o in rots.items())
                and any(tgt <= o <= b_off and r == 3 for r, o in rots.items())
            ):
                self.add("speck_hash", MEDIUM, tgt, "ror 8 / rol 3 round in a loop")
                break


def _local_boundaries(md, buf, p, back=96):
    """Instruction boundaries shortly before p, found by a short linear sweep
    that re-synchronises on p (x86 self-synchronises within a few insns)."""
    for lead in range(back + 32, back + 48):
        start = max(0, p - lead)
        offs = []
        last = start
        for addr, size, _, _ in md.disasm_lite(buf[start:p], start):
            offs.append(addr)
            last = addr + size
        if last == p:
            offs = [o for o in offs if o >= p - back]
            if not offs:
                return []
            # farthest, middle and nearest boundary
            return list(dict.fromkeys([offs[0], offs[len(offs) // 2], offs[-1]]))
        if start == 0:
            break
    return []


def _hash_anchors(buf, limit=16):
    """Offsets of known API hash constants anywhere in buf (any alignment).
    Set intersection over the four 4-byte phases runs at C speed."""
    found = []
    for phase in range(4):
        n = (len(buf) - phase) // 4
        if n <= 0:
            continue
        hits = set(struct.unpack_from(f"<{n}I", buf, phase)) & _KNOWN_HASH_SET
        for v in hits:
            pos = buf.find(v.to_bytes(4, "little"))
            if pos > 0:
                found.append(pos)
    return sorted(found)[:limit]


def _seeds(buf, md, max_seeds, extra=()):
    seeds = list(extra) + [0]
    anchors = []
    for pat in SEED_PATTERNS:
        for m in pat.finditer(buf):
            seeds.append(m.start())
            anchors.append(m.start())
            if len(anchors) > 64:
                break
    for pos in _hash_anchors(buf):
        anchors.append(pos - 1)  # push imm32 / mov r, imm32 opcode byte(s) precede it
    for p in sorted(set(anchors))[:24]:
        seeds.extend(_local_boundaries(md, buf, p))
    for m in PAD_RUN_RE.finditer(buf):
        if m.end() < len(buf) - 8:
            seeds.append(m.end())
    return list(dict.fromkeys(s for s in seeds if 0 <= s < len(buf)))[:max_seeds]


def _is_trampoline(d):
    """Hook-style stub: jmp out of the buffer, push imm/ret, or mov r, imm/jmp r."""
    for _, mn, op in d.insns.values():
        if mn == "jmp":
            tgt = _parse_int(op)
            if tgt is not None and not 0 <= tgt < d.n:
                return True
    seq = [v for _, v in sorted(d.insns.items())]
    for (_, m1, o1), (_, m2, o2) in zip(seq, seq[1:]):
        if m1 == "push" and o1.startswith("0x") and m2 == "ret":
            return True
        if m1 in ("mov", "movabs") and m2 == "jmp" and ", 0x" in o1 and o2 == o1.split(",")[0]:
            return True
    return False


def _evaluate_island(buf, d, is64, va, opts, nested=False):
    reached = sum(sz for sz, _, _ in d.insns.values())
    ninsn = len(d.insns)
    misaligned = d.misaligned_targets()
    bad_ratio = d.bad_paths / d.paths if d.paths else 1.0
    oob_ratio = len(d.oob) / d.branches if d.branches else 0.0
    core = mem_alu = incdec = 0
    for sz, m, o in d.insns.values():
        if not is64 and sz == 1 and (m, o) in _REX_AS_X86:
            incdec += 1
        if m in CORE_MNEMONICS or m in COND_BRANCHES:
            core += 1
        if m in _MEM_ALU and o.startswith(("byte ptr", "word ptr", "dword ptr", "qword ptr")):
            mem_alu += 1
    core_ratio = core / ninsn if ninsn else 0.0
    mem_alu_ratio = mem_alu / ninsn if ninsn else 0.0

    ind = _Indicators(is64, va, len(buf), buf)
    ind.nested = nested  # decoded output being checked: no further decoding
    ind.limit = d.far_limit
    ind._backedges = d.backedges
    if ninsn:
        ind.scan(d.insns)

    coherent = (
        ninsn >= 12
        and reached >= 32
        and bad_ratio <= 0.34
        and d.rare <= max(1, ninsn // 200)
        and oob_ratio <= 0.5
        and misaligned <= max(1, ninsn // 100)
        and core_ratio >= 0.45
        and mem_alu_ratio <= 0.3
    )
    # small but entirely clean islands (e.g. syscall stubs) are fine when they
    # also carry a strong indicator
    clean_small = ninsn >= 3 and d.bad_paths == 0 and d.rare == 0 and not misaligned
    # origin fingerprints: JIT output and compiled runtimes
    jit = ind.jit_ptrs >= JIT_MIN_POINTERS and ind.jit_ptrs >= ninsn * JIT_POINTER_RATIO
    compiled = sum(ind.runtime.values()) >= 2
    if jit:
        ind.add("jit_code", INFO, 0, f"{ind.jit_ptrs} absolute pointers into the process loaded in {ninsn} instructions")
    if compiled:
        ind.add("compiled_runtime", INFO, 0, ", ".join(f"{k} x{v}" for k, v in ind.runtime.most_common()))

    scored = {k: w for k, w in ind.hits.items() if k not in UNSCORED and w > INFO}
    strong = [k for k, w in scored.items() if w >= STRONG]
    strong_groups = {INDICATORS[k][0] for k in strong}
    has_medium = any(w >= MEDIUM for w in scored.values())
    score = sum(scored.values())
    linked = bool(LINKED & set(strong))
    trampoline = (
        len(buf) <= 256 and ninsn < 12 and not strong and d.bad_paths == 0 and d.rare == 0
        and "injected_call_stub" not in scored and _is_trampoline(d)
    )  # fmt: skip
    # a few clean instructions only confirm a large blob with more than one kind of evidence
    small_ok = len(buf) <= 1024 or reached >= 0.25 * len(buf) or len(strong_groups) >= 2

    if trampoline:
        verdict = "trampoline"
    elif ("decoder_stub" in strong or "decoded_payload" in strong) and ninsn >= 6:
        verdict = "shellcode"  # decoders run straight into encoded bytes
    elif strong and (coherent or (clean_small and small_ok)):
        verdict = "shellcode"
    elif strong and clean_small:
        verdict = "likely"
    elif len(strong) >= 2:
        verdict = "likely"
    elif not coherent:
        verdict = "likely" if clean_small and has_medium and len(buf) <= 1024 else "data"
    elif has_medium or score >= 4:
        verdict = "likely"
    else:
        verdict = "code"
    # JIT output can carry anything (it is code built at run time); only linked
    # evidence makes it shellcode. A compiled runtime only stops weak/medium
    # traits adding up to 'likely'.
    if jit and not linked and verdict in ("shellcode", "likely"):
        verdict = "code"
    elif compiled and not strong and verdict == "likely":
        verdict = "code"

    # position independence: coherent code with no absolute memory operands and no
    # pointers into its own region. Strong on x86 (compiled code is full of absolute
    # refs); on x64 RIP-relative addressing makes most compiled code PIC as well.
    if (coherent or clean_small) and ninsn >= 8 and ind.abs_refs == 0 and ind.ext_refs == 0 and ind.va_hits == 0:
        pic = "yes"
    elif ind.abs_refs >= 2 or ind.ext_refs >= 2 or ind.va_hits >= 2:
        pic = "no"
    else:
        pic = "unknown"
    return {
        "arch": "x64" if is64 else "x86",
        "pic": pic,
        "verdict": verdict,
        "score": score,
        "_far": d.far if verdict in ("shellcode", "likely") and not d.bad_paths else [],
        "tags": sorted(ind.hits, key=lambda k: (-ind.hits[k], k)),
        "_weights": dict(ind.hits),
        "_ind": ind,
        "regions": ind.regions,
        "apis": sorted(ind.apis),
        "sockaddrs": ind.sockaddrs,
        "evidence": sorted(ind.evidence, key=lambda e: int(e["offset"], 16)),
        "stack_strings": ind.stack_strings[:10],
        "structure": {
            "coherent": coherent,
            "instructions": ninsn,
            "reached_bytes": reached,
            "coverage": round(reached / len(buf), 3) if buf else 0.0,
            "paths": d.paths,
            "bad_path_ratio": round(bad_ratio, 3),
            "rare_insns": d.rare,
            "branches": d.branches,
            "oob_branches": len(d.oob),
            "misaligned_targets": misaligned,
            "abs_refs": ind.abs_refs,
            "external_rip_refs": ind.ext_refs,
            "core_mnemonic_ratio": round(core_ratio, 3),
            "mem_alu_ratio": round(mem_alu_ratio, 3),
            # share of 1-byte inc/dec: high when x64 code (REX prefixes) is read as x86
            "rex_as_incdec": round(incdec / ninsn, 2) if ninsn and incdec / ninsn >= 0.08 else 0.0,
        },
    }


def _rank(r):
    return (VERDICT_RANK[r["verdict"]], r["score"], -r["structure"].get("rex_as_incdec", 0.0), r["structure"]["reached_bytes"])


def _analyse_mode(buf, mode, va, max_insns, max_seeds, opts, extra_seeds=(), extent=None):
    """Each seed is descended as its own island. Returns (best island, all
    islands worth reporting, far branch targets)."""
    is64 = mode == CS_MODE_64
    md = Cs(CS_ARCH_X86, mode)
    best = None
    good = []
    far = []
    covered = set()  # instructions belonging to coherent islands already seen
    budget = max_insns * 2
    for seed in _seeds(buf, md, max_seeds, extra_seeds):
        if seed in covered or budget <= 0:
            continue
        d = _Descent(buf, mode, min(max_insns, budget), extent)
        d.run([seed])
        budget -= len(d.insns)
        r = _evaluate_island(buf, d, is64, va, opts)
        r["entry"] = seed
        far.extend(r.pop("_far"))
        if r["structure"]["coherent"]:
            covered.update(d.insns)
        if r["verdict"] in ("shellcode", "likely"):
            good.append(r)
        if best is None or _rank(r) > _rank(best):
            best = r
        if best["verdict"] == "shellcode" and best["score"] >= 2 * STRONG:
            break
    # disassembly context only for islands that are reported
    for r in good + ([best] if best not in good else []):
        r["_ind"].attach_context(opts["context"])
        r["evidence"] = sorted(r["_ind"].evidence, key=lambda e: int(e["offset"], 16))
        r["stack_strings"] = r["_ind"].stack_strings[:10]
    return best, good, far


def _u16(b, o):
    return int.from_bytes(b[o : o + 2], "little")


def _u32(b, o):
    return int.from_bytes(b[o : o + 4], "little")


def find_embedded_pes(data, limit, max_hits=MAX_EMBEDDED_PE):
    """Locate PE images inside a buffer by their NT headers ('PE\\0\\0' +
    machine + optional-header magic), so images whose MZ was wiped still count."""
    hits = []
    view = memoryview(data)[:limit]
    blob = bytes(view)
    pos = blob.find(b"PE\x00\x00")
    checked = 0
    while pos != -1 and len(hits) < max_hits and checked < 4096:
        checked += 1
        if pos + 0x18 + 0x40 <= len(blob):
            machine = _u16(blob, pos + 4)
            opt_size = _u16(blob, pos + 0x14)
            magic = _u16(blob, pos + 0x18)
            if machine in (0x14C, 0x8664, 0xAA64) and (magic, opt_size) in ((0x10B, 0xE0), (0x20B, 0xF0)):
                dos = None
                for back in range(0x40, min(pos, 0x1000) + 1, 4):
                    if _u32(blob, pos - back + 0x3C) == back:
                        dos = pos - back
                        break
                start = dos if dos is not None else pos
                hits.append(
                    {
                        "offset": hex(start),
                        "nt_offset": hex(pos),
                        "mz": dos is not None and blob[dos : dos + 2] == b"MZ",
                        "arch": {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}[machine],
                        "dll": bool(_u16(blob, pos + 0x16) & 0x2000),
                        "size_of_image": hex(_u32(blob, pos + 0x18 + 0x38)),
                    }
                )
        pos = blob.find(b"PE\x00\x00", pos + 4)
    return hits


def _executable_header(buf, size):
    """Images whose DOS header runs: pe2shc ('MZER' + call stub) and reflective
    DLL bootstraps such as Cobalt Strike / Metasploit ('MZAR...lea rbx,[rip-x];
    add rbx, off; call rbx' or 'MZ; call $+5; pop ebx; add ebx, off; call ebx').
    A tiny register tracker resolves the target. Returns (mode, offset, target)."""
    for mode in (CS_MODE_32, CS_MODE_64):
        md = Cs(CS_ARCH_X86, mode)
        regs = {}
        pending_pop = None
        for k, (addr, sz, mn, op) in enumerate(md.disasm_lite(buf[:128], 0)):
            if k >= 24 or mn in RARE_MNEMONICS or (mn == "add" and op.endswith("], al")):
                break
            nxt = addr + sz
            parts = op.split(", ")
            dst = _canon(parts[0]) if parts else None
            src = parts[1] if len(parts) > 1 else ""
            if mn in ("call", "jmp"):
                tgt = _parse_int(op)
                if tgt is None and _canon(op) in regs:
                    tgt = regs[_canon(op)]
                if tgt == nxt and mn == "call":
                    pending_pop = nxt  # call $+5: the following pop receives this address
                    continue
                if tgt is not None and 0x40 <= tgt < size:
                    return mode, addr, tgt
                break
            if mn == "pop" and dst and pending_pop is not None:
                regs[dst], pending_pop = pending_pop, None
            elif mn == "lea" and dst and "[rip" in src:
                d = _parse_int(
                    src.split("rip", 1)[1].strip(" +]").replace(" ", "").replace("-", "-0x").replace("-0x0x", "-0x") or "0"
                )
                regs[dst] = nxt + (d or 0)
            elif mn == "mov" and dst and _canon(src) in regs:
                regs[dst] = regs[_canon(src)]
            elif mn in ("add", "sub") and dst in regs and _parse_int(src) is not None:
                regs[dst] += _parse_int(src) if mn == "add" else -_parse_int(src)
    return None


def _cap_evidence(evidence):
    """Sorted by offset, at most MAX_EVIDENCE_PER_INDICATOR per indicator, so a
    noisy indicator (dozens of hash constants) can never crowd out another."""
    out, seen = [], {}
    for e in sorted(evidence, key=lambda e: int(e["offset"], 16)):
        k = seen.get(e["indicator"], 0)
        if k < MAX_EVIDENCE_PER_INDICATOR and not any(x["indicator"] == e["indicator"] and x["offset"] == e["offset"] for x in out):
            out.append(e)
            seen[e["indicator"]] = k + 1
    return out


def _rebase(r, base):
    r.pop("_ind", None)
    if isinstance(r["entry"], int):
        r["entry"] = hex(r["entry"] + base)
        for e in r["evidence"]:
            e.pop("block", None)
            e["offset"] = hex(int(e["offset"], 16) + base)
            for line in e.get("context", ()):
                if line[0]:
                    line[0] = hex(int(line[0], 16) + base)
        regions = []
        for g in r.get("regions", ()):
            g = dict(g)
            g["start"] = g["start"] + base
            regions.append(g)
        r["regions"] = regions
    return r


def _format_regions(regions):
    """Protected/decoded regions for the report, one per start offset (verified first)."""
    rank = {"verified": 0, "structural": 1, "linked": 2}
    out = {}
    for g in sorted(regions, key=lambda g: rank.get(g["status"], 3)):
        out.setdefault(g["start"], g)
    rows = []
    for start, g in sorted(out.items()):
        size = g.get("size")
        row = {k: v for k, v in g.items() if not k.startswith("_")}
        rows.append({**row, "start": hex(start), "end": hex(start + size) if size else None})
    return rows


# Import hint/name entries (WORD hint + ASCII name + NUL, padded to even): runs of
# these exist only in mapped/loaded PE images, never in shellcode code paths
_HINT_ENTRY = rb"[\x00-\xff][\x00-\x1f][A-Za-z_][A-Za-z0-9_]{3,62}\x00\x00?"
_HINT_NAME_RE = re.compile(rb"(?:" + _HINT_ENTRY + rb"){6,}")
_HINT_ENTRY_RE = re.compile(_HINT_ENTRY)
# ntdll syscall stub (x64): mov r10, rcx; mov eax, SSN
_NTDLL_STUB_RE = re.compile(rb"\x4c\x8b\xd1\xb8(..)\x00\x00", re.S)


def find_ntdll_copy(buf, min_stubs=16):
    """(start, end, count) of a run of ntdll syscall stubs 0x20 apart with
    rising SSNs (a clean ntdll .text copied in for unhooking), or None."""
    best = None
    run = []
    for m in _NTDLL_STUB_RE.finditer(buf):
        pos, ssn = m.start(), int.from_bytes(m.group(1), "little")
        if run and pos - run[-1][0] == 0x20 and ssn > run[-1][1]:
            run.append((pos, ssn))
        else:
            if len(run) >= min_stubs and (best is None or len(run) > best[2]):
                best = (run[0][0], run[-1][0] + 0x20, len(run))
            run = [(pos, ssn)]
    if len(run) >= min_stubs and (best is None or len(run) > best[2]):
        best = (run[0][0], run[-1][0] + 0x20, len(run))
    return best


# ---------------------------------------------------------------- known shellcode generators
# A framework is reported only when it is identified exactly: the generator's output layout plus
# an internal consistency check (a length field, a computed offset that lands on a PE, a known
# plaintext, a decoder that rebuilds itself). Shared public code that other tools copy (e.g.
# Metasploit's classic block_api) is an indicator, never a framework.
# Layouts were taken from each generator's source and checked against real output.

_M32 = 0xFFFFFFFF


def _rotr32(v, n):
    return ((v >> n) | (v << (32 - n))) & _M32


def _chaskey(mk, block):
    """Chaskey-LTS block encryption as used by Donut (16 rounds)."""
    k = struct.unpack("<4I", mk)
    w = [a ^ b for a, b in zip(struct.unpack("<4I", block), k)]
    for _ in range(16):
        w[0] = (w[0] + w[1]) & _M32
        w[1] = _rotr32(w[1], 27) ^ w[0]
        w[2] = (w[2] + w[3]) & _M32
        w[3] = _rotr32(w[3], 24) ^ w[2]
        w[2] = (w[2] + w[1]) & _M32
        w[0] = (_rotr32(w[0], 16) + w[3]) & _M32
        w[3] = _rotr32(w[3], 19) ^ w[0]
        w[1] = _rotr32(w[1], 25) ^ w[2]
        w[2] = _rotr32(w[2], 16)
    return struct.pack("<4I", *(a ^ b for a, b in zip(w, k)))


def _ctr_read(mk, ctr, data, start, off, n):
    """n plaintext bytes at off of a Chaskey-CTR stream starting at start (big-endian
    128-bit counter). CTR allows decrypting only the blocks that are needed."""
    rel = off - start
    first, last = rel // 16, (rel + n + 15) // 16
    c0 = int.from_bytes(ctr, "big")
    out = bytearray()
    for b in range(first, last):
        ks = _chaskey(mk, ((c0 + b) & ((1 << 128) - 1)).to_bytes(16, "big"))
        out += bytes(x ^ y for x, y in zip(data[start + 16 * b : start + 16 * b + 16], ks))
    skip = rel - 16 * first
    return bytes(out[skip : skip + n])


def _chaskey_stream(mk, c0, nblocks):
    """Chaskey-CTR keystream for nblocks blocks from counter c0 (pure Python, inlined rounds)."""
    k0, k1, k2, k3 = struct.unpack("<4I", mk)
    unpack, pack, m = struct.Struct("<4I").unpack, struct.Struct("<4I").pack, _M32
    out = []
    for b in range(nblocks):
        w0, w1, w2, w3 = unpack(((c0 + b) & ((1 << 128) - 1)).to_bytes(16, "big"))
        w0, w1, w2, w3 = w0 ^ k0, w1 ^ k1, w2 ^ k2, w3 ^ k3
        for _ in range(16):
            w0 = (w0 + w1) & m
            w1 = ((w1 >> 27) | (w1 << 5)) & m ^ w0
            w2 = (w2 + w3) & m
            w3 = ((w3 >> 24) | (w3 << 8)) & m ^ w2
            w2 = (w2 + w1) & m
            w0 = ((((w0 >> 16) | (w0 << 16)) & m) + w3) & m
            w3 = ((w3 >> 19) | (w3 << 13)) & m ^ w0
            w1 = ((w1 >> 25) | (w1 << 7)) & m ^ w2
            w2 = ((w2 >> 16) | (w2 << 16)) & m
        out.append(pack(w0 ^ k0, w1 ^ k1, w2 ^ k2, w3 ^ k3))
    return b"".join(out)


def _chaskey_stream_np(mk, c0, nblocks):
    """The same keystream, vectorised over all blocks with numpy."""
    b = np.arange(nblocks, dtype=np.uint64)
    lo0, hi0 = np.uint64(c0 & (2**64 - 1)), np.uint64((c0 >> 64) & (2**64 - 1))
    lo = lo0 + b  # wraps; the carry goes into the high half of the 128-bit big-endian counter
    hi = hi0 + (lo < lo0).astype(np.uint64)
    blocks = np.empty((nblocks, 2), dtype=">u8")
    blocks[:, 0], blocks[:, 1] = hi, lo
    w = blocks.view("<u4").reshape(-1, 4).astype(np.uint32)
    k = np.frombuffer(mk, dtype="<u4").astype(np.uint32)
    w ^= k

    def rotr(v, r):
        return (v >> np.uint32(r)) | (v << np.uint32(32 - r))

    v0, v1, v2, v3 = (w[:, i].copy() for i in range(4))
    for _ in range(16):
        v0 += v1
        v1 = rotr(v1, 27) ^ v0
        v2 += v3
        v3 = rotr(v3, 24) ^ v2
        v2 += v1
        v0 = rotr(v0, 16) + v3
        v3 = rotr(v3, 19) ^ v0
        v1 = rotr(v1, 25) ^ v2
        v2 = rotr(v2, 16)
    return (np.stack((v0, v1, v2, v3), axis=1) ^ k).astype("<u4").tobytes()


def _ctr_decrypt(mk, ctr, data, start, off, n):
    """_ctr_read for whole payloads (numpy when available: ~30x faster on multi-MB modules)."""
    rel = off - start
    first, last = rel // 16, (rel + n + 15) // 16
    c0 = int.from_bytes(ctr, "big") + first
    ks = (_chaskey_stream_np if np is not None and n >= 4096 else _chaskey_stream)(mk, c0, last - first)
    lo = start + 16 * first
    enc = bytes(data[lo : lo + len(ks)])
    plain = (int.from_bytes(enc, "little") ^ int.from_bytes(ks[: len(enc)], "little")).to_bytes(len(enc), "little")
    skip = rel - 16 * first
    return plain[skip : skip + n]


def _xpress_lz77(src, size):
    """Plain LZ77 Xpress (MS-XCA 2.3, COMPRESSION_FORMAT_XPRESS) decompression, capped at size bytes."""
    out = bytearray()
    i, flags, nflags, half = 0, 0, 0, None
    end = len(src)
    while i < end and len(out) < size:
        if nflags == 0:
            if i + 4 > end:
                break
            flags, nflags, i = _u32(src, i), 32, i + 4
        nflags -= 1
        if not flags >> nflags & 1:
            if i >= end:
                break
            out.append(src[i])
            i += 1
            continue
        if i + 2 > end:
            break
        match = src[i] | src[i + 1] << 8
        i += 2
        length, dist = match & 7, (match >> 3) + 1
        if length == 7:
            if half is None:
                if i >= end:
                    break
                length, half, i = src[i] & 0xF, i, i + 1
            else:
                length, half = src[half] >> 4, None
            if length == 15:
                if i >= end:
                    break
                length, i = src[i], i + 1
                if length == 255:
                    if i + 2 > end:
                        break
                    length, i = src[i] | src[i + 1] << 8, i + 2
                    if length == 0:
                        if i + 4 > end:
                            break
                        length, i = _u32(src, i), i + 4
                    if length < 22:
                        raise ValueError("invalid Xpress match length")
                    length -= 22
                length += 15
            length += 7
        length += 3
        if dist > len(out):
            raise ValueError("Xpress match before the start of the output")
        if dist >= length:
            out += out[-dist : len(out) - dist + length]
        else:
            for _ in range(length):
                out.append(out[-dist])
    return bytes(out[:size])


def _decompress(method, src, size):
    """Donut module compression: aPLib, LZNT1 or plain LZ77 Xpress (RtlDecompressBuffer format compress-1)."""
    if method == "aPLib":
        from cape_parsers.utils.aplib import decompress
    elif method == "LZNT1":
        from cape_parsers.utils.lznt1 import decompress_data as decompress
    elif method == "Xpress":
        return _xpress_lz77(src, size)
    else:
        return None
    out = decompress(bytes(src))
    return out[:size] if out else None


# Donut (github.com/TheWover/donut, donut.c / include/donut.h): E8 <len> <DONUT_INSTANCE> 59 <arch stub>
DONUT_ARCH_STUBS = {
    b"\x59\x5a\x51\x52": "x86",  # pop ecx; pop edx; push ecx; push edx
    b"\x59\x55\x48\x89\xe5\x48\x83\xe4\xf0\x48\x83\xec\x20": "x64",  # pop rcx; LOADER_EXE_X64_RSP_ALIGN
    b"\x59\x31\xc0\x48\x0f\x88": "x86+x64",  # pop ecx; xor eax, eax; dec eax / js (architecture switch)
}
# DONUT_INSTANCE / DONUT_MODULE offsets (Donut 1.x; the same layout Unit 42 documents for an
# in-the-wild sample). Everything from api_cnt on is encrypted with the key stored at +4.
DONUT_INSTANCE = {"key": 0x04, "api_cnt": 0x23C, "dll_names": 0x240, "bypass": 0x570, "headers": 0x574, "type": 0x920,
                  "server": 0x924, "mod_len": 0xD58, "module": 0xD60}  # fmt: skip
DONUT_BYPASS = {1: "no", 2: "yes (stop if it fails)", 3: "yes (continue if it fails)"}  # AMSI/WLDP/ETW
DONUT_HEADERS = {1: "overwritten after loading", 2: "kept"}  # the mapped PE's headers
DONUT_MODULE = {"type": 0x0, "compress": 0x8, "runtime": 0xC, "cls": 0x20C, "method": 0x30C, "zlen": 0x520,
                "len": 0x524, "data": 0x528}  # fmt: skip
DONUT_DLL_NAMES = b"ole32;oleaut32;wininet;mscoree;shell32"  # known plaintext at dll_names
DONUT_MODULE_TYPES = {1: ".NET DLL", 2: ".NET EXE", 3: "DLL", 4: "EXE", 5: "VBScript", 6: "JScript"}
DONUT_COMPRESSION = {1: None, 2: "aPLib", 3: "LZNT1", 4: "Xpress"}
DONUT_INSTANCE_TYPES = {1: "embedded", 2: "HTTP", 3: "DNS"}
EXTRACT_MAX = 32 * 1024 * 1024  # largest payload extracted from a framework layout


def _cstr(raw):
    return raw.split(b"\0", 1)[0].decode("latin-1", "replace")


def identify_donut(data):
    if len(data) < 0x40 or data[0] != 0xE8:
        return None
    n = _u32(data, 1)
    if n < DONUT_INSTANCE["module"] or _u32(data, 5) != n or 5 + n + 16 > len(data):
        return None
    arch = next((a for stub, a in DONUT_ARCH_STUBS.items() if data[5 + n : 5 + n + len(stub)] == stub), None)
    if arch is None:
        return None
    base = 5
    fw = {"name": "Donut", "confidence": "identified", "arch": arch,
          "evidence": [f"call over the instance ({n} bytes); its length field matches",
                       f"Donut's {arch} loader stub follows the instance at {5 + n:#x}"],
          "details": {}, "regions": [], "iocs": {}}  # fmt: skip
    region = {"start": base, "size": n, "status": "structural", "framework": "Donut",
              "source": "call over the instance at 0x0", "result_type": "instance", "result": "Donut instance",
              "entropy": None, "decoded_entropy": None}  # fmt: skip
    fw["regions"].append(region)
    mk, ctr = data[base + 4 : base + 20], data[base + 20 : base + 36]
    start = base + DONUT_INSTANCE["api_cnt"]
    names_at = base + DONUT_INSTANCE["dll_names"]
    if data[names_at : names_at + len(DONUT_DLL_NAMES)] == DONUT_DLL_NAMES:
        encrypted = False

        def read(off, k):
            return data[base + off : base + off + k]
    elif _ctr_read(mk, ctr, data, start, names_at, len(DONUT_DLL_NAMES)) == DONUT_DLL_NAMES:
        encrypted = True

        def read(off, k):
            return _ctr_read(mk, ctr, data, start, base + off, k)
    else:
        # layout matches but the known plaintext does not (another Donut version): no payload details
        region["result"] = "Donut instance (layout of another Donut version: not decoded)"
        return fw
    fw["evidence"].append(
        ("decrypting with the instance's own Chaskey key gives" if encrypted else "plaintext instance holds")
        + " Donut's DLL list 'ole32;oleaut32;wininet;mscoree;shell32'"
    )
    fw["details"]["instance"] = "encrypted with Chaskey-CTR, key stored in the instance" if encrypted else "not encrypted"
    itype = _u32(read(DONUT_INSTANCE["type"], 4), 0)
    fw["details"]["instance_type"] = DONUT_INSTANCE_TYPES.get(itype, str(itype))
    bypass = DONUT_BYPASS.get(_u32(read(DONUT_INSTANCE["bypass"], 4), 0))
    if bypass:
        fw["details"]["amsi_wldp_etw_bypass"] = bypass
    headers = DONUT_HEADERS.get(_u32(read(DONUT_INSTANCE["headers"], 4), 0))
    if itype != 1:
        url = _cstr(read(DONUT_INSTANCE["server"], 256))
        if url:
            fw["details"]["staging_url"] = url
            fw["iocs"]["urls"] = [url]
        region["result"] = (
            f"Donut instance, {'encrypted' if encrypted else 'not encrypted'}; payload staged from {url or 'a server'}"
        )
        return fw
    mod = base + DONUT_INSTANCE["module"]
    head = read(DONUT_INSTANCE["module"], DONUT_MODULE["data"] + 0x400)
    mtype, comp = _u32(head, DONUT_MODULE["type"]), _u32(head, DONUT_MODULE["compress"])
    zlen, plen = _u32(head, DONUT_MODULE["zlen"]), _u32(head, DONUT_MODULE["len"])
    kind = DONUT_MODULE_TYPES.get(mtype)
    if kind is None or plen == 0 or plen > len(data) * 64:
        region["result"] = "Donut instance (module header not recognised)"
        return fw
    compression = DONUT_COMPRESSION.get(comp, f"type {comp}")
    payload = head[DONUT_MODULE["data"] :]
    if not compression:
        pes = find_embedded_pes(payload, len(payload), 1)
        if pes and pes[0]["offset"] == "0x0":
            kind = f"{pes[0]['arch']} {kind}"
    stored = zlen if compression else plen
    fw["details"].update({"payload": kind, "payload_size": plen})
    if headers and mtype in (3, 4):  # unmanaged PEs are mapped by the loader itself
        fw["details"]["pe_headers"] = headers
    for k in ("runtime", "cls", "method"):
        v = _cstr(head[DONUT_MODULE[k] : DONUT_MODULE[k] + 256])
        if v:
            fw["details"][{"cls": "class"}.get(k, k)] = v
    what = f"{kind}, {plen} bytes"
    if compression:
        fw["details"]["compression"] = f"{compression} ({zlen} -> {plen} bytes)"
        what += f", {compression}-compressed to {zlen}"
    region["result"] = f"Donut instance, {'encrypted' if encrypted else 'not encrypted'}; payload: {what}"
    src = mod + DONUT_MODULE["data"]

    def extract():
        if stored > EXTRACT_MAX or plen > EXTRACT_MAX or src + stored > len(data):
            return None
        raw = _ctr_decrypt(mk, ctr, data, start, src, stored) if encrypted else data[src : src + stored]
        if compression:
            raw = _decompress(compression, raw, plen)
        return bytes(raw) if raw and len(raw) == plen else None

    fw["_payload"] = {"extract": extract, "offset": src, "description": f"Donut module: {kind}"}
    fw["regions"].append(
        {
            "start": mod + DONUT_MODULE["data"],
            "size": stored,
            "status": "verified" if encrypted else "structural",
            "framework": "Donut",
            "source": "DONUT_MODULE.data (sizes from the module header)",
            "result_type": "pe" if "EXE" in kind or "DLL" in kind else "script",
            "result": what,
            "entropy": None,
            "decoded_entropy": None,
        }  # fmt: skip
    )
    return fw


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


def identify_srdi(data):
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
        pes = find_embedded_pes(data[dll : dll + 0x1000], 0x1000, 1) if 0 < dll < len(data) else []
        if not (pes and pes[0]["offset"] == "0x0" and data[dll : dll + 2] == b"MZ" and pes[0]["arch"] == arch):
            continue  # the computed DLL offset must land on a PE of the bootstrap's architecture
        size = _pe_raw_size(data, dll + int(pes[0]["nt_offset"], 16)) or None
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
            "extract": lambda: bytes(data[dll:end]) if 0 < end - dll <= EXTRACT_MAX and end <= len(data) else None,
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


# pe2shc (github.com/hasherezade/pe_to_shellcode, pe2shc/main.cpp): the DOS header is overwritten
# with a redirection stub calling the loader appended at the end of the original file
_PE2SHC = (
    (re.compile(rb"MZER\xe8\x00\x00\x00\x00\x58\x83\xe8\x09\x50\x05(.{4})\xff\xd0\xc3", re.S), "x86"),
    (re.compile(rb"MZER\xe8\x00\x00\x00\x00\x59\x48\x83\xe9\x09\x48\x8b\xc1\x48\x05(.{4})\xff\xd0\xc3", re.S), "x64"),
    (re.compile(rb"MZER\xe8\x00\x00\x00\x00\x5b\x48\x83\xeb\x09\x53\x48\x81\xc3(.{4})\xff\xd3\xc3", re.S), "x86 (old loader)"),
)


def identify_pe2shc(data):
    for rx, arch in _PE2SHC:
        m = rx.match(data)
        if not m:
            continue
        stub = _u32(m.group(1), 0)
        pes = find_embedded_pes(data[:0x1000], 0x1000, 1)
        if not pes or pes[0]["offset"] != "0x0":
            continue
        size = _pe_raw_size(data, int(pes[0]["nt_offset"], 16)) or 0
        if not size <= stub < len(data):
            continue  # the loader must sit after the PE's last section
        kind = f"{pes[0]['arch']} {'DLL' if pes[0]['dll'] else 'EXE'}"
        payload = {
            "extract": lambda: bytes(data[:stub]) if 0 < stub <= EXTRACT_MAX else None,
            "offset": 0,
            "description": f"pe2shc original PE: {kind}",
        }
        return {"name": "pe2shc", "confidence": "identified", "arch": pes[0]["arch"], "_payload": payload,
                "evidence": [f"pe2shc {arch} redirection stub in the DOS header", f"it calls the loader appended at {stub:#x}, after the PE's sections"],
                "details": {"payload": kind, "payload_size": stub, "loader_stub": f"{stub:#x}-{len(data):#x}"}, "iocs": {},
                "regions": [{"start": 0, "size": stub, "status": "structural", "framework": "pe2shc", "source": "file before the loader stub",
                             "result_type": "pe", "result": f"{kind}, {stub} bytes", "entropy": None, "decoded_entropy": None}]}  # fmt: skip
    return None


# ------------------------------------------------------------------------------------- encoders
# Encoders wrap a payload in a decoder stub. They are reported as indicators (with the layers they
# wrap), not as frameworks: an encoder says how a payload was wrapped, not which tool produced it.
#
# Shikata Ga Nai (Metasploit modules/encoders/x86/shikata_ga_nai.rb; other implementations exist):
# polymorphic XOR additive feedback encoder. Stub blocks are shuffled: FPU insn, fnstenv [esp-0xc];
# pop A (GetPC), clear ecx, mov cl/cx/ecx, N (dwords), mov K, key; loop: xor [A+d], K / add K, [A+d] /
# add A, 4 (any order); loop. The last 1-4 bytes of the stub (ending in the 'loop' instruction e2 f5)
# are moved into the encoded buffer, so decoding must rebuild the stub's own loop: an exact proof.
_SGN_FNSTENV = b"\xd9\x74\x24\xf4"
ENCODER_MAX_LAYERS = 8


def _sgn_layer(buf):
    """(region start, dword count, key, stub start, decoded bytes, cutoff) for one SGN layer at the head of buf, or None."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    p = buf.find(_SGN_FNSTENV, 0, 0x100)
    while p != -1:
        for s in range(max(0, p - 16), p + 1):
            pre = list(md.disasm_lite(buf[s:p], s))
            if (pre[-1][0] + pre[-1][1] if pre else s) != p:
                continue
            body = list(md.disasm_lite(buf[p : p + 48], p, 12))
            fpu = next((a for a, _, m, _ in reversed(pre) if m.startswith("f")), None)
            # the GetPC pop: first pop after fnstenv (other blocks, e.g. the key load, may sit between)
            pop = next((k for k, (_, _, m, _) in enumerate(body[1:6], 1) if m == "pop" or m in ("push", "call")), None)
            if fpu is None or pop is None or body[pop][2] != "pop" or not _canon(body[pop][3]):
                continue
            addr = _canon(body[pop][3])
            insns = pre + body
            key = count = None
            add_first = False
            xor = None
            for a, sz, m, o in insns:
                parts = o.split(", ", 1)
                if m == "mov" and len(parts) == 2 and _parse_int(parts[1]) is not None and _canon(parts[0]):
                    if _canon(parts[0]) == "c":
                        count = _parse_int(parts[1])
                    elif _reg_bits(parts[0]) == 32:
                        key = (_canon(parts[0]), _parse_int(parts[1]) & _M32)
                elif m in ("add", "sub") and _canon(parts[0]) == addr and len(parts) == 2 and xor is None:
                    step = _parse_int(parts[1])
                    add_first = (m == "add" and step == 4) or (m == "sub" and step in (-4, 0xFFFFFFFC))
                elif m == "xor" and parts[0].startswith("dword ptr [") and key and _canon(parts[1]) == key[0]:
                    mm = _mem(parts[0])
                    if mm and mm[1] == addr and mm[2] is None:
                        xor = (a, mm[4])
                        break
            if not (key and count and xor):
                continue
            start = fpu + xor[1] + (4 if add_first else 0)
            if not s <= start <= len(buf) or start - xor[0] > 16:
                continue
            enc = buf[start : start + 4 * count]
            n = len(enc) // 4
            out = bytearray()
            k = key[1]
            for v in struct.unpack_from(f"<{n}I", enc):
                plain = v ^ k
                out += plain.to_bytes(4, "little")
                k = (k + plain) & _M32
            # known plaintext: the first 1-4 decoded bytes complete the stub, ending in 'loop' back to the xor
            full = buf[:start] + bytes(out[:8])
            for cutoff in (1, 2, 3, 4):
                end = start + cutoff
                if (
                    full[end - 2 : end] == b"\xe2\xf5"
                    and end - 11 <= xor[0]
                    and _sgn_loop_ok(md, full, end - 11, end, addr, key[0])
                ):
                    return start, count, key[1], s, bytes(out), cutoff
        p = buf.find(_SGN_FNSTENV, p + 1, 0x100)
    return None


def _sgn_loop_ok(md, full, lo, end, addr, key):
    """The rebuilt loop block: xor [A+d], K; add K, [A+d]; add A, 4 (any order), then loop to lo."""
    ins = list(md.disasm_lite(full[lo:end], lo))
    if not ins or ins[-1][0] + ins[-1][1] != end or ins[-1][2] != "loop" or _parse_int(ins[-1][3]) != lo:
        return False
    kinds = set()
    for _, _, m, o in ins[:-1]:
        parts = o.split(", ", 1)
        if m == "xor" and parts[0].startswith("dword ptr [") and _canon(parts[1]) == key:
            kinds.add("xor")
        elif m == "add" and _canon(parts[0]) == key and parts[1].startswith("dword ptr ["):
            kinds.add("feedback")
        elif m in ("add", "sub") and _canon(parts[0]) == addr:
            kinds.add("step")
        else:
            return False
    return kinds == {"xor", "feedback", "step"}


def _layer(name, arch, stub, start, size, payload, how):
    return {"name": name, "arch": arch, "stub": stub, "start": start, "size": size, "payload": payload, "how": how}


def _enc_sgn(buf):
    r = _sgn_layer(buf)
    if r is None:
        return None
    start, count, key, stub, decoded, cutoff = r
    return _layer("x86/shikata_ga_nai", "x86", stub, start, 4 * count, decoded[cutoff:],
                  f"FPU GetPC, key {key:#010x}, {count} dwords; decoding rebuilds the stub's own loop ({cutoff} byte tail)")  # fmt: skip


# Metasploit (msfvenom) encoders with fixed stubs: modules/encoders/x86|x64 and rex-encoder alpha2.
# Rex::Arch::X86 set/sub forms that load the loop counter into ecx ahead of a fixed stub tail.
_REX_CLEAR = frozenset((b"\x29\xc9", b"\x2b\xc9", b"\x31\xc9", b"\x33\xc9"))


def _rex_ecx(buf, end):
    """ecx after the Rex counter prefix that ends at end (set: push/pop, mov cl/cx/ecx, clear;
    sub: clear + sub ecx, -n), or None."""

    def clear(at):
        return at >= 2 and buf[at - 2 : at] in _REX_CLEAR

    b = buf[max(0, end - 9) : end]
    n = len(b)
    # longest forms first, so an immediate's own bytes are not read as a shorter form
    if n >= 6 and b[-6:-4] == b"\x81\xe9" and clear(end - 6):  # sub ecx, imm32
        return -struct.unpack("<I", b[-4:])[0] & _M32
    if n >= 5 and b[-5:-2] == b"\x66\x81\xe9" and clear(end - 5):  # sub cx, imm16
        return -struct.unpack("<H", b[-2:])[0] & 0xFFFF
    if n >= 6 and b[-6] == 0x68 and b[-1] == 0x59:  # push imm32; pop ecx
        return struct.unpack("<I", b[-5:-1])[0]
    if n >= 4 and b[-4:-2] == b"\x66\xb9" and clear(end - 4):  # mov cx, imm16
        return struct.unpack("<H", b[-2:])[0]
    if n >= 5 and b[-5] == 0xB9:  # mov ecx, imm32
        return struct.unpack("<I", b[-4:])[0]
    if n >= 3 and b[-3:-1] == b"\x83\xe9" and clear(end - 3):  # sub ecx, imm8
        return -struct.unpack("<b", b[-1:])[0] & _M32
    if n >= 3 and b[-3] == 0x6A and b[-1] == 0x59:  # push imm8; pop ecx
        return struct.unpack("<b", b[-2:-1])[0] & _M32
    if n >= 2 and b[-2] == 0xB1 and clear(end - 2):  # mov cl, imm8
        return b[-1]
    return None


def _xor_blocks(enc, key, width):
    fmt = {4: "I", 8: "Q"}[width]
    n = len(enc) // width
    return struct.pack(f"<{n}{fmt}", *(v ^ key for v in struct.unpack_from(f"<{n}{fmt}", enc)))


_MSF_X64_XOR = re.compile(rb"\x48\x31\xc9\x48\x81\xe9(.{4})\x48\x8d\x05\xef\xff\xff\xff\x48\xbb(.{8})\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4", re.S)  # fmt: skip
_MSF_CALL4 = re.compile(rb"\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e(.{4})\x83\xee\xfc\xe2\xf4", re.S)
_MSF_FNSTENV_MOV = re.compile(rb"\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13(.{4})\x83\xeb\xfc\xe2\xf4", re.S)
_MSF_COUNTDOWN = re.compile(rb"\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e\x07\xe2\xfa")
_MSF_JMP_CALL_ADD = re.compile(rb"\xfc\xbb(.{4})\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff", re.S)  # fmt: skip
# xor_dynamic: 'A' (key terminator) and 'BB' (payload terminator) are replaced by chosen bytes
_MSF_XOR_DYN = (
    (
        re.compile(
            rb"\xeb\x23\x5b\x89\xdf\xb0(.)\xfc\xae\x75\xfd\x89\xf9\x89\xde\x8a\x06\x30\x07\x47\x66\x81\x3f(..)\x74\x08\x46\x80\x3e\1\x75\xee\xeb\xea\xff\xe1\xe8\xd8\xff\xff\xff",
            re.S,
        ),
        "x86",
    ),  # fmt: skip
    (
        re.compile(
            rb"\xeb\x27\x5b\x53\x5f\xb0(.)\xfc\xae\x75\xfd\x57\x59\x53\x5e\x8a\x06\x30\x07\x48\xff\xc7\x48\xff\xc6\x66\x81\x3f(..)\x74\x07\x80\x3e\1\x75\xea\xeb\xe6\xff\xe1\xe8\xd4\xff\xff\xff",
            re.S,
        ),
        "x64",
    ),  # fmt: skip
)
# alpha2 decoders: fixed alphanumeric bodies (after a register-dependent prefix); the encoded
# payload follows as character pairs up to the 'AA' terminator
_MSF_ALPHA = (
    (b"jAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI", "x86/alpha_mixed"),
    (b"VTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJI", "x86/alpha_upper"),
)
_MSF_UNICODE = (
    (b"jXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JB", "x86/unicode_mixed"),
    (b"QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JB",
     "x86/unicode_upper"),
)  # fmt: skip
ENCODER_SEARCH = 0x400  # an encoder's stub sits at the head of what it wraps


def _enc_x64_xor(buf):
    m = _MSF_X64_XOR.search(buf, 0, ENCODER_SEARCH)
    if not m:
        return None
    blocks = -struct.unpack("<i", m.group(1))[0]
    key = struct.unpack("<Q", m.group(2))[0]
    start = m.end()
    if not 0 < blocks or start + 8 * blocks > len(buf):
        return None
    return _layer("x64/xor", "x64", m.start(), start, 8 * blocks, _xor_blocks(buf[start : start + 8 * blocks], key, 8),
                  f"lea rax, [rip-0x11] GetPC, qword key {key:#018x}, {blocks} qwords")  # fmt: skip


def _enc_dword_xor(buf, rx, name, getpc):
    m = rx.search(buf, 0, ENCODER_SEARCH)
    if not m:
        return None
    count = _rex_ecx(buf, m.start())
    key = struct.unpack("<I", m.group(1))[0]
    start = m.end()
    if not count or start + 4 * count > len(buf):
        return None
    return _layer(name, "x86", m.start(), start, 4 * count, _xor_blocks(buf[start : start + 4 * count], key, 4),
                  f"{getpc} GetPC, key {key:#010x}, {count} dwords")  # fmt: skip


def _enc_call4(buf):
    return _enc_dword_xor(buf, _MSF_CALL4, "x86/call4_dword_xor", "call $+4")


def _enc_fnstenv_mov(buf):
    return _enc_dword_xor(buf, _MSF_FNSTENV_MOV, "x86/fnstenv_mov", "fldz + fnstenv")


def _enc_countdown(buf):
    m = _MSF_COUNTDOWN.search(buf, 0, ENCODER_SEARCH)
    if not m:
        return None
    count = _rex_ecx(buf, m.start())
    start = m.end()
    if count is None or start + count + 1 > len(buf):
        return None
    n = count + 1
    payload = bytes(b ^ ((i + 1) & 0xFF) for i, b in enumerate(buf[start : start + n]))
    return _layer("x86/countdown", "x86", m.start(), start, n, payload, f"call $+4 GetPC, byte i xor (i+1), {n} bytes")


def _enc_jmp_call_additive(buf):
    m = _MSF_JMP_CALL_ADD.search(buf, 0, ENCODER_SEARCH)
    if not m:
        return None
    k = key = struct.unpack("<I", m.group(1))[0]
    start, out = m.end(), bytearray()
    for at in range(start, len(buf) - 3, 4):
        plain = struct.unpack_from("<I", buf, at)[0] ^ k
        if plain == 0:  # the encoder appends its final key: decodes to the zero terminator
            return _layer("x86/jmp_call_additive", "x86", m.start(), start, at + 4 - start, bytes(out),
                          f"jmp/call/pop GetPC, XOR additive feedback from key {key:#010x}, zero-dword terminated")  # fmt: skip
        out += plain.to_bytes(4, "little")
        k = (k + plain) & _M32
    return None


def _enc_xor_dynamic(buf):
    for rx, arch in _MSF_XOR_DYN:
        m = rx.search(buf, 0, ENCODER_SEARCH)
        if not m:
            continue
        kt, pt = m.group(1), m.group(2)
        k_end = buf.find(kt, m.end(), m.end() + 0x10000)
        if k_end <= m.end():
            continue
        key = buf[m.end() : k_end]
        start = k_end + 1
        end = buf.find(pt, start)
        if end < 0:
            continue
        payload = bytes(b ^ key[i % len(key)] for i, b in enumerate(buf[start:end]))
        return _layer(f"{arch}/xor_dynamic", arch, m.start(), start, end + 2 - start, payload,
                      f"jmp/call/pop GetPC, {len(key)}-byte key, terminators {kt.hex()} / {pt.hex()}")  # fmt: skip
    return None


def _alpha_pairs(text, additive):
    """alpha2 payload: (second, first) character pairs; low nibble from the first, high nibble
    xored (alpha) or added (unicode) from the second's low nibble and the first's high nibble."""
    out = bytearray()
    for i in range(0, len(text) - 1, 2):
        s, f = text[i], text[i + 1]
        hi = ((s & 0xF) + (f >> 4)) & 0xF if additive else (s & 0xF) ^ (f >> 4)
        out.append(hi << 4 | f & 0xF)
    return bytes(out)


def _enc_alpha(buf):
    for core, name in _MSF_ALPHA:
        at = buf.find(core, 0, ENCODER_SEARCH + len(core))
        if at < 0:
            continue
        start = at + len(core)
        end = start
        while end + 1 < len(buf) and buf[end : end + 2] != b"AA" and buf[end : end + 2].isalnum():
            end += 2
        if buf[end : end + 2] != b"AA" or end == start:
            continue
        return _layer(name, "x86", at, start, end + 2 - start, _alpha_pairs(buf[start:end], False),
                      f"alphanumeric decoder body, {(end - start) // 2} bytes as character pairs, 'AA' terminated")  # fmt: skip
    for core, name in _MSF_UNICODE:
        for form, label in ((core, ""), (b"".join(bytes([c, 0]) for c in core), " (widened in memory)")):
            at = buf.find(form, 0, ENCODER_SEARCH + len(form))
            if at >= 0:
                return _layer(name, "x86", at, at + len(form), 0, b"", f"unicode-safe decoder body{label}; payload not decoded")
    return None


def _enc_zutto_dekiru(buf):
    """x64/zutto_dekiru: polymorphic head (FPU insn + fxsave64 GetPC, key and count loads in random
    order), then dec S; xor [R + S*8 + d], K; test S, S; jnz. Proven when d lands exactly on the
    end of that loop, counted from the FPU instruction whose address fxsave64 stores."""
    m = re.search(rb"[\x48\x49]\x0f\xae(?:[\x00-\x07]|\x45\x00)", buf[:0x80])
    if not m:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    ins = list(md.disasm_lite(buf[:0xA0], 0))
    fpu = next((a for a, _, mn, _ in ins if a < m.start() and mn.startswith("f") and not mn.startswith("fxsave")), None)
    if fpu is None:
        return None
    key = count = None
    for k, (a, sz, mn, o) in enumerate(ins):
        parts = o.split(", ", 1)
        if mn in ("mov", "movabs") and len(parts) == 2 and _canon(parts[0]) and _parse_int(parts[1]) is not None:
            v = _parse_int(parts[1])
            if _reg_bits(parts[0]) == 64 and v > 0xFFFFFFFF:
                key = (_canon(parts[0]), v)
            else:
                count = (_canon(parts[0]), v)
        if mn == "xor" and parts[0].startswith("qword ptr [") and key and count and _canon(parts[1]) == key[0]:
            mm = _mem(parts[0])
            nxt = ins[k + 1 : k + 3]
            if not (mm and mm[2] == count[0] and mm[3] == 8 and k >= 1 and ins[k - 1][2] == "dec" and len(nxt) == 2):
                return None
            if nxt[0][2] != "test" or nxt[1][2] != "jne" or _parse_int(nxt[1][3]) != ins[k - 1][0]:
                return None
            start = fpu + mm[4]
            n = count[1]
            if start != nxt[1][0] + nxt[1][1] or not 0 < n or start + 8 * n > len(buf):
                return None
            return _layer("x64/zutto_dekiru", "x64", 0, start, 8 * n, _xor_blocks(buf[start : start + 8 * n], key[1], 8),
                          f"FPU + fxsave64 GetPC, qword key {key[1]:#018x}, {n} qwords")  # fmt: skip
    return None


_ENCODER_LAYERS = (_enc_sgn, _enc_x64_xor, _enc_call4, _enc_fnstenv_mov, _enc_countdown, _enc_jmp_call_additive,
                   _enc_xor_dynamic, _enc_zutto_dekiru, _enc_alpha)  # fmt: skip


def _encoder_layer(buf):
    for fn in _ENCODER_LAYERS:
        layer = fn(buf)
        if layer:
            return layer
    return None


def identify_encoders(data):
    """An encoder wrapping the payload, peeled layer by layer (msfvenom -i / chained -e). Each layer
    is proven: an exact stub, or (Shikata Ga Nai) the decoded tail rebuilding the stub's own loop."""
    first = _encoder_layer(data)
    if first is None:
        return None
    layers = [first]
    payload = first["payload"]
    while payload and len(layers) < ENCODER_MAX_LAYERS:
        nxt = _encoder_layer(payload)
        if nxt is None or nxt["stub"] > 0x40:
            break
        layers.append(nxt)
        payload = nxt["payload"]
    arch = layers[-1]["arch"]
    what, found = f"{arch} data", []
    head = payload[:8192]
    if head:
        d = _Descent(head, CS_MODE_64 if arch == "x64" else CS_MODE_32, 1500)
        d.run(_seeds(head, d.md, 8))
        r = _evaluate_island(head, d, arch == "x64", None, {"context": 0}, nested=True)
        if r["structure"]["coherent"]:
            found = [t for t in r["tags"] if t not in UNSCORED and r["_weights"].get(t, 0) >= MEDIUM]
            what = f"{arch} code"
    names = [lay["name"] for lay in layers]
    chain = " -> ".join(names) if len(set(names)) > 1 else names[0] + (f" x{len(names)}" if len(names) > 1 else "")
    sgn = first["name"] == "x86/shikata_ga_nai"
    return {
        "name": chain,
        "tag": "shikata_ga_nai" if sgn else "msf_encoder",
        "arch": first["arch"],
        "layers": len(layers),
        "stub": first["stub"],
        "how": first["how"],
        "payload": payload,
        "what": what,
        "found": found,
        "region": {"start": first["start"], "size": first["size"], "status": "verified", "framework": None,
                   "source": f"{first['name']} decoder stub at {first['stub']:#x}", "result_type": "code" if what.endswith("code") else "data",
                   "result": (f"{what}" + (f" ({', '.join(found[:6])})" if found else "") + f" after {len(layers)} layer{'s' if len(layers) > 1 else ''}")
                   if payload else "not decoded (unicode-safe encoder)",
                   "entropy": None, "decoded_entropy": None},
    }  # fmt: skip


# Metasploit's classic block_api prologue (also copied by other tools, e.g. Cobalt Strike stagers).
# Current Metasploit shuffles block_api and randomises its hash IV, so this is a resemblance only.
_MSF_BLOCK_API = (
    (re.compile(rb"\x60\x89\xe5\x31[\xc0\xd2]\x64\x8b[\x50\x52]\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"), "x86"),
    (re.compile(rb"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"), "x64"),
)  # fmt: skip


# wininet stager (Metasploit reverse_http(s) and the many stagers built the same way): every string
# argument is passed with call-over-string (the call pushes the address of the string after it), and
# APIs are called by block_api hash: push imm32 (x86) / mov r10d, imm32 (x64), then call ebp/rbp.
# Current Metasploit seeds block_api's ror13 with a random IV held in the stub (mov edi, iv / mov
# r9d, iv); classic stagers (and copies of them) use IV 0.
_INTERNET_FLAG_RELOAD_NO_CACHE = 0x84000000  # INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
_INTERNET_FLAG_SECURE = 0x00800000
_HASH_CALL_RE = re.compile(rb"(?:\x68|\x41\xba)(.{4})\xff\xd5", re.S)
_BLOCK_API_IV_RE = re.compile(rb"(?:\xbf|\x41\xb9)(.{4})", re.S)


def _ror13(data, h=0):
    for c in data:
        h = (((h >> 13) | (h << 19)) & _M32) + c & _M32
    return h


def _block_api_hash(mod, func, iv=None):
    """block_api hash of mod!func. Classic (iv None): ror13 of the upper-case UTF-16LE module name
    with its NUL, plus ror13 of the function name with its NUL. Current Metasploit
    (Rex::Text.block_api_hash): ror13 of the module name (no NUL) from iv, then of the function name
    and its NUL continuing from the module hash."""
    wide = mod.upper().encode("utf-16le")
    if iv is None:
        return (_ror13(wide + b"\x00\x00") + _ror13(func.encode() + b"\x00")) & _M32
    return _ror13(func.encode() + b"\x00", _ror13(wide, iv & _M32))


def _call_strings(data, limit=0x10000):
    """[(call offset, string, call target)] for call-over-string: e8 rel32 followed by a printable
    NUL-terminated string (the return address pushed is the string's), the call landing past its
    end or back before the call (x86 stagers fetch the host with a backward call)."""
    out = []
    for m in re.finditer(rb"\xe8(.{4})([\x20-\x7e]{1,1024})\x00", data[:limit], re.S):
        rel = struct.unpack("<i", m.group(1))[0]
        if rel >= len(m.group(2)) + 1 or -m.start() - 5 <= rel < -5:
            out.append((m.start(), m.group(2).decode("ascii"), m.start() + 5 + rel))
    return out


def find_http_stager(data, limit=0x10000):
    """{host, port, uri, scheme, url, user_agent} of a wininet stager. The block_api IV is the one
    for which InternetConnectA's hash is called; then the host is the call-over-string landing just
    before that call, the port the immediate passed with it (x86: pushed before the URI's call; x64:
    mov r8), the URI the '/' string, https when HttpOpenRequestA's flags carry INTERNET_FLAG_SECURE,
    and the User-Agent the string landing just before the InternetOpenA call."""
    head = data[:limit]
    calls = {}
    for m in _HASH_CALL_RE.finditer(head):
        calls.setdefault(_u32(m.group(1), 0), []).append(m.start())
    if not calls:
        return None
    ivs = [None] + [_u32(m.group(1), 0) for m in _BLOCK_API_IV_RE.finditer(head)][:64]
    found = [v for v in ivs if _block_api_hash("wininet.dll", "InternetConnectA", v) in calls]
    if not found:
        return None
    iv = found[0]
    connects = calls[_block_api_hash("wininet.dll", "InternetConnectA", iv)]
    every = sorted(p for ps in calls.values() for p in ps)

    def lands_before(tgt, targets, within):
        # the first API call after the string's call target is the one it is an argument of
        nxt = next((p for p in every if p >= tgt), None)
        return nxt in targets and nxt - tgt <= within

    strings = _call_strings(head)
    host = next((st for _, st, tgt in strings if not st.startswith("/") and lands_before(tgt, connects, 0x30)), None)
    uri_call = next(((at, st) for at, st, _ in strings if st.startswith("/")), None)
    if host is None or uri_call is None:
        return None
    port = None
    at = uri_call[0]
    if at >= 2 and head[at - 2] == 0x6A:  # x86: push port; call over the URI
        port = head[at - 1]
    elif at >= 5 and head[at - 5] == 0x68:
        port = _u32(head, at - 4)
    else:  # x64: mov r8, port after the host string
        m = re.search(rb"(?:\x49\xc7\xc0|\x41\xb8)(.{4})", head[max(0, connects[0] - 0x30) : connects[0]], re.S)
        port = _u32(m.group(1), 0) if m else None
    if not port or port > 0xFFFF:
        return None
    scheme = "http"
    opens_request = calls.get(_block_api_hash("wininet.dll", "HttpOpenRequestA", iv), [])
    if opens_request:
        for f in re.finditer(rb"(?:\x68|\x48\xc7\xc0|\xb8)(.{4})", head[max(0, opens_request[0] - 0x40) : opens_request[0]], re.S):
            flags = _u32(f.group(1), 0)
            if flags & _INTERNET_FLAG_RELOAD_NO_CACHE == _INTERNET_FLAG_RELOAD_NO_CACHE:
                scheme = "https" if flags & _INTERNET_FLAG_SECURE else "http"
    opens = calls.get(_block_api_hash("wininet.dll", "InternetOpenA", iv), [])
    ua = next((st for _, st, tgt in strings if lands_before(tgt, opens, 0x20)), None)
    out = {"host": host, "port": port, "uri": uri_call[1], "scheme": scheme, "url": f"{scheme}://{host}:{port}{uri_call[1]}"}
    if iv is not None:
        out["block_api_iv"] = f"{iv:#010x}"
    if ua:
        out["user_agent"] = ua
    return out


def find_block_api(data):
    """(offset, arch) of the classic Metasploit block_api prologue, or None."""
    for rx, arch in _MSF_BLOCK_API:
        m = rx.search(data, 0, 0x10000)
        if m:
            return m.start(), arch
    return None


def _framework_label(fw):
    """Short badge text: 'Donut: x64 EXE', 'sRDI: x64 DLL'."""
    d = fw["details"]
    name = fw["name"] + (f" x{d['iterations']}" if d.get("iterations", 1) > 1 else "")
    kind = d.get("payload") or ("staged (HTTP)" if d.get("staging_url") else "")
    return f"{name}: {kind}" if kind else name


# Family reported for an identified framework when it becomes a CAPE detection (default: its name)
FRAMEWORK_FAMILIES = {}


def framework_family(name):
    return FRAMEWORK_FAMILIES.get(name, name)


def identify_frameworks(data):
    """Known generator/encoder layouts, each matched exactly (one generator writes the outer layout).
    Shared public code that other tools copy is reported as an indicator instead (block_api_prologue)."""
    for fn in (identify_donut, identify_srdi, identify_pe2shc):
        fw = fn(data)
        if fw:
            fw["label"] = _framework_label(fw)
            return [fw]
    return []


# Verbatim modern x64 ntdll syscall stub (KUSER_SHARED_DATA test + int 2e fallback). The legacy
# 'mov r10, rcx; mov eax, SSN; syscall; ret' form is not matched: hand-written direct-syscall
# stubs (Hell's Gate and the like) are byte-identical to it.
_SYSCALL_STUB_RE = re.compile(
    rb"\x4c\x8b\xd1\xb8(..)\x00\x00\xf6\x04\x25\x08\x03\xfe\x7f\x01\x75\x03\x0f\x05\xc3\xcd\x2e\xc3", re.S
)


def find_stub_copies(buf):
    """SSNs when the whole buffer is one or a few verbatim ntdll syscall stubs (allowing a few
    padding bytes each): hook-bypass copies, and browser sandbox interception thunks (Chromium)."""
    if len(buf) > 0x200:
        return None
    stubs = list(_SYSCALL_STUB_RE.finditer(buf))
    if not stubs or stubs[0].start() > 8:
        return None
    covered = sum(m.end() - m.start() for m in stubs)
    if len(buf) - covered > 8 * len(stubs):
        return None
    return [int.from_bytes(m.group(1), "little") for m in stubs]


def find_import_names(buf, embedded=()):
    """(offset, entries) of the longest import hint/name run outside embedded PEs."""
    skip = []
    for pe in embedded:
        lo = int(pe["offset"], 16)
        if lo > 0:
            skip.append((lo, lo + max(int(pe.get("size_of_image", "0x0"), 16), 0x1000)))
    best = None
    for m in _HINT_NAME_RE.finditer(buf):
        if any(lo <= m.start() < hi for lo, hi in skip):
            continue
        count = len(_HINT_ENTRY_RE.findall(m.group()))
        if best is None or count > best[1]:
            best = (m.start(), count)
    return best


PDATA_MIN_ENTRIES = 32


def find_pdata(buf, limit=0x2000000):
    """(offset, entries) of an x64 exception table (.pdata) at a page boundary: RUNTIME_FUNCTION
    entries {begin, end, unwind RVA} ascending and non-overlapping, each unwind RVA pointing at
    UNWIND_INFO version 1/2. In a mapped image RVAs are buffer offsets, so this holds even when the
    headers and the import names were wiped."""
    size = min(len(buf), limit)
    bound = size + 0x10000
    for page in range(0x1000, size - 12 * PDATA_MIN_ENTRIES, 0x1000):
        count, prev_end = 0, 0
        for at in range(page, min(size - 12, page + 12 * 4096), 12):
            begin, end, unwind = struct.unpack_from("<3I", buf, at)
            if not (0x1000 <= begin < end <= bound and begin >= prev_end and end - begin < 0x100000):
                break
            u = unwind & ~1  # bit 0 marks a chained entry pointing at another RUNTIME_FUNCTION
            if not 0x1000 <= u < size or (unwind & 1 == 0 and buf[u] & 7 not in (1, 2)):
                break
            count += 1
            prev_end = end
        if count >= PDATA_MIN_ENTRIES:
            return page, count
    return None


# ---------------------------------------------------------------- IOC extraction
_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,2048}")
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,2048}")
_TLDS = (
    "com|net|org|info|biz|io|co|me|tv|cc|ru|su|ua|by|kz|cn|hk|tw|jp|kr|in|ir|tr|de|fr|it|es|nl|be|ch|at|pl|cz|ro|hu|"
    "uk|eu|us|ca|au|br|ar|mx|top|xyz|online|site|club|shop|store|live|icu|vip|pro|pw|ws|tk|ml|ga|cf|gq|onion|"
    "cloud|app|dev|link|click|space|website|fun|work|today|buzz|best|cyou|rest|monster|digital|network|tech|life"
)
_IOC_PATTERNS = (
    ("urls", re.compile(r"(?:https?|ftp|wss?)://[\x21-\x7e]{3,}", re.I)),
    ("ips", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?![\d.])")),
    ("domains", re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r")(?![\w-])", re.I)),
    ("pipes", re.compile(r"\\\\[.?]\\pipe\\[\x21-\x7e]+", re.I)),
    ("paths", re.compile(r"(?:[a-z]:\\|%[a-z_]+%\\|\\\\[\w.$-]+\\|\\(?:\?\?|Device|KnownDlls|BaseNamedObjects|SystemRoot)\\)[^\x00-\x1f\"<>|*?]{2,}", re.I)),
    ("registry", re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|\\Registry\\Machine|(?<![\w\\])(?:SOFTWARE|SYSTEM)\\(?:Microsoft|CurrentControlSet|Classes|Policies|Wow6432Node))\\?[^\x00-\x1f\"]{2,}", re.I)),
    ("user_agents", re.compile(r"(?:Mozilla/\d\.\d[^\x00-\x1f]*|User-Agent: ?[^\x00-\x1f]+)")),
    ("http", re.compile(r"(?:(?:GET|POST|PUT|HEAD) /[\x21-\x7e]*(?: HTTP/1\.[01])?|(?:Host|Cookie|Content-Type|Authorization|Accept): ?[^\x00-\x1f]+)")),
    ("commands", re.compile(r"(?:cmd(?:\.exe)?\s+/[ckr]\s+|powershell(?:\.exe)?\s+-|(?:rundll32|regsvr32|mshta|certutil|bitsadmin|schtasks|wmic|whoami)(?:\.exe)?\s+)[^\x00-\x1f]*", re.I)),
    ("files", re.compile(r"(?<![\w\\/.-])[\w-][\w .-]{0,62}\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|vbe|js|jse|hta|scr|lnk|msi|cpl|ocx|dat|bin|tmp|log|txt|zip|7z|rar)(?![\w])", re.I)),
)  # fmt: skip
_SYSTEM_MODULES = frozenset(
    (
        "kernel32 ntdll kernelbase user32 advapi32 ws2_32 wininet winhttp shell32 ole32 oleaut32 mscoree amsi urlmon "
        "crypt32 msvcrt ucrtbase iphlpapi dnsapi netapi32 bcrypt secur32 shlwapi psapi version clr mscorlib wtsapi32 "
        "gdi32 comctl32 rpcrt4 sechost combase dbghelp userenv mswsock"
    ).split()
)
IOC_LIMIT = 25


def extract_iocs_fn(buf, stack_strings=(), sockaddrs=()):
    """Network/file/registry/command indicators from printable strings in the
    buffer (ASCII and UTF-16LE), strings built on the stack, and literal
    sockaddr_in structures. Returns {category: [values]}, the API names seen
    as plain strings, and CLR runtime names/versions seen (Donut-style .NET hosting)."""
    strings = [m.group().decode("ascii") for m in _ASCII_RE.finditer(buf)]
    strings += [m.group().decode("utf-16le", "ignore") for m in _WIDE_RE.finditer(buf)]
    strings += list(stack_strings)
    out = {}
    apis = set()
    clr = set()

    def put(cat, value):
        vals = out.setdefault(cat, [])
        value = value.strip()[:256]
        if value and value not in vals and len(vals) < IOC_LIMIT:
            vals.append(value)

    for string in strings:
        low = string.lower()
        if low in _API_NAMES:
            apis.add(_API_NAMES[low])
        clr.update(h for h in _CLR_HINTS if h in low)
        for cat, rx in _IOC_PATTERNS:
            for m in rx.finditer(string):
                value = m.group()
                if cat == "ips" and value.split(":")[0] in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
                    continue
                if cat == "files":
                    stem = value.rsplit(".", 1)[0].lower()
                    if value.lower().endswith(".dll") and stem in _SYSTEM_MODULES:
                        put("modules", value)
                        continue
                if cat == "domains" and any(value.lower() in u.lower() for u in out.get("urls", ())):
                    continue
                if cat == "paths" and "\\pipe\\" in value.lower():
                    continue  # reported under pipes
                if cat == "paths" and sum(c.isalpha() for c in value) < 4:
                    continue  # digit/backslash runs from data, not a path
                if cat == "files" and any(
                    value.lower() in v.lower() for c in ("urls", "paths", "commands") for v in out.get(c, ())
                ):
                    continue  # already visible in a fuller indicator
                put(cat, value)
    for addr in sockaddrs:
        put("network", addr)
    return out, apis, sorted(clr)


_CLR_HINTS = ("clr.dll", "mscoree.dll", "mscorlib", "v4.0.30319", "v2.0.50727")


def _capabilities(apis, clr_hints=()):
    found = {}
    for cap, names in CAPABILITIES.items():
        hit = sorted(set(names) & apis)
        if hit:
            found[cap] = hit
    if clr_hints:  # CLR runtime names/versions in strings: Donut-style .NET hosting
        found["dotnet_hosting"] = sorted(set(found.get("dotnet_hosting", ())) | {f"'{h}'" for h in clr_hints})
    # injection needs a write/execute primitive, not just one call
    if "remote_injection" in found and len(found["remote_injection"]) < 2:
        del found["remote_injection"]
    # Ekko-style sleep masking: RtlCaptureContext alone is in every MSVC runtime
    sleep = set(found.get("sleep_obfuscation", ()))
    timers = {"NtContinue", "SystemFunction032", "SystemFunction033", "CreateTimerQueueTimer", "RtlCreateTimer", "RtlRegisterWait"}
    if sleep and (len(sleep) < 2 or not sleep & timers):
        del found["sleep_obfuscation"]
    # one work item API on its own says little; the work-item lifecycle does
    if len(found.get("threadpool_execution", ())) < 2:
        found.pop("threadpool_execution", None)
    return found


def _collect_payloads(frameworks, regions, encoder=None):
    """Payloads recovered statically: what an identified framework carries, else what an encoder
    wraps, else the PE images and exactly sized code decoded from verified regions.
    [{data, framework, family, offset, description}]"""
    out = []
    for f in frameworks:
        p = f.get("_payload") if f["confidence"] == "identified" else None
        if not p:
            continue
        try:
            blob = p["extract"]()
        except Exception as e:  # malformed module: report the framework, skip the payload
            f.setdefault("details", {})["extraction"] = f"failed: {e}"
            continue
        if blob:
            out.append({"data": blob, "framework": f["name"], "family": framework_family(f["name"]),
                        "offset": hex(p["offset"]), "description": p["description"]})  # fmt: skip
    if out:
        return out
    if encoder and encoder["payload"]:
        return [{"data": encoder["payload"], "framework": None, "family": None, "offset": hex(encoder["region"]["start"]),
                 "description": f"{encoder['name']} decoded {encoder['what']}"}]  # fmt: skip
    seen = set()
    for g in sorted(regions, key=lambda g: g["start"]):
        blob = g.get("_data")
        if blob and g.get("status") == "verified" and blob not in seen:
            seen.add(blob)
            out.append({"data": blob, "framework": None, "family": None, "offset": hex(g["start"]),
                        "description": f"{g['source']}: {g['result']}"})  # fmt: skip
    return out


def analyse(
    data,
    va=None,
    arch=None,
    max_scan=MAX_SCAN_DEFAULT,
    max_insns=MAX_INSNS_DEFAULT,
    max_seeds=32,
    deep_scan=True,
    deep_bytes=DEEP_BYTES_DEFAULT,
    deep_windows=DEEP_WINDOWS,
    extract_iocs=True,
    evidence_context=2,
    entry=None,
    extract_payloads=False,
):
    """Classify a buffer.

    arch: None (auto), "x86" or "x64". va: int or hex string region base.
    max_scan: head window fully analysed (0/None = whole buffer).
    max_insns: instruction budget per island (descent depth).
    deep_scan/deep_bytes/deep_windows: follow code beyond the head window.
    extract_iocs: URLs, IPs, domains, paths, registry, pipes, commands, ...
    evidence_context: disassembly lines kept either side of each match.
    entry: known entry offset (int or hex string), e.g. the shellcode package's 'offset' option.
    extract_payloads: also return the payloads recovered statically under the internal key
    '_payloads' (bytes; the caller must pop it before storing the result): the module carried by
    an identified framework, else PE images or exactly sized code decoded from a verified region.
    """
    start = default_timer()
    if not HAVE_CAPSTONE:
        return {"verdict": "unavailable", "error": "capstone not installed"}
    if isinstance(va, str):
        va = _parse_int(va)
    if isinstance(entry, str):
        entry = _parse_int(entry)
    opts = {"context": max(0, int(evidence_context))}
    size = len(data)
    window = size if not max_scan or max_scan <= 0 else min(size, max_scan)
    buf = bytes(memoryview(data)[:window])
    stats = byte_stats(buf)
    result = {
        "verdict": "data",
        "score": 0,
        "tags": [],
        "indicators": [],
        "evidence": [],
        "bytes": stats,
        "size": size,
        "scanned": window,
        "truncated": window < size,
    }
    pe_limit = size if not deep_scan else min(size, window + max(0, deep_bytes))
    embedded = find_embedded_pes(data, pe_limit)
    if embedded:
        result["embedded_pe"] = embedded
    # known generator layouts are read from the raw bytes: they hold for payloads of any size
    frameworks = identify_frameworks(data)
    fw_arch = next((f["arch"] for f in frameworks if f["confidence"] == "identified" and f["arch"] in ("x86", "x64")), None)
    # an encoder wrapping the payload (only when no generator layout claims the buffer)
    encoder = None if fw_arch else identify_encoders(data)
    if encoder:
        fw_arch = encoder["arch"]

    exec_header = None
    weights = {}
    best = None
    islands = []
    regions = []
    if buf[:2] == b"MZ" and b"PE\x00\x00" in buf[:0x400]:
        exec_header = _executable_header(buf, size)
        if exec_header is None:
            result["reason"] = "PE image"

    if result.get("reason"):
        pass
    elif stats["size"] < 5:
        result["reason"] = "too small"
    elif stats["distinct_bytes"] < 4 or (stats["size"] >= 64 and stats["size"] - round(stats["zero_ratio"] * stats["size"]) < 16):
        # judged on non-zero byte count, not ratio: a small stub at the start of
        # a large, mostly zeroed allocation is a normal shape for a dump
        result["reason"] = "padding"
    else:
        if arch == "x86":
            modes = [CS_MODE_32]
        elif arch == "x64" or (va is not None and va > 0xFFFFFFFF):
            modes = [CS_MODE_64]
        elif fw_arch:
            modes = [CS_MODE_64 if fw_arch == "x64" else CS_MODE_32]
        elif exec_header:
            modes = [exec_header[0]] + [m for m in (CS_MODE_32, CS_MODE_64) if m != exec_header[0]]
        else:
            modes = [CS_MODE_32, CS_MODE_64]

        far_by_mode = {}
        for mode in modes:
            extra = [exec_header[2]] if exec_header and exec_header[2] < window else []
            if entry is not None and 0 <= entry < window:
                extra.insert(0, entry)
            r, good, far = _analyse_mode(buf, mode, va, max_insns, max_seeds, opts, extra, extent=size)
            far_by_mode[mode] = far
            for g in good:
                islands.append(_rebase(g, 0))
            _rebase(r, 0)
            if best is None or _rank(r) > _rank(best):
                best = r

        deep = []
        if deep_scan and window < size and deep_windows > 0:
            anchors = []  # (absolute offset, exact entry?)
            for mode in modes:
                anchors.extend((t, True) for t in far_by_mode[mode] if t < size)
            if exec_header and exec_header[2] >= window:
                anchors.insert(0, (exec_header[2], True))
            if buf[:1] == b"\xe8":
                # call over a large blob (Donut instance, MSF-style data): the code is past the window
                t = 5 + int.from_bytes(buf[1:5], "little", signed=True)
                if window <= t < size:
                    anchors.insert(0, (t, True))
            tail = memoryview(data)[window : min(size, window + max(0, deep_bytes))]
            for k, m in enumerate(DEEP_ANCHOR_RE.finditer(tail)):
                if k >= deep_windows * 4:
                    break
                anchors.append((window + m.start(), False))
            seen = []
            for off, exact in anchors:
                if len(deep) >= deep_windows:
                    break
                if any(lo <= off < hi for lo, hi in seen):
                    continue
                lo = off if exact else max(window, off - 1024)
                sub = bytes(memoryview(data)[lo : lo + DEEP_WINDOW_SIZE])
                seen.append((lo, lo + len(sub)))
                win_best = None
                for mode in modes:
                    r, good, _ = _analyse_mode(sub, mode, va, max_insns, max_seeds, opts, [off - lo], extent=size - lo)
                    for g in good:
                        islands.append(_rebase(g, lo))
                    _rebase(r, lo)
                    if win_best is None or _rank(r) > _rank(win_best):
                        win_best = r
                deep.append({"start": hex(lo), "anchor": "branch" if exact else "pattern", "verdict": win_best["verdict"]})
                if _rank(win_best) > _rank(best):
                    best = win_best
                if best["verdict"] == "shellcode" and best["score"] >= 2 * STRONG:
                    break  # confirmed; further windows would only add cost
            result["deep_windows"] = deep

        result.update({k: v for k, v in best.items() if not k.startswith("_")})
        # fold in other islands of the same architecture that carry shellcode traits
        weights = dict(best["_weights"])
        evidence = list(best["evidence"])
        apis = set(best["apis"])
        sockaddrs = list(best["sockaddrs"])
        stack_strings = list(best.get("stack_strings", []))
        for isl in islands:
            if isl is best or isl["arch"] != best["arch"]:
                continue
            for t, w in isl["_weights"].items():
                weights[t] = max(w, weights.get(t, w))
            evidence.extend(e for e in isl["evidence"] if e not in evidence)
            apis.update(isl["apis"])
            sockaddrs.extend(a for a in isl["sockaddrs"] if a not in sockaddrs)
            stack_strings.extend(x for x in isl.get("stack_strings", []) if x not in stack_strings)
        if exec_header:
            weights["executable_pe_header"] = STRONG
            evidence.insert(0, {"offset": hex(exec_header[1]), "indicator": "executable_pe_header",
                                "insn": f"DOS header runs: transfers to {hex(exec_header[2])}"})  # fmt: skip
            if result["verdict"] in ("code", "likely"):
                result["verdict"] = "shellcode"
            elif result["verdict"] in ("data", "trampoline"):
                result["verdict"] = "likely"
        if embedded and ("reflective_pe_loader" in weights or exec_header or "getpc_call_pop" in weights):
            staged = [e for e in embedded if int(e["offset"], 16) > 0 or exec_header]
            if staged:
                weights["staged_pe"] = STRONG
                pe = staged[0]
                evidence.append({"offset": pe["offset"], "indicator": "staged_pe",
                                 "insn": f"{pe['arch']} {'DLL' if pe['dll'] else 'EXE'} image carried by the loader"})  # fmt: skip
        # a loop linked in one island is not also an unlinked candidate from a partial island
        linked_at = {e["offset"] for e in evidence if e["indicator"] == "decoder_stub"}
        evidence = [e for e in evidence if not (e["indicator"] == "decoder_loop" and e["offset"] in linked_at)]
        if "decoder_loop" in weights and not any(e["indicator"] == "decoder_loop" for e in evidence):
            del weights["decoder_loop"]
        regions.extend(best.get("regions", ()))
        for isl in islands:
            if isl is not best and isl["arch"] == best["arch"]:
                regions.extend(isl.get("regions", ()))

        # a copy of ntdll's syscall stubs (unhooking) is ntdll's code, not shellcode traits
        nt = find_ntdll_copy(buf) if best["arch"] == "x64" else None
        copies = None if nt or best["arch"] != "x64" else find_stub_copies(buf)
        stub_tags = ("direct_syscall", "indirect_syscall", "syscall_insn", "int2e_syscall", "kuser_shared_data")
        if copies:
            # nothing but ntdll's own stub code: no shellcode traits of its own
            evidence = [e for e in evidence if e["indicator"] not in stub_tags]
            for t in stub_tags:
                weights.pop(t, None)
            ssns = ", ".join(f"{v:#x}" for v in copies[:8])
            weights["syscall_stub_copy"] = INFO
            evidence.append(
                {
                    "offset": "0x0",
                    "indicator": "syscall_stub_copy",
                    "insn": f"{len(copies)} stub{'s' if len(copies) > 1 else ''}, SSN {ssns}",
                }
            )
            if not any(w >= MEDIUM for t, w in weights.items() if t not in UNSCORED):
                result["verdict"] = "image"
                result["reason"] = f"copy of ntdll syscall stub{'s' if len(copies) > 1 else ''} (SSN {ssns})"
        if nt:
            lo, hi, count = nt

            def in_copy(e):
                return e["indicator"] in stub_tags and lo <= int(e["offset"], 16) < hi

            evidence = [e for e in evidence if not in_copy(e)]
            for t in stub_tags:
                if t in weights and not any(e["indicator"] == t for e in evidence):
                    del weights[t]
            weights["ntdll_copy"] = INFO
            evidence.append({"offset": hex(lo), "indicator": "ntdll_copy", "insn": f"{count} syscall stubs at {lo:#x}-{hi:#x}"})
            if not any(w >= MEDIUM for t, w in weights.items() if t not in UNSCORED):
                result["verdict"] = "image"
                result["reason"] = "copy of ntdll's syscall stubs (unhooking)"
        # mapped image whose headers were wiped: its import names are still there
        names = None if exec_header else find_import_names(buf, embedded)
        # an embedded PE in file layout (carried by a loader) is not a mapped image: no .pdata search then
        pdata = None if exec_header or embedded or fw_arch or (names and names[1] >= 8) else find_pdata(data)
        if (names and names[1] >= 8) or pdata:
            weights["mapped_image"] = INFO
            what = (
                f"{names[1]} import hint/name entries"
                if not pdata
                else f"x64 exception table (.pdata): {pdata[1]} RUNTIME_FUNCTION entries"
            )
            evidence.append({"offset": hex(names[0] if not pdata else pdata[0]), "indicator": "mapped_image", "insn": what})
            if not LINKED & {t for t, w in weights.items() if w >= STRONG}:
                result["verdict"] = "image"
                result["reason"] = "mapped PE image with its headers wiped"
        result["score"] = sum(w for t, w in weights.items() if t not in UNSCORED)
        result["evidence"] = _cap_evidence(evidence)
        result["stack_strings"] = stack_strings[:20]
        result["sockaddrs"] = sockaddrs
        result["apis"] = sorted(apis)

    block_api = find_block_api(buf)
    if block_api:
        weights["block_api_prologue"] = STRONG
        result["evidence"] = result.get("evidence", []) + [
            {
                "offset": hex(block_api[0]),
                "indicator": "block_api_prologue",
                "insn": f"classic Metasploit {block_api[1]} block_api prologue",
            }
        ]
        if result["verdict"] in ("likely", "code"):
            result["verdict"] = "shellcode"
    if frameworks:
        result["frameworks"] = [
            {k: v for k, v in f.items() if k not in ("regions", "iocs") and not k.startswith("_")} for f in frameworks
        ]
        identified = [f for f in frameworks if f["confidence"] == "identified"]
        for f in identified:
            regions.extend(f["regions"])
            weights["framework_layout"] = STRONG
            at = f["regions"][0]["start"] if f["regions"] else 0
            summary = ", ".join(f"{k}: {v}" for k, v in f["details"].items() if k in ("payload", "staging_url", "instance"))
            result["evidence"] = result.get("evidence", []) + [
                {"offset": hex(at), "indicator": "framework_layout", "insn": f"{f['name']}" + (f" ({summary})" if summary else "")}
            ]
        if identified:
            # the generator's own layout proves this is its shellcode, whatever was reached by descent
            result["verdict"] = "shellcode"
            result.pop("reason", None)
            result.setdefault("arch", identified[0]["arch"] if identified[0]["arch"] in ("x86", "x64") else None)
    if encoder:
        # the generic loop decoder may have found the same stub: the encoder's own region replaces it
        regions = [g for g in regions if g["start"] != encoder["region"]["start"]]
        regions.append(encoder["region"])
        tag = encoder["tag"]
        weights[tag] = STRONG
        summary = f"{encoder['name']}: {encoder['how']}" + (f"; decodes to {encoder['what']}" if encoder["payload"] else "")
        result["evidence"] = result.get("evidence", []) + [{"offset": hex(encoder["stub"]), "indicator": tag, "insn": summary}]
        result["encoder"] = {"name": encoder["name"], "arch": encoder["arch"], "layers": encoder["layers"],
                             "payload": encoder["what"] if encoder["payload"] else None, "payload_size": len(encoder["payload"])}  # fmt: skip
        if encoder["found"]:
            result["encoder"]["payload_indicators"] = ", ".join(encoder["found"])
        # the proven stub makes this shellcode, whatever descent reached
        result["verdict"] = "shellcode"
        result.pop("reason", None)
        result.setdefault("arch", encoder["arch"])
    if extract_payloads:
        result["_payloads"] = _collect_payloads(frameworks, regions, encoder)
    if regions:
        result["regions"] = _format_regions(regions)
    if embedded:
        weights.setdefault("embedded_pe", WEAK)
        result["evidence"] = result.get("evidence", []) + [
            {
                "offset": pe["offset"],
                "indicator": "embedded_pe",
                "insn": f"{pe['arch']} {'DLL' if pe['dll'] else 'EXE'}, NT header at {pe['nt_offset']}",
            }
            for pe in embedded
        ]

    # strings / IOCs are cheap and useful even when the blob is not code (configs)
    if extract_iocs:
        iocs, string_apis, clr_hints = extract_iocs_fn(buf, result.get("stack_strings", ()), result.get("sockaddrs", ()))
        if iocs:
            result["iocs"] = iocs
        apis = set(result.get("apis", ())) | string_apis
        if apis:
            result["apis"] = sorted(apis)
        unhook = [v for v in iocs.get("paths", []) if "knowndlls" in v.lower() or v.lower().endswith("\\ntdll.dll")]
        if unhook and result["verdict"] != "data":
            weights["unhooking_string"] = MEDIUM
            pos = max(buf.find(unhook[0].encode("latin-1", "ignore")), buf.find(unhook[0].encode("utf-16le")), 0)
            result["evidence"].append({"offset": hex(pos), "indicator": "unhooking_string", "insn": unhook[0]})
    stager = find_http_stager(buf) if result["verdict"] in ("shellcode", "likely") else None
    if stager:
        weights["http_stager_config"] = INFO
        result["evidence"] = result.get("evidence", []) + [
            {
                "offset": "0x0",
                "indicator": "http_stager_config",
                "insn": stager["url"] + (f"  UA: {stager['user_agent']}" if "user_agent" in stager else ""),
            }
        ]
        found = {"urls": [stager["url"]]} | ({"user_agents": [stager["user_agent"]]} if "user_agent" in stager else {})
        for cat, values in found.items():
            got = result.setdefault("iocs", {}).setdefault(cat, [])
            got.extend(v for v in values if v not in got)
    for f in frameworks:
        for cat, values in f.get("iocs", {}).items():
            got = result.setdefault("iocs", {}).setdefault(cat, [])
            got.extend(v for v in values if v not in got)
    caps = _capabilities(set(result.get("apis", ())), clr_hints if extract_iocs else ())
    if caps:
        result["capabilities"] = caps

    result["tags"] = sorted(weights, key=lambda k: (-weights[k], k))
    result["score"] = sum(w for t, w in weights.items() if t not in UNSCORED)
    result["evidence"] = _cap_evidence(result.get("evidence", []))
    by_tag = {}
    for e in result["evidence"]:
        by_tag.setdefault(e["indicator"], []).append(e["offset"])
    first = {}
    for e in result["evidence"]:
        first.setdefault(e["indicator"], e["insn"])
    result["indicators"] = [
        {
            "name": t,
            "group": INDICATORS[t][0],
            "confidence": CONFIDENCE[weights[t]],
            "scored": t not in UNSCORED and weights[t] > INFO,
            "description": INDICATORS[t][1],
            # what this instance found (walk stages, decoded range, ...)
            "detail": first.get(t, "") if t in DETAILED else "",
            "offsets": by_tag.get(t, [])[:8],
        }
        for t in result["tags"]
    ]
    result["time_ms"] = round((default_timer() - start) * 1000, 2)
    return result


def main(argv=None):  # pragma: no cover - CLI helper for corpus validation
    import argparse
    import json
    import os

    p = argparse.ArgumentParser(description="CAPE shellcode confirmation heuristics")
    p.add_argument("paths", nargs="+", help="files or directories (e.g. storage/analyses/*/CAPE)")
    p.add_argument("--va", help="region virtual address hint")
    p.add_argument("--arch", choices=["x86", "x64"])
    p.add_argument("--json", action="store_true")
    p.add_argument("--max-scan", type=int, default=MAX_SCAN_DEFAULT, help="head window in bytes (0 = whole file)")
    p.add_argument("--max-insns", type=int, default=MAX_INSNS_DEFAULT, help="instruction budget per island")
    p.add_argument("--no-deep", action="store_true", help="do not follow code past the head window")
    a = p.parse_args(argv)
    files = []
    for path in a.paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                files.extend(os.path.join(root, f) for f in names if not f.endswith((".json", ".yar")))
        else:
            files.append(path)
    for f in files:
        with open(f, "rb") as fh:
            r = analyse(fh.read(), va=a.va, arch=a.arch, max_scan=a.max_scan, max_insns=a.max_insns, deep_scan=not a.no_deep)
            if not a.json and r.get("iocs"):
                r["tags"] = r["tags"] + [f"{k}={len(v)}" for k, v in r["iocs"].items()]
        if a.json:
            print(json.dumps({"file": f, **r}))
        else:
            print(
                f"{r['verdict']:<10} {r.get('arch', '-'):<4} score={r['score']:<3} {r['time_ms']:>7}ms  {','.join(r['tags'])}  {f}"
            )


if __name__ == "__main__":  # pragma: no cover
    main()
