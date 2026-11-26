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
from collections import Counter, deque
from timeit import default_timer

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    HAVE_CAPSTONE = True
except ImportError:  # pragma: no cover
    HAVE_CAPSTONE = False

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
    "image_base": "Finding a module's base without the loader lists: backward scans for the MZ header, the SEH chain's last handler, kernel entry points",
    "self_modifying": "Code that rewrites its own instructions",
    "stager_api": "Stage API combinations the code resolves itself (by hash or stack string): sockets, HTTP download, download-and-execute, call-stack spoofing",
    "exceptions": "Exception-driven control flow: SEH frames and vectored handlers set up by the code, handlers that move the saved instruction pointer",
    "patching": "In-memory function patching (AMSI/ETW/WLDP) and AMSI context corruption",
    "kernel": "Kernel-mode payload constructs (token stealing)",
    "anti_analysis": "Anti-debug, anti-VM, timing and KUSER_SHARED_DATA checks",
    "network": "Literal sockaddr_in (IP:port) of bind/reverse shells, and HTTP(S) stager configuration",
    "framework": "Output layout of known shellcode generators, matched exactly",
    "injection": "Injector-built stubs that call API addresses inside the target process",
    "layout": "Layout and origin hints (stack alignment, position dependence, JIT/compiled code)",
    "crypto": "Cipher, hash and encoding primitives (AES, RC4, ChaCha/Salsa, TEA/XTEA, MD5/SHA, Base64, Windows crypto APIs): supporting weight only, in shellcode",
    "api_sets": "API combinations the code resolves itself (by hash or stack string), not names lying in data",
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
    "speck_hash": ("api_hashing", "Speck ARX round (ror 8 / rol 3) in a loop: Speck-based API hashing or decryption"),
    "getpc_call_pop": ("getpc", "call $+5; pop - obtains its own address"),
    "getpc_jmp_call_pop": ("getpc", "jmp/call/pop - obtains the address of trailing data"),
    "getpc_call4": ("getpc", "call $+4 (e8 ff ff ff ff) into its own last byte, then pop - obtains its own address"),
    "getpc_fnstenv": ("getpc", "fnstenv [esp-0xc] - obtains EIP via the FPU environment"),
    "getpc_self_base": ("getpc", "Computes its own start address (call/pop then -5), typical of loader bootstraps"),
    "getpc_call_over_data": (
        "getpc",
        "call forward over embedded data/code, then pop - obtains its address (e.g. a Donut instance or MSF block_api)",
    ),
    "decoder_loop": ("decoders", "Loop with a decoder's shape whose pointer is not tied to the blob"),
    "decoder_stub": ("decoders", "Decoder loop whose pointer comes from GetPC/RIP: it decodes bytes of the blob itself"),
    "decoded_payload": ("decoders", "Linked decoder's region decoded statically: gives a PE, code or text (exact range)"),
    "fpu_getpc_decoder": (
        "decoders",
        "FPU instruction + fnstenv [esp-0xc] GetPC: the stub of an FPU GetPC decoder (e.g. Shikata Ga Nai, fnstenv_mov, alpha_mixed)",
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
        "Exact output layout of a known shellcode generator, proven by its framework module; see Frameworks",
    ),
    "block_api_prologue": (
        "api_hashing",
        "Classic Metasploit block_api resolver prologue. Shared public code (also Cobalt Strike stagers and others), "
        "so not an attribution; current Metasploit shuffles this code",
    ),
    "rc4_ksa": (
        "decoders",
        "RC4 key schedule (256-entry S-box init + swap loop): medium next to a linked decoder, else supporting weight in shellcode",
    ),
    "aplib_depacker": ("decoders", "aPLib depacker (cld; mov dl, 0x80; ...; movsb; mov bl, 2): unpacks a compressed payload"),
    "chaskey_cipher": ("decoders", "Chaskey ARX rotations (5/7/8/13/16): Chaskey-based decryption"),
    "direct_syscall": ("syscalls", "mov r10, rcx; mov eax, SSN; syscall - bypasses user-mode hooks"),
    "indirect_syscall": ("syscalls", "mov r10, rcx; mov eax, SSN; jmp into ntdll's syscall gadget"),
    "syscall_insn": ("syscalls", "Executes syscall/sysenter directly"),
    "syscall_stub_scan": ("syscalls", "Reads syscall numbers out of ntdll stubs (e.g. Hell's/Halo's Gate)"),
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
    "executable_pe_header": ("pe_loader", "DOS header is executable and jumps to a loader (e.g. pe2shc)"),
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
    "aes_ni": ("crypto", "AES-NI round instructions (aesdec/aesenc...): an AES decrypt of a payload or config"),
    "chacha_constants": ("crypto", "ChaCha/Salsa20 constants ('expand 32-byte k') as immediates or a stack string"),
    "tea_delta": ("crypto", "TEA/XTEA round: the 0x9e3779b9 delta added to a sum, with the shift-by-4/5 mixing"),
    "rc4_systemfunction": ("crypto", "Resolves SystemFunction032/033 (advapi32 RC4), used to mask or decrypt memory"),
    "aes_tables": ("crypto", "Software AES tables carried in the blob (S-box, inverse S-box, T-table or round constants)"),
    "digest_constants": (
        "crypto",
        "MD5/SHA-1/SHA-256 constants or a CRC32 table: hashing, e.g. to derive a key or hash names",
    ),
    "base64_alphabet": ("crypto", "Base64 alphabet carried in the blob or built on the stack: Base64 decoding"),
    "crypto_api": (
        "crypto",
        "Resolves Windows crypto APIs itself (CryptDecrypt, BCryptDecrypt, CryptStringToBinary...): decrypts or decodes data",
    ),
    "pe_custom_magic": (
        "pe_loader",
        "After e_lfanew, compares the NT header signature with something other than 'PE' (a custom magic, "
        "e.g. Cobalt Strike magic_pe) and then reads header fields",
    ),
    "remote_injection": (
        "api_sets",
        "Resolves a remote write primitive and a remote execution primitive (VirtualAllocEx/WriteProcessMemory/"
        "NtMapViewOfSection with CreateRemoteThread/NtQueueApcThread/SetThreadContext...)",
    ),
    "sleep_obfuscation": (
        "api_sets",
        "Resolves the pieces of a sleep-masking chain (e.g. Ekko/Foliage): two of a timer or wait trigger, "
        "a context switch (NtContinue/RtlCaptureContext) and RC4 memory masking (SystemFunction032/033)",
    ),
    "chained_blocks": (
        "layout",
        "Blocks chained by jmps and laid out of order (control-flow obfuscation); the indicators were matched in execution order",
    ),
    "nop_sled": ("layout", "A NOP sled (a long run of one-byte no-ops or one repeated filler byte) leads into the code"),
    "seh_handler_install": (
        "exceptions",
        "Installs an SEH frame (fs:[0]) whose handler is inside the blob (from GetPC, a call's return address, or the region's own base)",
    ),
    "exception_context_rewrite": (
        "exceptions",
        "Exception handler changes the saved instruction pointer (CONTEXT.Eip/Rip) so execution resumes somewhere else: it "
        "checks the exception code or returns 'continue execution', or the code takes its address",
    ),
    "exception_control_flow": (
        "exceptions",
        "The code takes the address of a handler in the blob and that handler moves CONTEXT.Eip/Rip: control flow driven by exceptions",
    ),
    "exception_trigger": ("exceptions", "Raises an exception on purpose (int3, ud2, int 0x2d...) right after installing a handler"),
    "exception_handler_api": (
        "exceptions",
        "Resolves AddVectoredExceptionHandler / RtlAddVectoredExceptionHandler / SetUnhandledExceptionFilter itself (hash or stack string)",
    ),
    "image_base_scan": (
        "image_base",
        "Walks backwards from an address, a page or 64 KB at a time, until it finds 'MZ': locates the base of the image that address is in",
    ),
    "seh_chain_walk": (
        "image_base",
        "Follows the SEH chain (fs:[0]) to its last frame (-1), whose handler is inside kernel32/ntdll: medium when a scan back to 'MZ' follows",
    ),
    "kernel_msr_read": ("kernel", "Reads the LSTAR / SYSENTER_EIP MSR: the kernel's system-call entry point (kernel-mode payload)"),
    "kernel_base_discovery": (
        "kernel",
        "Kernel payload: takes a kernel address (system-call entry MSR, or the IDT from the KPCR) and scans back to the kernel image's 'MZ'",
    ),
    "self_modifying_code": (
        "self_modifying",
        "Writes into its own instructions (RIP-relative or through a GetPC pointer), with code all the way from the write to its target",
    ),
    "vmware_backdoor": ("anti_analysis", "VMware backdoor I/O port check: eax = 'VMXh', in eax, dx"),
    "red_pill": ("anti_analysis", "Stores a descriptor table register (sidt/sgdt/sldt/str): virtual machine check"),
    "trap_flag": (
        "exceptions",
        "Sets the trap flag in the saved flags (pushf; or [sp], 0x100; popf): single-step exception on the next instruction",
    ),
    "exception_directory_walk": (
        "syscalls",
        "Walks ntdll's exception directory (RUNTIME_FUNCTION entries): ranks syscall stubs without reading them",
    ),
    "kernel_callback_table": ("peb_walk", "Reads PEB.KernelCallbackTable: user32 callback pointers that can be redirected"),
    "process_parameters_write": (
        "peb_walk",
        "Overwrites PEB.ProcessParameters strings (image path / command line): process masquerading",
    ),
    "rwx_alloc_args": ("layout", "Sets up an allocation call with MEM_COMMIT(|RESERVE) and PAGE_EXECUTE_READWRITE"),
    "printable_code": (
        "decoders",
        "Clean code made only of printable bytes that rewrites memory: an alphanumeric / printable encoder stub",
    ),
    "socket_stager": ("stager_api", "Resolves a socket channel: socket + connect + recv, or bind + listen + accept"),
    "http_stager": ("stager_api", "Resolves an HTTP download chain (WinINet or WinHTTP: open, connect/open URL, read)"),
    "download_execute": ("stager_api", "Resolves URLDownloadToFile with WinExec / CreateProcess / ShellExecute"),
    "stack_spoofing": (
        "stager_api",
        "Resolves BaseThreadInitThunk / RtlUserThreadStart (with RtlLookupFunctionEntry / RtlVirtualUnwind): builds a fake call stack",
    ),
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
# Privileged or legacy instructions are noise in user-mode code, except where the code sets them up
# on purpose: an MSR read (kernel payloads find the kernel through LSTAR / SYSENTER_EIP), the
# VMware backdoor port, and descriptor-table stores (red pill)
_MSRS = {0xC0000082: "LSTAR", 0x176: "SYSENTER_EIP", 0x174: "SYSENTER_CS", 0x175: "SYSENTER_ESP", 0xC0000080: "EFER",
         0xC0000081: "STAR", 0xC0000101: "GS_BASE", 0xC0000102: "KERNEL_GS_BASE"}  # fmt: skip
VMWARE_MAGIC = "eax, 0x564d5868"  # 'VMXh'


def _deliberate(mn, op, recent):
    """A rare instruction the code prepared for (recent: the (mnemonic, operands) just before it)."""
    if mn in ("rdmsr", "wrmsr"):
        return any(m == "mov" and o.startswith("ecx, ") and _imm(o[5:]) in _MSRS for m, o in recent)
    if mn == "in":
        return op == "eax, dx" and any(m == "mov" and o == VMWARE_MAGIC for m, o in recent)
    if mn in ("sidt", "sgdt"):
        return "sp" in op or "bp" in op  # stored to a stack slot and read back
    if mn == "sldt":
        return op in _REG_CANON
    return False


# jcc pairs that between them always branch: 'jz X' directly followed by 'jnz X' is a jmp X
_COMPLEMENT = {}
for _a, _b in (
    ("je", "jne"),
    ("ja", "jbe"),
    ("jae", "jb"),
    ("jg", "jle"),
    ("jge", "jl"),
    ("jo", "jno"),
    ("jp", "jnp"),
    ("js", "jns"),
):
    _COMPLEMENT[_a], _COMPLEMENT[_b] = _b, _a
# prefixes capstone folds into the mnemonic: CET (notrack), MPX (bnd), and the AMD 'rep ret' idiom
_BRANCH_PREFIXES = frozenset({"notrack", "bnd"})
_RET_PREFIXES = frozenset({"rep", "repz", "repe", "repne", "repnz"})
# a string (ASCII or UTF-16, NUL-terminated) placed after a call that passes its address
_INLINE_STRING = re.compile(rb"[\x09\x0a\x0d\x20-\x7e\x00]*(?:[A-Za-z0-9]\x00?){4}[\x09\x0a\x0d\x20-\x7e\x00]*\x00")
_RIP_OPERAND = re.compile(r"\[rip(?: ([+-]) (0x[0-9a-f]+|\d+))?\]")
# NOP sleds: long runs of one-byte instructions with no lasting effect, or of one repeated byte
# that decodes as a harmless instruction (heap-spray 0x0c0c0c0c: or al, 0xc). They only nominate
# where code may start; a sled never scores on its own.
SLED_MIN = 64
_SLED_REPEATS = rb"\x0a{%d,}|\x0c{%d,}|\x0d{%d,}|(?:\x66\x90){%d,}" % (SLED_MIN, SLED_MIN, SLED_MIN, SLED_MIN // 2)
SLED_RE = {
    # x86: inc/dec r32, xchg eax, r32 (not esp), cwde/cdq, wait, sahf/lahf, cmc/clc/stc/cld/std, daa/das/aaa/aas, salc
    False: re.compile(
        rb"[\x27\x2f\x37\x3f\x40-\x4f\x90-\x93\x95-\x99\x9b\x9e\x9f\xd6\xf5\xf8\xf9\xfc\xfd]{%d,}|" % SLED_MIN + _SLED_REPEATS
    ),
    # x64: 0x40-0x4f are REX prefixes and the BCD opcodes are invalid
    True: re.compile(rb"[\x90\x98\x99\x9b\x9e\x9f\xf5\xf8\xf9\xfc\xfd]{%d,}|" % SLED_MIN + _SLED_REPEATS),
}
MAX_SLEDS = 16
# NTSTATUS codes a handler tests for: breakpoint, single step, guard page, access violation, illegal
# instruction, divide by zero, privileged instruction
_EXCEPTION_CODES = frozenset({0x80000003, 0x80000004, 0x80000001, 0xC0000005, 0xC000001D, 0xC0000094, 0xC0000096})
_EXCEPTION_APIS = frozenset({"AddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler", "SetUnhandledExceptionFilter"})
_SELF_WRITES = frozenset("mov xor add sub or and not neg inc dec".split())
HANDLER_SPAN = 0x100  # a handler's CONTEXT write sits this close to its entry
LOADER_SPAN = 0x2000  # the stages of one PE loader sit together; further apart they are unrelated functions
# jmp-chained code (every block ends in a jmp to the next, blocks shuffled): scanned again in execution order
CHAINED_MIN_JMPS = 8
CHAINED_JMP_RATIO = 0.12
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
        "Process32First Process32Next AddVectoredExceptionHandler BaseThreadInitThunk RtlLookupFunctionEntry RtlVirtualUnwind"
    ),
    "ntdll.dll": (
        "RtlUserThreadStart NtAllocateVirtualMemory NtProtectVirtualMemory NtWriteVirtualMemory NtCreateThreadEx NtMapViewOfSection "
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
    "advapi32.dll": (
        "RegOpenKeyExA RegSetValueExA CryptAcquireContextA CryptAcquireContextW CryptImportKey CryptDeriveKey "
        "CryptCreateHash CryptHashData CryptDecrypt CryptEncrypt CryptDestroyKey SystemFunction032 SystemFunction033 "
        "OpenProcessToken"
    ),
    "crypt32.dll": "CryptStringToBinaryA CryptStringToBinaryW CryptUnprotectData",
    "bcrypt.dll": (
        "BCryptOpenAlgorithmProvider BCryptSetProperty BCryptGenerateSymmetricKey BCryptImportKey BCryptDecrypt "
        "BCryptEncrypt BCryptCreateHash BCryptHashData"
    ),
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


def _imm(text):
    """An immediate operand's value; cheap for the register and memory operands that are not."""
    return _parse_int(text) if text and (text[0].isdigit() or text[0] == "-") else None


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


_REG_BITS = {r: _reg_bits(r) for r in _REG_CANON}


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


STACK_STRING_MIN = 6  # ASCII characters
WIDE_STRING_MIN = 5  # UTF-16 characters
_SIMD_LOADS = frozenset("movdqa movdqu movaps movups lddqu vmovdqa vmovdqu vmovaps vmovups vlddqu".split())
_SIMD_XORS = frozenset("pxor xorps xorpd vpxor vxorps vxorpd".split())
_FOLD = frozenset("xor add sub and or rol ror shl shr".split())
_REG_TRACK_MNS = frozenset("mov movabs lea xor xchg xadd cmpxchg".split())


def _clobber_table():
    """Registers written implicitly (not named as the destination operand)."""
    table = {}
    for mn, regs in {"mul": "a d", "imul": "a d", "div": "a d", "idiv": "a d", "cdq": "d", "cqo": "d", "cwd": "d",
                     "cdqe": "a", "cwde": "a", "cbw": "a", "rdtsc": "a d", "rdtscp": "a c d", "cpuid": "a b c d",
                     "syscall": "a c r11", "sysenter": "a c d", "int": "a", "xlatb": "a", "loop": "c", "loope": "c",
                     "loopne": "c", "cmpxchg": "a"}.items():  # fmt: skip
        table[mn] = tuple(regs.split())
    for op, regs in {"lods": "a si", "stos": "di", "movs": "si di", "scas": "di", "cmps": "si di"}.items():
        for w in "bwdq":
            table[op + w] = tuple(regs.split())
            for prefix in ("rep", "repe", "repne"):
                table[f"{prefix} {op}{w}"] = tuple(regs.split()) + ("c",)
    return table


_CLOBBERS = _clobber_table()
_STRING_PUNCT = frozenset(" ._-\\/:%$@#,()[]{}=+&?!'\"~;*<>|^`")
_SP = _canon("rsp")
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_WIDE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % WIDE_STRING_MIN)


def _texty(text):
    """Reads as a name, path, URL or sentence: mostly letters, digits and ordinary punctuation (at
    least two letters, for ws2_32), and no five-character runs of one character (xor keys, padding)."""
    if sum(c.isalpha() for c in text) < 2 or sum(c.isalnum() for c in text) < 0.5 * len(text):
        return False
    if sum(c.isalnum() or c in _STRING_PUNCT for c in text) < 0.85 * len(text):
        return False
    return not re.search(r"(.)\1{4}", text)


def _strings_in(data):
    """[(index, text, wide)]: ASCII and UTF-16LE strings in stack bytes, split at NULs."""
    out = [(m.start(), m.group().decode("ascii"), False) for m in _ASCII_RUN.finditer(data)]
    out = [o for o in out if len(o[1]) >= STACK_STRING_MIN or o[1].lower() in _API_NAMES]  # Sleep, send
    out += [(m.start(), m.group().decode("utf-16le"), True) for m in _WIDE_RUN.finditer(data)]
    return [(at, text, wide) for at, text, wide in sorted(out) if _texty(text)]


_API_EXACT = frozenset(_API_NAMES.values())
_AES_MNS = frozenset("aesdec aesdeclast aesenc aesenclast aesimc aeskeygenassist".split())
# ChaCha/Salsa20 sigma/tau: "expand 32-byte k" / "expand 16-byte k"
_CHACHA_WORDS = {
    0x61707865: "expa",
    0x3320646E: "nd 3",
    0x79622D32: "2-by",
    0x6B206574: "te k",
    0x3120646E: "nd 1",
    0x79622D36: "6-by",
}
_TEA_DELTAS = {0x9E3779B9: "0x9e3779b9", 0x61C88647: "-0x9e3779b9", 0xC6EF3720: "0x9e3779b9 * 32", 0x8DDE6E40: "0x9e3779b9 * 64"}
# MD5 / SHA-1 / SHA-256 initial values and first round constants, as 32-bit immediates
_DIGEST_WORDS = {
    **dict.fromkeys((0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476), "MD5/SHA-1"),
    0xC3D2E1F0: "SHA-1",
    **dict.fromkeys((0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE), "MD5"),
    **dict.fromkeys(
        (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
         0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5),
        "SHA-256",
    ),
}  # fmt: skip
# Tables carried as data: (tag, what, leading bytes). Matches inside an embedded PE are the PE's own.
_CRYPTO_TABLES = (
    ("aes_tables", "AES S-box", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("aes_tables", "AES inverse S-box", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("aes_tables", "AES T-table (Te0)", bytes.fromhex("a56363c6847c7cf8997777ee8d7b7bf6")),
    ("aes_tables", "AES round constants", bytes.fromhex("01020408102040801b36")),
    ("digest_constants", "SHA-256 round constants", bytes.fromhex("982f8a4291443771cffbc0b5a5dbb5e9")),
    ("digest_constants", "SHA-256 initial values", bytes.fromhex("67e6096a85ae67bb72f36e3c3af54fa5")),
    ("digest_constants", "MD5/SHA-1 initial values", bytes.fromhex("0123456789abcdeffedcba9876543210")),
    ("digest_constants", "MD5 round constants", bytes.fromhex("78a46ad756b7c7e8db702024eecebdc1")),
    ("digest_constants", "CRC32 table", bytes.fromhex("0000000096300777") + bytes.fromhex("2c610eeeba510999")),
    ("base64_alphabet", "Base64 alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
)
_CRYPTO_APIS = frozenset(
    "CryptAcquireContextA CryptAcquireContextW CryptImportKey CryptDeriveKey CryptCreateHash CryptHashData "
    "CryptDecrypt CryptEncrypt CryptStringToBinaryA CryptStringToBinaryW CryptUnprotectData "
    "BCryptOpenAlgorithmProvider BCryptSetProperty BCryptGenerateSymmetricKey BCryptImportKey BCryptDecrypt "
    "BCryptEncrypt BCryptCreateHash BCryptHashData".split()
)
# Recorded as INFO by the code scan; supporting weight (WEAK) only once the blob is shellcode on other
# evidence, dropped otherwise (crypto libraries and compiled code use all of them)
CIPHER_TAGS = ("aes_ni", "chacha_constants", "tea_delta", "rc4_systemfunction", "rc4_ksa", "digest_constants")
# Short patterns that can occur by coincidence: recorded as INFO, supporting weight once the blob is shellcode
SUPPORT_TAGS = ("red_pill", "trap_flag", "exception_directory_walk", "kernel_callback_table", "process_parameters_write",
                "rwx_alloc_args", "seh_chain_walk")  # fmt: skip
MZ_SCAN_BODY = 24  # instructions in a backward MZ scan loop


def _crypto_tables(data, embedded, regions):
    """[(tag, what, offset)]: cipher/digest tables and the Base64 alphabet carried in the blob,
    outside embedded PE images (a carried DLL's own tables are not the shellcode's)."""
    skip = []
    for pe in embedded or ():
        lo = int(pe["offset"], 16)
        size = max(
            int(pe.get("size_of_image", "0x0"), 16), _pe_raw_size(data, lo + int(pe.get("nt_offset", "0x0"), 16)) or 0, 0x1000
        )
        skip.append((lo, lo + size))
    skip += [(g["start"], g["start"] + (g.get("size") or 0)) for g in regions if g.get("result_type") == "pe"]
    found = {}
    for tag, what, pattern in _CRYPTO_TABLES:
        at = data.find(pattern)
        while at != -1 and any(lo <= at < hi for lo, hi in skip):
            at = data.find(pattern, at + 1)
        if at != -1:
            found.setdefault(tag, []).append((what, at))
    return [(tag, ", ".join(w for w, _ in hits), min(a for _, a in hits)) for tag, hits in found.items()]


def _split_api_names(text):
    """Counted (ANSI_STRING) names laid end to end without NULs, 'VirtualAllocLoadLibraryA':
    the API names, when the whole run is made of them; otherwise None."""
    if len(text) < 10 or text.lower() in _API_NAMES:
        return None
    best = {0: []}
    for start in range(len(text)):
        if start not in best:
            continue
        for end in range(start + 4, min(len(text), start + 48) + 1):
            if end not in best and text[start:end] in _API_EXACT:
                best[end] = best[start] + [text[start:end]]
    parts = best.get(len(text))
    return parts if parts and len(parts) > 1 else None


def _apply_feedback(data, width, op, key, feedback):
    """Decoder whose key changes with every element: element = cipher op key, then the key is
    updated from the plaintext, the ciphertext or a constant. feedback: (source, update op, constant)."""
    source, update, const = feedback
    mask = (1 << 8 * width) - 1
    bits = 8 * width
    out = bytearray()
    for i in range(0, len(data) - width + 1, width):
        c = int.from_bytes(data[i : i + width], "little")
        p = c ^ key if op == "xor" else (c + key) & mask if op == "add" else (c - key) & mask
        out += p.to_bytes(width, "little")
        v = p if source == "plain" else c if source == "cipher" else const
        if update == "mov":
            key = v
        elif update == "xor":
            key ^= v
        elif update == "add":
            key = (key + v) & mask
        elif update == "sub":
            key = (key - v) & mask
        elif update == "rol":
            key = ((key << v % bits) | (key >> (bits - v % bits))) & mask
        elif update == "ror":
            key = ((key >> v % bits) | (key << (bits - v % bits))) & mask
    return bytes(out) + bytes(data[len(out) :])


def _apply_key_table(data, op, key, first):
    """Byte decoder with a repeating key table: data[j] op= key[(first + j) % len(key)]."""
    n = len(key)
    stream = (key[first % n :] + key[: first % n]) * (len(data) // n + 1)
    if op == "xor":
        return (int.from_bytes(data, "little") ^ int.from_bytes(stream[: len(data)], "little")).to_bytes(len(data), "little")
    sign = 1 if op == "add" else -1
    return bytes((b + sign * k) & 0xFF for b, k in zip(data, stream))


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

    def __init__(self, buf, mode, max_insns, extent=None, sleds=()):
        self.buf = buf
        self.n = len(buf)
        self.is64 = mode == CS_MODE_64
        self.sleds = sleds  # sorted (start, end) NOP sleds: never decoded, entered at their end
        self.junk = set()  # instructions that run straight into bytes that do not decode: not code
        self.getpc = {}  # offset of a pop reached by a call -> the return address it receives
        self.entry = None
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

    def _past_sled(self, off):
        """off, or the end of the sled it lies in."""
        i = bisect.bisect_right(self.sleds, (off, self.n + 1)) - 1
        if i >= 0 and self.sleds[i][0] <= off < self.sleds[i][1]:
            return self.sleds[i][1]
        return off

    def run(self, entries):
        work = list(dict.fromkeys(entries))
        self.entry = (self._past_sled(work[0]) if self.sleds else work[0]) if work else None
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
            if self.sleds:
                start = self._past_sled(start)
            if start in self.insns or not 0 <= start < self.n:
                continue
            self.paths += 1
            self._walk(start, work)

    def _looks_like_code(self, start, limit=48):
        """Trial linear decode: a clean run to a terminator, no legacy opcodes."""
        k = -1
        core = 0
        recent = deque(maxlen=6)
        for k, (_, _, mn, op) in enumerate(self.md.disasm_lite(self.buf[start : start + 512], start, limit)):
            if (
                (mn in RARE_MNEMONICS and not _deliberate(mn, op, recent))
                or mn in FAR_TRANSFERS
                or (mn == "add" and op.endswith("], al"))
            ):
                return False
            recent.append((mn, op))
            core += mn in CORE_MNEMONICS or mn in COND_BRANCHES
            if mn in TERMINATORS:
                return k >= 2
        # no terminator yet, but a long clean run of ordinary instructions is code
        return k + 1 >= limit and core >= 0.7 * limit

    def _walk(self, start, work):
        off = start
        padding_run = 0
        gate = 0  # instructions left in which a far return counts as heaven's gate
        tail = None  # instructions since the last branch: junk if they run into undecodable bytes
        # (not from the entry itself: a decoder stub runs straight into what it has yet to decode)
        prev_cond = None  # (mnemonic, target, end offset) of the conditional branch just decoded
        lea = None  # (register, blob offset, instructions left) from lea reg, [rip + x]
        pushed = None  # that register, when the previous instruction pushed it
        pc = None  # (register, blob offset, instructions left) from call/pop GetPC
        while True:
            if self.sleds:
                off = self._past_sled(off)
                if off >= self.n:
                    self.clean_paths += 1
                    return
            window_end = min(off + WINDOW, self.n)
            last_end = off
            stop = None  # "clean" | "bad" | "merge" | "end"
            decoded = 0
            for addr, size, mn, op in self.md.disasm_lite(self.buf[off:window_end], off, CHUNK_INSNS):
                decoded += 1
                if addr in self.insns:
                    stop = "merge"
                    break
                if " " in mn:
                    prefix, _, base = mn.partition(" ")
                    if (prefix in _BRANCH_PREFIXES and base in ("jmp", "call", "ret")) or (
                        base == "ret" and prefix in _RET_PREFIXES
                    ):
                        mn = base
                self.insns[addr] = (size, mn, op)
                last_end = addr + size
                if tail is not None:
                    tail.append(addr)

                if mn == "add" and op in ("byte ptr [eax], al", "byte ptr [rax], al"):
                    padding_run += 1
                    if padding_run >= 4:
                        stop = "end"  # ran into zero padding (e.g. after a noreturn call)
                        break
                else:
                    padding_run = 0

                if mn in RARE_MNEMONICS and not _deliberate(mn, op, [self.insns[a][1:] for a in list(self.insns)[-7:-1]]):
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
                if lea:
                    # lea r, [rip + x]; jmp r / call r / push r; ret: the target is known
                    reg, where, left = lea
                    if ((is_jmp or mn == "call") and op == reg) or (pushed and mn == "ret"):
                        if where not in self.insns and self._looks_like_code(where):
                            self.targets.add(where)
                            work.append(where)
                        lea = None
                    else:
                        pushed = mn == "push" and op == reg
                        lea = (reg, where, left - 1) if left > 1 and not (", " in op and op.startswith(reg + ",")) else None
                if pc:
                    # call/pop GetPC; lea r, [pc_reg + x]: an address in the blob is taken (handler, callback)
                    reg, base, left = pc
                    if mn == "lea" and f"[{reg} " in op:
                        m = _mem(op.split(", ", 1)[1])
                        if m and m[2] is None and 0 <= base + m[4] < self.n and base + m[4] not in self.insns:
                            self.spec.append(base + m[4])
                    pc = (reg, base, left - 1) if left > 1 and not op.startswith(reg + ",") else None
                if mn == "pop" and addr in self.getpc:
                    pc = (op, self.getpc[addr], 16)
                if mn == "lea" and self.is64 and "[rip" in op:
                    m = _RIP_OPERAND.search(op)
                    where = addr + size + (int(m.group(2), 0) * (-1 if m.group(1) == "-" else 1) if m and m.group(1) else 0)
                    if m and 0 <= where < self.n:
                        lea, pushed = (op.split(",", 1)[0], where, 4), False
                        if where not in self.insns:
                            self.spec.append(where)  # an address taken: a handler or callback, walked if it decodes as code
                if is_jmp or mn == "call" or mn in COND_BRANCHES:
                    tail = []
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
                if mn == "call" and tgt is not None and addr + size <= tgt < self.n and 0x58 <= self.buf[tgt] <= 0x5F:
                    self.getpc[tgt] = addr + size
                if mn == "call" and tgt is not None and addr + size < tgt < self.n:
                    b0 = self.buf[tgt]
                    if 0x58 <= b0 <= 0x5F or (b0 == 0x41 and tgt + 1 < self.n and 0x58 <= self.buf[tgt + 1] <= 0x5F):
                        # call forward to a pop: the skipped bytes are data (Donut instance) or
                        # code reached only indirectly (MSF block_api). Try them later on trial.
                        self.spec.append(addr + size)
                        stop = "clean"
                        break
                    gap = self.buf[addr + size : tgt]
                    if (
                        6 <= len(gap) <= 512
                        and not gap[-1]
                        and _INLINE_STRING.fullmatch(gap)
                        and not self._looks_like_code(addr + size)
                    ):
                        stop = "clean"  # call over an inline string: the callee takes its address from the stack
                        break
                if tgt is not None and mn in _COMPLEMENT:
                    if prev_cond == (_COMPLEMENT[mn], tgt, addr):
                        stop = "clean"  # jz X; jnz X: always taken, what follows is not reached from here
                        break
                    prev_cond = (mn, tgt, addr + size)
                else:
                    prev_cond = None
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
                    self.junk.update(tail or ())  # what led straight into it is not code either

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

    def scan(self, insns, junk=()):
        seq = sorted(insns.items()) if not junk else sorted(kv for kv in insns.items() if kv[0] not in junk)
        n = len(seq)
        is64 = self.is64
        exp_off = 0x88 if is64 else 0x78
        seg_starts = []  # sequence indexes of segment-relative reads (PEB walk start points)
        pushes = []  # running printable push immediates for stack strings: (offset, 4 raw bytes)
        self._smap = {}  # base register -> {displacement: byte} from immediate stores (stack strings)
        self._smap_at = {}  # base register -> offset of its first store
        self._frame = {_SP: 0}  # stack-frame registers -> offset from the entry stack pointer
        self._vstack = []  # known pushed values, for push imm; pop reg
        self._barrier = -1  # index after the last jmp/ret: constants set before it may be from another path
        xmm_consts = {}  # xmm/ymm register -> known bytes (xorstr-style SIMD string decoding)
        va_hits = 0
        self._lfanew_reads = []  # sequence indexes of [r + 0x3c] loads (e_lfanew)
        reg_consts = {}  # canonical register -> (constant, seq index) from 'mov reg, imm'
        frame, smap = self._frame, self._smap
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
                        self.add("syscall_stub_scan", STRONG, off, f"{text}  ; ntdll stub bytes")
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

            push_s = None
            # constants and stack bytes; skipped inline for what cannot matter (conditional jumps,
            # arithmetic on registers holding nothing known) as this runs for every instruction
            if dst is None:
                if mn[0] != "j" or mn == "jmp":
                    self._track_strings(i, off, size, mn, op, dst, src, reg_consts, xmm_consts)
            else:
                cdq = _REG_CANON.get(dst)
                if (
                    cdq is None
                    or cdq in reg_consts
                    or cdq in frame
                    or cdq in smap
                    or mn in _CLOBBERS
                    or (mn in _REG_TRACK_MNS and not (mn == "mov" and src[-1] == "]"))
                ):
                    self._track_strings(i, off, size, mn, op, dst, src, reg_consts, xmm_consts)
            if mn in ("mov", "movabs", "push"):
                v = _parse_int(src if src is not None else op) if has_hex or (src or op).isdigit() else None
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
                    # --- stack strings pushed 4 bytes at a time (the first push is the string's end,
                    # so it may be a 1-3 character tail: push 0x65)
                    if mn == "push" and 0 < v <= 0xFFFFFFFF and (v >= 0x2020 or not pushes):
                        raw = v.to_bytes(4, "little")
                        if raw[0] and all(b == 0 or 0x20 <= b < 0x7F for b in raw) and (v >= 0x2020 or chr(raw[0]).isalnum()):
                            push_s = raw

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
                elif op.endswith(", 0xfff") and dst in _REG16 and i + 1 < n and seq[i + 1][1][1:] == ("inc", "e" + dst):
                    # or bx, 0xfff; inc ebx: next page (the SEH egg hunter walks with a handler instead of a syscall)
                    self.add("egg_hunter", STRONG if scasd else MEDIUM, off, f"{text}; inc e{dst}")
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
                self._flush_stack(pushes)

        self._flush_stack(pushes)
        self._harvest_strings()
        rd = [k for k, (_, (_, m, _)) in enumerate(seq) if m == "rdtsc"]
        if any(b - a <= 40 for a, b in zip(rd, rd[1:])):
            self.add("rdtsc_timing", WEAK, seq[rd[0]][0], "rdtsc ... rdtsc")
        self._peb_walks(seq, seg_starts)
        self._loops(seq, insns)
        self._decoders(seq)
        self._pe_loader(seq)
        self._kernel_token_steal(seq)
        self._exception_handlers(seq)
        self._stages(seq)
        self._ciphers(seq)
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
        cands = {}  # group -> every place it was seen, to find stages that sit together
        index = {o: k for k, (o, _) in enumerate(seq)}

        def seen(group, lines):
            groups.setdefault(group, lines)
            if len(cands.setdefault(group, [])) < 32:
                cands[group].append(lines)

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
                seen(
                    "headers",
                    [(i, "e_lfanew")] + [(j, header_fields[d]) for d, j in fields.items() if d not in (import_dir, reloc_dir)],
                )
            if len(fields.keys() & header_fields.keys()) >= 2 and "magic" not in groups:
                magic = self._custom_magic(seq, i)
                if magic is not None:
                    groups["magic"] = [(i, "e_lfanew"), (magic, "NT signature compared with a custom value")] + sorted(
                        (j, header_fields[d]) for d, j in fields.items()
                    )[:4]
            if import_dir in fields:
                seen("_import_dir", [(i, "e_lfanew"), (fields[import_dir], header_fields[import_dir])])
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
                seen("sections", [s for s in sec if s])
            rel = [
                pick(lambda m, o: m == "movzx" and "word ptr [" in o, "relocation entry (word)"),
                pick(lambda m, o: m == "shr" and o.endswith(", 0xc"), "type = entry >> 12"),
                pick(lambda m, o: m == "and" and o.endswith(", 0xfff"), "offset = entry & 0xfff"),
            ]
            if all(rel):
                seen("relocs", rel)
            step = pick(lambda m, o: m == "add" and o.endswith(", 0x14"), "next import descriptor (0x14)")
            if step and len(disps & {0x0C, 0x10}) == 2:
                groups.setdefault("_import_stride", [step])
        if "_import_dir" in groups and (ordinal is not None or "_import_stride" in groups):
            imp = list(groups["_import_dir"])
            if ordinal is not None:
                imp.append((ordinal, "ordinal flag test"))
            imp += groups.get("_import_stride", [])
            groups["imports"] = imp
            extra = imp[len(groups["_import_dir"]) :]
            cands["imports"] = [c + extra for c in cands["_import_dir"]]

        if "magic" in groups:
            k = groups["magic"][1][0]
            self.add(
                "pe_custom_magic",
                MEDIUM,
                seq[k][0],
                f"{seq[k][1][1]} {seq[k][1][2]}",
                [self.line(j, note) for j, note in groups["magic"]],
            )
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
            # one loader: the stages sit together. Header, section and import code spread across a
            # large compiled image belongs to unrelated functions (CRT, runtime, delay-load helper).
            best = None
            for pivot in (c[0][0] for g in found for c in cands[g]):
                pick = {g: min(cands[g], key=lambda c: abs(seq[c[0][0]][0] - seq[pivot][0])) for g in found}
                offs = sorted((seq[c[0][0]][0], g) for g, c in pick.items())
                # the widest run of stages within reach of each other
                for lo in range(len(offs)):
                    near = [g for o, g in offs if 0 <= o - offs[lo][0] <= LOADER_SPAN]
                    if len(near) >= 3 and ("relocs" in near or "imports" in near) and (best is None or len(near) > len(best[0])):
                        best = (near, pick)
            if best:
                near, pick = best
                near = [g for g in names if g in near]
                lines = sorted({k: (k, note) for g in near for k, note in pick[g]}.values())
                anchor = min(seq[pick[g][0][0]][0] for g in near)
                self.add("reflective_pe_loader", STRONG, anchor, "+".join(near), [self.line(k, note) for k, note in lines])
        self._header_wipe(seq)

    def _exception_handlers(self, seq):
        """Exception-driven control flow.

          install   x86 SEH frame: push handler; push fs:[0]; mov fs:[0], esp - with the handler in the blob
          rewrite   a handler loads the CONTEXT record (x64: [ExceptionInfo + 8]; x86 SEH: third argument,
                    VEH: [[esp + 4] + 4]) and writes its Eip/Rip field
          flow      the code takes the address of such a handler (lea [rip + h], a GetPC pointer, the SEH frame)
        Compiler-built frames push absolute handler addresses and are not reported.
        """
        n = len(seq)
        is64 = self.is64
        ctx_ip = 0xF8 if is64 else 0xB8
        word = "qword ptr [" if is64 else "dword ptr ["
        needle = f"+ {ctx_ip:#x}]"
        installs = [
            k for k, (_, (_, mn, op)) in enumerate(seq) if mn == "mov" and op.startswith("dword ptr fs:[") and op.endswith("], esp")
        ]
        writes = [k for k, (_, (_, mn, op)) in enumerate(seq) if needle in op and mn in ("mov", "add", "sub", "inc", "dec")]
        if not installs and not writes:
            return

        def back(k, limit):
            """Indexes before k in the same straight-line run."""
            for j in range(k - 1, max(-1, k - limit - 1), -1):
                if seq[j][1][1] in TERMINATORS:
                    return
                yield j

        # --- handlers that move the saved instruction pointer
        rewrites = []  # (write index, CONTEXT load index, checked?)
        for k in writes:
            dst = seq[k][1][2].split(", ", 1)[0]
            m = _mem(dst) if dst.startswith(word) else None
            if not m or m[0] is not None or m[2] is not None or m[4] != ctx_ip or m[1] in (None, "rip", "sp", "bp"):
                continue
            load = None
            for j in back(k, 20):
                parts = seq[j][1][2].split(", ", 1)
                if len(parts) == 2 and _canon(parts[0]) == m[1]:
                    sm = _mem(parts[1]) if seq[j][1][1] == "mov" and parts[1].endswith("]") else None
                    if sm and sm[0] is None and sm[2] is None and sm[1] not in (None, "rip"):
                        if is64:
                            ok = sm[4] == 8 and sm[1] not in ("sp", "bp")  # ExceptionInfo->ContextRecord
                        elif sm[1] in ("sp", "bp"):
                            ok = (sm[1], sm[4]) in (("sp", 0xC), ("bp", 0x10))  # SEH handler's third argument
                        else:
                            # VEH: ExceptionInfo (first argument) -> ContextRecord
                            first = (f"{parts[1][parts[1].index('[') + 1 :].split(' ')[0].rstrip(']')}, dword ptr [esp + 4]",
                                     f"{parts[1][parts[1].index('[') + 1 :].split(' ')[0].rstrip(']')}, dword ptr [ebp + 8]")  # fmt: skip
                            ok = sm[4] == 4 and any(seq[q][1][1] == "mov" and seq[q][1][2] in first for q in back(j, 8))
                        if ok:
                            load = j
                    break
            if load is None:
                continue
            lo, hi = max(0, load - 24), min(n, k + 12)
            code = next(
                (
                    q
                    for q in range(lo, hi)
                    if seq[q][1][1] == "cmp" and (_imm(seq[q][1][2].rsplit(", ", 1)[-1]) or 0) & 0xFFFFFFFF in _EXCEPTION_CODES
                ),
                None,
            )
            resume = [("mov", "eax, 0xffffffff"), ("or", "eax, 0xffffffff"), ("mov", "rax, -1")]
            if not is64 and seq[load][1][2].endswith(("[esp + 0xc]", "[ebp + 0x10]")):
                resume = [("xor", "eax, eax"), ("sub", "eax, eax")]  # an SEH handler returns ExceptionContinueExecution (0)
            cont = next((q for q in range(k + 1, hi) if seq[q][1][1:] in resume), None)
            block = [self.line(load, "CONTEXT record"), self.line(k, "Rip rewritten" if is64 else "Eip rewritten")]
            if code is not None:
                block.append(self.line(code, "exception code check"))
            if cont is not None:
                block.append(self.line(cont, "EXCEPTION_CONTINUE_EXECUTION"))
            rewrites.append((k, load, code is not None or cont is not None, block))

        # --- code pointers the blob takes: SEH frames, lea [rip + h], GetPC-relative pointers
        taken = {}  # handler offset -> sequence index where its address is taken
        call_ret = {}
        for t, ks in self._call_targets.items():
            call_ret[t] = seq[ks[0]][0] + seq[ks[0]][1][0]
        targets = {seq[q][0]: q for q in range(n)}
        for k in installs:
            inner = seq[k][1][2][len("dword ptr fs:[") : -len("], esp")]
            if inner != "0" and not any(
                seq[j][1][1] in ("xor", "sub") and seq[j][1][2] == f"{inner}, {inner}" for j in back(k, 12)
            ):
                continue
            # the old head of the chain is pushed just before; the handler just before that
            prev = next((j for j in back(k, 6) if seq[j][1][1] == "push"), None)
            if prev is None:
                continue
            handler = None
            hk = next((j for j in back(prev, 4) if seq[j][1][1] == "push"), None)
            entered = next((q for q in range(max(0, prev - 3), prev + 1) if seq[q][0] in call_ret), None)
            if entered is not None and (hk is None or hk < entered):
                handler = call_ret[seq[entered][0]]  # call over the handler: its return address is the frame's handler
                hk = entered
            elif hk is not None:
                arg = seq[hk][1][2]
                if _canon(arg):
                    vals = _Values(False)
                    for j in range(max(0, hk - 24), hk):
                        o, (sz, mn, op) = seq[j]
                        if mn in TERMINATORS and mn != "jmp":
                            vals = _Values(False)
                            continue
                        vals.step(
                            o,
                            sz,
                            mn,
                            op,
                            getpc=lambda at: call_ret.get(at) if at in call_ret and seq[targets[at]][1][1] == "pop" else None,
                        )
                    v = vals.get(arg)
                    handler = v[1] if v and v[0] == "ptr" else None
                elif self.va is not None and _imm(arg) is not None and 0 <= _imm(arg) - self.va < self.size:
                    handler = _imm(arg) - self.va  # absolute, but inside this region
            if handler is None or not 0 <= handler < self.size:
                continue
            taken.setdefault(handler, k)
            block = [self.line(hk, f"handler at {handler:#x}"), self.line(prev, "previous frame"), self.line(k, "frame installed")]
            self.add("seh_handler_install", MEDIUM, seq[k][0], f"SEH frame with its handler at {handler:#x}", block)
            trap = next(
                (q for q in range(k + 1, min(n, k + 16))
                 if seq[q][1][1] in ("int3", "ud2", "int1", "hlt") or (seq[q][1][1] == "int" and seq[q][1][2] in ("3", "0x2d", "0x29"))),
                None,
            )  # fmt: skip
            if trap is not None:
                self.add(
                    "exception_trigger",
                    WEAK,
                    seq[trap][0],
                    f"{seq[trap][1][1]} {seq[trap][1][2]}".strip(),
                    [self.line(k, "frame installed"), self.line(trap, "raises the exception")],
                )
        if not rewrites:
            return
        if is64:
            for k, (off, (size, mn, op)) in enumerate(seq):
                if mn == "lea" and "[rip" in op:
                    m = _RIP_OPERAND.search(op)
                    if m:
                        where = off + size + (int(m.group(2), 0) * (-1 if m.group(1) == "-" else 1) if m.group(1) else 0)
                        if 0 <= where < self.size:
                            taken.setdefault(where, k)
        else:
            vals = _Values(False)
            for k, (o, (sz, mn, op)) in enumerate(seq):
                if mn in TERMINATORS and mn != "jmp":
                    vals = _Values(False)
                    continue
                vals.step(
                    o, sz, mn, op, getpc=lambda at: call_ret.get(at) if at in call_ret and seq[targets[at]][1][1] == "pop" else None
                )
                if mn == "lea":
                    v = vals.get(op.split(", ", 1)[0])
                    if v and v[0] == "ptr" and 0 <= v[1] < self.size:
                        taken.setdefault(v[1], k)
        for k, load, checked, block in rewrites:
            at = seq[load][0]
            handler = max((h for h in taken if h <= at < h + HANDLER_SPAN and taken[h] != load), default=None)
            if not checked and handler is None:
                continue  # a write to some structure's field: nothing says it is a CONTEXT
            self.add("exception_context_rewrite", MEDIUM, seq[k][0], f"{seq[k][1][1]} {seq[k][1][2]}", block)
            if handler is not None and checked and "exception_control_flow" not in self.hits:
                where = taken[handler]
                block = [self.line(where, f"takes the address of the handler at {handler:#x}"), self.line(load, "handler: CONTEXT record"),
                         self.line(k, "Rip rewritten" if is64 else "Eip rewritten")]  # fmt: skip
                self.add(
                    "exception_control_flow",
                    STRONG,
                    seq[where][0],
                    f"handler at {handler:#x} moves the saved instruction pointer",
                    block,
                )

    def _stages(self, seq):
        """Stage-level techniques: finding an image base by scanning back to 'MZ' (from a return
        address, the SEH chain's last handler, or a kernel entry point), code that writes into its
        own instructions, VM checks, and short supporting patterns (trap flag, PEB fields,
        allocation arguments)."""
        n = len(seq)
        is64 = self.is64
        index = {o: k for k, (o, _) in enumerate(seq)}
        text = lambda k: f"{seq[k][1][1]} {seq[k][1][2]}".strip()  # noqa: E731

        # --- one pass for the rare anchors
        msr, idt, chain, peb, stores, privileged = [], [], [], [], [], []
        seg_peb = "gs:[0x60]" if is64 else "fs:[0x30]"
        for k, (off, (size, mn, op)) in enumerate(seq):
            if mn == "rdmsr":
                msr.append(k)
            elif mn in ("sidt", "sgdt", "sldt", "str", "in"):
                privileged.append(k)
            elif mn == "mov" or mn == "movabs":
                if op.endswith(("s:[0x38]", "fs:[0]")) or ("fs:[e" in op and op.endswith("]")):
                    (idt if op.endswith("s:[0x38]") else chain).append(k)
                elif op.endswith(seg_peb):
                    peb.append(k)
                elif "[rip" in op and op.split(", ", 1)[0].endswith("]"):
                    stores.append(k)
                elif (is64 and op.startswith(("r9d, 0x40", "r9, 0x40"))) and op.endswith("0x40"):
                    self._rwx_args(seq, k)
            elif mn in _SELF_WRITES and "[rip" in op and op.split(", ", 1)[0].endswith("]"):
                stores.append(k)
            elif mn == "push" and op == "0x40" and not is64:
                self._rwx_args(seq, k)
            elif mn in ("or", "bts") and op in (
                "dword ptr [esp], 0x100",
                "qword ptr [rsp], 0x100",
                "dword ptr [rsp], 0x100",
                "dword ptr [esp], 8",
                "qword ptr [rsp], 8",
            ):
                if k and k + 1 < n and seq[k - 1][1][1].startswith("pushf") and seq[k + 1][1][1].startswith("popf"):
                    self.add("trap_flag", INFO, off, f"{seq[k - 1][1][1]}; {mn} {op}; {seq[k + 1][1][1]}")

        # --- VM checks
        for k in privileged:
            mn, op = seq[k][1][1:]
            if mn == "in":
                if op == "eax, dx" and any(seq[j][1][1:] == ("mov", VMWARE_MAGIC) for j in range(max(0, k - 6), k)):
                    self.add("vmware_backdoor", MEDIUM, seq[k][0], f"mov {VMWARE_MAGIC}; in eax, dx")
            else:
                self.add("red_pill", INFO, seq[k][0], text(k))

        # --- kernel entry points
        kernel = {}
        for k in msr:
            which = next((_MSRS[_imm(seq[j][1][2][5:])] for j in range(max(0, k - 6), k)
                          if seq[j][1][1] == "mov" and seq[j][1][2].startswith("ecx, ") and _imm(seq[j][1][2][5:]) in _MSRS), None)  # fmt: skip
            if which in ("LSTAR", "SYSENTER_EIP"):
                kernel[k] = f"{which} MSR"
                self.add("kernel_msr_read", MEDIUM, seq[k][0], f"rdmsr  ; {which}")
        for k in idt:
            kernel[k] = "IDT base from the KPCR"

        # --- backward scans for 'MZ'
        for b_off, tgt in self._backedges:
            if tgt not in index or b_off not in index:
                continue
            lo, hi = index[tgt], index[b_off]
            if not 1 <= hi - lo <= MZ_SCAN_BODY:
                continue
            reg = None
            for k in range(lo, hi + 1):
                mn, op = seq[k][1][1:]
                if mn != "cmp" or not op.endswith((", 0x5a4d", ", 0x905a4d")):
                    continue
                first = op.split(", ", 1)[0]
                m = _mem(first) if first.endswith("]") else None
                if m is None and _canon(first):  # movzx r, word ptr [p]; cmp r, 'MZ'
                    load = next((seq[j][1][2].split(", ", 1)[1] for j in range(k - 1, max(lo - 1, k - 4), -1)
                                 if seq[j][1][1] in ("mov", "movzx") and _canon(seq[j][1][2].split(", ", 1)[0]) == _canon(first)
                                 and seq[j][1][2].endswith("]")), None)  # fmt: skip
                    m = _mem(load) if load else None
                if m and m[0] is None and m[2] is None and m[4] == 0 and m[1] not in (None, "rip", "sp", "bp"):
                    reg, at = m[1], k
                    break
            if reg is None:
                continue
            step = 0
            for k in range(lo, hi + 1):
                mn, op = seq[k][1][1:]
                parts = op.split(", ", 1)
                if _canon(parts[0]) != reg:
                    continue
                if mn in ("sub", "add") and len(parts) == 2 and _imm(parts[1]) is not None:
                    step += _imm(parts[1]) * (-1 if mn == "sub" else 1)
                elif mn in ("dec", "inc"):
                    step += -1 if mn == "dec" else 1
                elif mn == "lea" and len(parts) == 2:
                    lm = _mem(parts[1])
                    step += lm[4] if lm and lm[1] == reg and lm[2] is None else 0
            if is64 and step > 1 << 63:
                step -= 1 << 64
            elif not is64 and step > 1 << 31:
                step -= 1 << 32
            if step >= 0:
                continue  # forwards: a search for an appended image, not for the image the code is in
            paged = step % 0x1000 == 0
            block = [self.line(at, "'MZ' test"), self.line(hi, f"back {abs(step):#x} bytes and again")]
            source = next((k for k in sorted(kernel, reverse=True) if 0 < lo - k <= 24), None)
            if source is not None:
                self.add("kernel_base_discovery", STRONG, seq[source][0], f"{kernel[source]}, then back to 'MZ' {abs(step):#x} bytes at a time",
                         [self.line(source, kernel[source])] + block)  # fmt: skip
            walk = next((k for k in chain if 0 < lo - k <= 24), None)
            self.add(
                "image_base_scan", STRONG if paged else MEDIUM, seq[at][0], f"{text(at)}; steps back {abs(step):#x} bytes", block
            )
            if walk is not None:
                self.add("seh_chain_walk", MEDIUM, seq[walk][0], text(walk), [self.line(walk, "SEH chain head")] + block[:1])

        # --- SEH chain followed to its end (without a scan after it)
        for k in chain:
            if "seh_chain_walk" in self.hits:
                break
            reg = _canon(seq[k][1][2].split(", ", 1)[0])
            end = next((j for j in range(k + 1, min(n, k + 10)) if seq[j][1][1] == "cmp" and seq[j][1][2].endswith(("], -1", "], 0xffffffff"))
                        and (_mem(seq[j][1][2].split(", ", 1)[0]) or (0, 0))[1] == reg), None)  # fmt: skip
            nxt = next((j for j in range(k + 1, min(n, k + 10)) if seq[j][1][1] == "mov" and seq[j][1][2].endswith("]")
                        and _canon(seq[j][1][2].split(", ", 1)[0]) == reg and (_mem(seq[j][1][2].split(", ", 1)[1]) or (0, 0))[1] == reg), None)  # fmt: skip
            if reg and end is not None and nxt is not None:
                self.add(
                    "seh_chain_walk",
                    INFO,
                    seq[k][0],
                    text(k),
                    [self.line(k, "SEH chain head"), self.line(end, "last frame?"), self.line(nxt, "next frame")],
                )

        # --- PEB fields
        for k in peb:
            reg = _canon(seq[k][1][2].split(", ", 1)[0])
            if not reg:
                continue
            for j in range(k + 1, min(n, k + 7)):
                mn, op = seq[j][1][1:]
                parts = op.split(", ", 1)
                if mn != "mov" or len(parts) != 2 or not parts[1].endswith("]"):
                    continue
                m = _mem(parts[1])
                if not m or m[1] != reg or m[2] is not None:
                    continue
                if m[4] == (0x58 if is64 else 0x2C):
                    self.add(
                        "kernel_callback_table",
                        INFO,
                        seq[j][0],
                        text(j),
                        [self.line(k, "PEB"), self.line(j, "KernelCallbackTable")],
                    )
                elif m[4] == (0x20 if is64 else 0x10) and _canon(parts[0]):
                    params = _canon(parts[0])
                    fields = (0x60, 0x68, 0x70, 0x78) if is64 else (0x38, 0x3C, 0x40, 0x44)
                    hit = next((q for q in range(j + 1, min(n, j + 13)) if seq[q][1][1] == "mov" and seq[q][1][2].split(", ", 1)[0].endswith("]")
                                and (_mem(seq[q][1][2].split(", ", 1)[0]) or (0, 0, 0, 0, 0))[1] == params
                                and _mem(seq[q][1][2].split(", ", 1)[0])[4] in fields), None)  # fmt: skip
                    if hit is not None:
                        self.add("process_parameters_write", INFO, seq[hit][0], text(hit),
                                 [self.line(k, "PEB"), self.line(j, "ProcessParameters"), self.line(hit, "ImagePathName / CommandLine")])  # fmt: skip

        # --- exception directory (x64): [image + e_lfanew + 0xa0], then 12-byte RUNTIME_FUNCTION steps
        if is64:
            for i in self._lfanew_reads:
                for j in range(i + 1, min(n, i + 12)):
                    if seq[j][1][1] == "mov" and seq[j][1][2].endswith("+ 0xa0]"):
                        stride = next(
                            (q for q in range(j + 1, min(n, j + 32)) if seq[q][1][1] == "add" and seq[q][1][2].endswith(", 0xc")),
                            None,
                        )
                        if stride is not None:
                            self.add("exception_directory_walk", INFO, seq[j][0], text(j),
                                     [self.line(i, "e_lfanew"), self.line(j, "exception directory"), self.line(stride, "next RUNTIME_FUNCTION")])  # fmt: skip
                        break

        # --- writes into the code itself
        def contiguous(a, b):
            """Decoded instructions cover every byte from index a to index b."""
            a, b = min(a, b), max(a, b)
            return b - a <= 512 and all(seq[q][0] + seq[q][1][0] == seq[q + 1][0] for q in range(a, b))

        offsets = [o for o, _ in seq]

        def inside(target):
            q = bisect.bisect_right(offsets, target) - 1
            return q if q >= 0 and offsets[q] <= target < offsets[q] + seq[q][1][0] else None

        for k in stores:
            off, (size, mn, op) = seq[k]
            m = _RIP_OPERAND.search(op)
            if not m:
                continue
            target = off + size + (int(m.group(2), 0) * (-1 if m.group(1) == "-" else 1) if m.group(1) else 0)
            q = inside(target) if 0 <= target < self.size else None
            if q is not None and q != k and contiguous(k, q):
                self.add(
                    "self_modifying_code", STRONG, off, text(k), [self.line(k, "write"), self.line(q, f"rewritten at {target:#x}")]
                )
                break
        if not is64 and "self_modifying_code" not in self.hits:
            call_ret = {
                t: seq[ks[0]][0] + seq[ks[0]][1][0]
                for t, ks in self._call_targets.items()
                if t in index and seq[index[t]][1][1] == "pop"
            }
            for t in call_ret:
                vals = _Values(False)
                for k in range(index[t], min(n, index[t] + 48)):
                    o, (sz, mn, op) = seq[k]
                    if mn in TERMINATORS:
                        break
                    dst = op.split(", ", 1)[0]
                    if mn in _SELF_WRITES and dst.endswith("]") and "fs:" not in dst:
                        mm = _mem(dst)
                        addr = vals.addr(mm) if mm else None
                        q = inside(addr[1]) if addr and addr[0] == "ptr" and 0 <= addr[1] < self.size else None
                        if q is not None and q != k and contiguous(k, q):
                            self.add(
                                "self_modifying_code",
                                STRONG,
                                o,
                                text(k),
                                [self.line(index[t], "GetPC"), self.line(k, "write"), self.line(q, f"rewritten at {addr[1]:#x}")],
                            )
                            break
                    vals.step(o, sz, mn, op, getpc=call_ret.get)
                if "self_modifying_code" in self.hits:
                    break

    def _rwx_args(self, seq, k):
        """PAGE_EXECUTE_READWRITE next to MEM_COMMIT(|MEM_RESERVE), then a call."""
        n = len(seq)
        commit = ("r8d, 0x3000", "r8d, 0x1000", "r8, 0x3000") if self.is64 else ("0x3000", "0x1000")
        want = "mov" if self.is64 else "push"
        near = next(
            (j for j in range(max(0, k - 5), min(n, k + 6)) if j != k and seq[j][1][1] == want and seq[j][1][2] in commit), None
        )
        call = next((j for j in range(k + 1, min(n, k + 10)) if seq[j][1][1] == "call"), None)
        if near is not None and call is not None:
            self.add("rwx_alloc_args", INFO, seq[k][0], "PAGE_EXECUTE_READWRITE, " + ("MEM_COMMIT|MEM_RESERVE" if "0x3000" in seq[near][1][2] else "MEM_COMMIT"),
                     [self.line(near, "allocation type"), self.line(k, "protection"), self.line(call, "allocator")])  # fmt: skip

    def _ciphers(self, seq):
        """Cipher primitives, recorded as INFO here: they only add supporting weight once the blob
        is shellcode on other evidence (crypto libraries use every one of them)."""
        n = len(seq)
        chacha = {}
        digest = {}
        if self._backedges and "rc4_ksa" not in self.hits:  # with a linked decoder it is already reported (medium)
            rc4 = self._rc4_ksa(seq, {o: k for k, (o, _) in enumerate(seq)})
            if rc4 is not None:
                self.add("rc4_ksa", INFO, rc4[0], "256-entry S-box init + swap loop", rc4[1])
        for i, (off, (_, mn, op)) in enumerate(seq):
            if mn.lstrip("v") in _AES_MNS:
                self.add("aes_ni", INFO, off, f"{mn} {op}")
                continue
            last = op.rsplit(", ", 1)[-1]
            if not last[:1].isdigit():
                continue
            v = _parse_int(last)
            if v is None:
                continue
            v &= 0xFFFFFFFF
            if v in _DIGEST_WORDS:
                digest.setdefault(v, off)
            if v in _CHACHA_WORDS:
                chacha.setdefault(v, off)
            elif v in _TEA_DELTAS and mn in ("add", "sub", "mov", "lea"):
                # the round: delta added to a sum, data words shifted by 4 and 5 nearby
                near = {
                    seq[k][1][2].rsplit(", ", 1)[-1]
                    for k in range(max(0, i - 12), min(n, i + 12))
                    if seq[k][1][1] in ("shl", "shr", "sal")
                }
                if {"4", "5"} <= near or {"0x4", "0x5"} <= near:
                    self.add("tea_delta", INFO, off, f"{mn} {op}  ; TEA/XTEA delta {_TEA_DELTAS[v]}")
        for algo in ("SHA-256", "SHA-1", "MD5", "MD5/SHA-1"):
            words = [
                v for v in digest if _DIGEST_WORDS[v] == algo or (algo in ("SHA-1", "MD5") and _DIGEST_WORDS[v] == "MD5/SHA-1")
            ]
            if len(words) >= 3 and (algo == "MD5/SHA-1" or any(_DIGEST_WORDS[v] == algo for v in words)):
                off = min(digest[v] for v in words)
                self.add(
                    "digest_constants",
                    INFO,
                    off,
                    f"{algo} constants: " + ", ".join(f"{v:#x}" for v in sorted(words, key=digest.get)[:4]),
                )
                break
        if len(chacha) >= 2:
            off = min(chacha.values())
            self.add("chacha_constants", INFO, off, "'" + "".join(_CHACHA_WORDS[v] for v in sorted(chacha, key=chacha.get)) + "'")
        for text in self.stack_strings:
            if text.startswith(("expand 32-byte k", "expand 16-byte k")):
                self.add("chacha_constants", INFO, 0, f"'{text}' built on the stack")

    def _custom_magic(self, seq, i):
        """Index of a compare of the NT header's first word/dword (base + e_lfanew, displacement 0)
        with a value other than 'PE\\0\\0', following the e_lfanew register; None when the code checks
        the standard signature or no such compare follows."""
        n = len(seq)
        first = seq[i][1][2].split(", ")[0]
        nt = {_canon(first)} if _canon(first) else set()
        hit = None
        for j in range(i + 1, min(n, i + 16)):
            mn, op = seq[j][1][1:]
            parts = op.split(", ")
            dst = _canon(parts[0]) if parts and parts[0] else None
            if mn == "cmp" and len(parts) == 2 and parts[0].endswith("]"):
                m = _mem(parts[0])
                v = _imm(parts[1])
                if m and (m[1] in nt or m[2] in nt) and m[4] == 0 and m[5] in (2, 4) and v is not None:
                    if v & 0xFFFF == 0x4550:
                        return None
                    if hit is None and v >= 0x100:
                        hit = j
            elif dst and len(parts) == 2:
                src = _mem(parts[1]) if mn == "lea" else None
                if mn == "add" and dst in nt:
                    continue
                if (mn == "lea" and src and (src[1] in nt or src[2] in nt)) or (mn == "mov" and _canon(parts[1]) in nt):
                    nt.add(dst)
                else:
                    nt.discard(dst)
        return hit

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
            table = None
            if len(keys) == 1 and keys[0][1] is None and keys[0][0] in ("xor", "add", "sub") and shape["width"] == 1:
                table = self._key_table(seq, ks, shape, vals)
            feedback = None
            if not table and len(keys) == 1 and keys[0][1] is None and keys[0][0] in ("xor", "add", "sub"):
                feedback = self._feedback(seq, ks, shape, vals)
            desc = self._xform_desc(shape, keys)
            if feedback:
                how = {"plain": "the plaintext", "cipher": "the ciphertext", "const": f"{feedback[1][2]:#x}"}[feedback[1][0]]
                step = f"replaced by {how}" if feedback[1][1] == "mov" else f"{feedback[1][1]} {how}"
                desc = desc.replace(f"rolling key ({shape['xforms'][0][1]})", f"key {feedback[0]:#x}, {step} after each element")
            if table:
                desc = desc.replace(f"rolling key ({shape['xforms'][0][1]})", f"{len(table[0])}-byte key table at {table[2]:#x}")
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
            if table:
                key_bytes, first = table[:2]

                def decode(raw, op=keys[0][0], key=key_bytes, first=first):
                    return _apply_key_table(raw, op, key, first)

            elif feedback:

                def decode(raw, width=shape["width"], op=keys[0][0], key=feedback[0], fb=feedback[1]):
                    return _apply_feedback(raw, width, op, key, fb)

            else:

                def decode(raw, width=shape["width"], keys=keys):
                    return _apply_xforms(raw, width, keys)

            if (table or feedback or all(k is not None for _, k in keys)) and enc and not getattr(self, "nested", False):
                dec = decode(enc[:DECODE_VERIFY_MAX] if not nbytes else enc)
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
                            dec = decode(self.buf[start : start + rsize])
                        if len(dec) >= rsize:
                            region["_data"] = bytes(dec[:rsize])
                    elif rtype == "code" and nbytes and len(dec) == nbytes:
                        region["_data"] = bytes(dec)
            elif not table and not feedback and not all(k is not None for _, k in keys):
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

    def _feedback(self, seq, ks, shape, vals):
        """An in-place decoder whose key register is updated once per element, in a closed form:
        (start key, (source, op, constant)), or None.

            xor [p], k; mov k, [p]            key = the plaintext just written
            mov t, [p]; xor [p], k; mov k, t  key = the ciphertext just read
            xor [p], k; add k, [p]            key += plaintext (also xor/sub, and with t for the ciphertext)
            xor [p], k; add k, 0x11223344     key stepped by a constant (add/sub/xor/rol/ror)
        """
        if shape["kind"] != "in-place" or len(shape["xforms"]) != 1:
            return None
        _, src, anchor = shape["xforms"][0]
        key = _canon(src) if src else None
        start = vals.get(src) if key else None
        if not start or start[0] != "const" or _reg_bits(src) != 8 * shape["width"]:
            return None
        mm = shape["mem"]
        writes = [
            (k, seq[k][1][1], seq[k][1][2].split(", ", 1))
            for k in ks
            if _canon(seq[k][1][2].split(", ", 1)[0]) == key and seq[k][1][1] not in ("cmp", "test")
        ]
        if len(writes) != 1 or writes[0][0] < anchor or len(writes[0][2]) != 2:
            return None
        k, mn, (_, arg) = writes[0]
        if mn not in ("mov", "add", "sub", "xor", "rol", "ror"):
            return None
        # the pointer must not move between the transform and the key update
        if any(_canon(seq[q][1][2].split(", ", 1)[0]) in (mm[1], mm[2]) for q in ks if anchor < q < k):
            return None
        mask = (1 << 8 * shape["width"]) - 1
        if _imm(arg) is not None:
            return (start[1] & mask, ("const", mn, _imm(arg) & mask)) if mn != "mov" else None
        if mn in ("rol", "ror"):
            return None
        am = _mem(arg) if arg.endswith("]") else None
        if am:
            return (start[1] & mask, ("plain", mn, 0)) if am[:5] == mm[:5] else None
        # a register that holds the ciphertext: loaded from [p] before the transform, not written since
        tmp = _canon(arg)
        load = next((q for q in ks if q < anchor and seq[q][1][1] == "mov" and seq[q][1][2].split(", ", 1)[0] == arg
                     and (_mem(seq[q][1][2].split(", ", 1)[1]) or ())[:5] == mm[:5]), None)  # fmt: skip
        if tmp is None or load is None or any(_canon(seq[q][1][2].split(", ", 1)[0]) == tmp for q in ks if load < q < k):
            return None
        return start[1] & mask, ("cipher", mn, 0)

    def _key_table(self, seq, ks, shape, vals):
        """A byte decoder whose key comes from a table in the blob, indexed by a counter modulo the
        table length: (key bytes, first index, table offset), or None.

            mov edx, ecx; and edx, N-1      or      mov eax, ecx; xor edx, edx; div r(=N)
            mov al, [K + rdx]                        (K: a blob offset from GetPC/RIP)
            xor [P + rcx], al ... inc ecx            (the counter advances one byte per byte)
        """
        src = shape["xforms"][0][1]
        anchor = shape["anchor"]
        body = [(k, seq[k][1][1], seq[k][1][2]) for k in ks]
        load = next(((k, m, o) for k, m, o in reversed(body) if k < anchor and _canon(o.split(", ", 1)[0]) == _canon(src)), None)
        if load is None or load[1] not in ("mov", "movzx") or ", " not in load[2]:
            return None
        km = _mem(load[2].split(", ", 1)[1])
        if not km or km[0] is not None or km[2] is None or km[3] != 1 or (km[5] or 1) != 1:
            return None
        kbase, kidx = km[1], km[2]
        written = {_canon(o.split(", ", 1)[0]) for _, m, o in body if m in _WRITES_DST} | {
            _canon(o) for _, m, o in body if m in ("inc", "dec", "pop")
        }
        base = vals.get(kbase)
        if kbase in written or not base or base[0] != "ptr":
            return None
        # the key index: counter & (N-1), or counter % N through div
        counter = n = None
        before = [(k, m, o) for k, m, o in body if k < load[0]]
        for k, m, o in reversed(before):
            parts = o.split(", ")
            if m == "and" and _canon(parts[0]) == kidx and len(parts) == 2 and _parse_int(parts[1]) is not None:
                mask = _parse_int(parts[1])
                if mask & (mask + 1) == 0 and 2 <= mask + 1 <= 256:
                    mov = next(
                        (x for x in reversed(before) if x[0] < k and x[1] == "mov" and _canon(x[2].split(", ")[0]) == kidx), None
                    )
                    counter, n = (_canon(mov[2].split(", ")[1]) if mov else None), mask + 1
                break
            if m == "div" and kidx == "d":
                divisor = _canon(o)
                dv = next(
                    (
                        _parse_int(x[2].split(", ")[1])
                        for x in reversed(before)
                        if x[0] < k and x[1] == "mov" and _canon(x[2].split(", ")[0]) == divisor
                    ),
                    None,
                )
                if dv is None and divisor not in written and (vals.get(divisor) or ("",))[0] == "const":
                    dv = vals.get(divisor)[1]
                mov = next((x for x in reversed(before) if x[0] < k and x[1] == "mov" and _canon(x[2].split(", ")[0]) == "a"), None)
                zero = any(
                    x[1] == "xor" and _canon(x[2].split(", ")[0]) == "d" and x[2].split(", ")[0] == x[2].split(", ")[-1]
                    for x in before
                    if x[0] < k
                )
                if dv and 2 <= dv <= 256 and zero and mov:
                    counter, n = _canon(mov[2].split(", ")[1]), dv
                break
        if counter is None or counter in (kbase, kidx):
            return None
        # the counter moves one per byte decoded: the data index itself, or in step with the pointer
        steps = sum(1 if m == "inc" else -1 if m == "dec" else 0 for _, m, o in body if _canon(o) == counter)
        steps += sum(
            _parse_int(o.split(", ")[1]) or 0
            for _, m, o in body
            if m == "add" and _canon(o.split(", ")[0]) == counter and ", " in o
        )
        mm, step = shape["mem"], shape["step"]
        advance = sum(abs(v) * (mm[3] if r == mm[2] else 1) for r, v in step.items())
        first = vals.get(counter)
        if steps != 1 or advance != 1 or not first or first[0] != "const" or (mm[2] not in (None, counter)):
            return None
        koff = base[1] + km[4]
        if not 0 <= koff or koff + n > self.size:
            return None
        return bytes(self.buf[koff : koff + n]), first[1], koff

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

    def _flush_stack(self, run):
        """Pushed stack strings: the last push is the start of the string."""
        if len(run) >= 2:
            data = b"".join(raw for _, raw in reversed(run))
            for _, text, wide in _strings_in(data):
                self._emit_string(text, run[0][0], wide)
        run.clear()

    def _emit_string(self, text, off, wide=False):
        parts = _split_api_names(text)
        if parts:
            for part in parts:
                self._emit_string(part, off, wide)
            return
        text = text[:64]
        if text in self.stack_strings:
            return
        self.stack_strings.append(text)
        low = text.lower()
        if low in _API_NAMES:
            self.apis.add(_API_NAMES[low])
        label = f"'{text}'" + ("  ; UTF-16" if wide else "")
        if any(h in low for h in API_STRING_HINTS):
            self.add("stack_string_api", MEDIUM, off, label)
        else:
            self.add("stack_string", WEAK, off, label)

    def _harvest_strings(self, base=None):
        """Strings in the stack byte map (one base register, or all), then forget those bytes."""
        for b in [base] if base is not None else list(self._smap):
            cells = self._smap.pop(b, None)
            at = self._smap_at.pop(b, 0)
            if not cells:
                continue
            keys = sorted(cells)
            start = prev = keys[0]
            for k in keys[1:] + [None]:
                if k is not None and k == prev + 1:
                    prev = k
                    continue
                data = bytes(cells[d] for d in range(start, prev + 1)) if prev - start >= 3 else b""
                for _, text, wide in _strings_in(data):
                    self._emit_string(text, at, wide)
                if k is not None:
                    start = prev = k

    def _store(self, off, base, disp, raw, fold=None):
        """Immediate bytes stored at [base + disp]; fold: xor/add/sub into bytes already known."""
        cells = self._smap.setdefault(base, {})
        span = range(disp, disp + len(raw))
        if fold is None:
            if any(d in cells and cells[d] != raw[k] for k, d in enumerate(span)):
                self._harvest_strings(base)  # the slot is reused for another string
                cells = self._smap.setdefault(base, {})
            for k, d in enumerate(span):
                cells[d] = raw[k]
        elif all(d in cells for d in span):
            cur = int.from_bytes(bytes(cells[d] for d in span), "little")
            arg = int.from_bytes(raw, "little")
            mask = (1 << 8 * len(raw)) - 1
            new = {"xor": cur ^ arg, "add": (cur + arg) & mask, "sub": (cur - arg) & mask}[fold]
            for k, d in enumerate(span):
                cells[d] = new.to_bytes(len(raw), "little")[k]
        else:
            return False
        self._smap_at.setdefault(base, off)
        return True

    def _stack_bytes(self, base, disp, width):
        cells = self._smap.get(base, {})
        if all(d in cells for d in range(disp, disp + width)):
            return bytes(cells[d] for d in range(disp, disp + width))
        return None

    def _track_strings(self, i, off, size, mn, op, dst, src, reg_consts, xmm_consts):
        """Keep register constants right through arithmetic, and record immediate stores into the
        stack byte map: direct, through a register, xor/add/sub-folded (obfuscated stack strings),
        and SIMD loads/xors/stores of constant data (xorstr / obfuscate.h style)."""
        frame = self._frame
        clobbers = _CLOBBERS.get(mn)
        if clobbers:
            for r in clobbers:
                reg_consts.pop(r, None)
                frame.pop(r, None)
        if dst is None:
            self._track_flow(i, mn, op, reg_consts, xmm_consts)
            return
        if dst[-1] == "]":
            # --- stores into memory: the stack byte map
            if mn in _SIMD_LOADS:
                if xmm_consts.get(src):
                    m = _mem(dst)
                    if m[1] not in (None, "rip") and m[2] is None:
                        self._store(off, *self._slot(m[1], m[4]), xmm_consts[src])
                        return
            elif mn in ("cmp", "test", "bt"):
                return
            sv = _imm(src) if src else None
            if sv is None and src:
                sv = self._const(_REG_CANON.get(src), i, reg_consts)
                if mn in ("xchg", "xadd"):
                    reg_consts.pop(_REG_CANON.get(src), None)
            if sv is None:
                if not self._smap:
                    return
                b = _REG_CANON.get(dst[dst.index("[") + 1 :].split(" ", 1)[0].rstrip("]"))
                if b not in self._smap and not (b in frame and "frame" in self._smap):
                    return  # nothing known around this base register
            m = _mem(dst)
            if m[1] in (None, "rip"):
                return
            key, disp = self._slot(m[1], m[4])
            if sv is not None and mn in ("mov", "xor", "add", "sub") and m[2] is None and m[5]:
                raw = (sv & ((1 << 8 * m[5]) - 1)).to_bytes(m[5], "little")
                if mn == "mov" and key not in self._smap and not any(0x20 <= c < 0x7F for c in raw):
                    return  # zeros, sizes and flags where no string is being built
                if self._store(off, key, disp, raw, None if mn == "mov" else mn):
                    return
            cells = self._smap.get(key)  # an unknown value lands here: those bytes are no longer known
            if cells:
                if m[2] is not None:
                    self._harvest_strings(key)
                else:
                    for d in range(disp, disp + (m[5] or 16)):
                        cells.pop(d, None)
            return
        cd = _REG_CANON.get(dst)
        if cd is None:
            if dst in xmm_consts or mn in _SIMD_LOADS or mn in _SIMD_XORS:
                self._track_simd(off, size, mn, dst, src, xmm_consts)
            return
        if mn in ("xchg", "xadd", "cmpxchg"):
            reg_consts.pop(_REG_CANON.get(src), None)
            frame.pop(_REG_CANON.get(src), None)
        sm = None
        if cd not in reg_consts and cd not in frame and cd not in self._smap:
            # untracked register (most instructions): only a constant or a frame pointer matters
            if mn in ("mov", "movabs"):
                if "[" in src or not (
                    src[0].isdigit() or _REG_CANON.get(src) in reg_consts or (cd == "bp" and src in ("rsp", "esp"))
                ):
                    return
            elif mn == "lea":
                b = _REG_CANON.get(src[1:].split(" ", 1)[0].rstrip("]"))
                if b not in reg_consts and not (cd == "bp" and b in frame):
                    return
            elif mn != "xor" or dst != src:
                return
        elif mn in ("cmp", "test", "bt"):
            return
        bits = _REG_BITS.get(dst)
        sv = _imm(src)
        if sv is None:
            sv = self._const(_REG_CANON.get(src), i, reg_consts)
        if mn == "lea" and sm is None:
            sm = _mem(src)
        # stack-frame registers: rsp moves by known amounts, rbp = rsp + k (lea rbp, [rsp - 0x70])
        if cd == _SP:
            if mn in ("sub", "add") and sv is not None:
                frame[_SP] += -sv if mn == "sub" else sv
                self._vstack.clear()
            else:
                self._reset_frame()
        elif cd != "bp":
            pass
        elif sm and sm[1] in frame and sm[2] is None:
            frame[cd] = frame[sm[1]] + sm[4]
        elif mn == "mov" and bits == (64 if self.is64 else 32) and _REG_CANON.get(src) in frame:
            frame[cd] = frame[_REG_CANON[src]]
        else:
            frame.pop(cd, None)
        if cd in self._smap:
            self._harvest_strings(cd)  # the base register moves: its offsets no longer line up
        # constants, folded through arithmetic
        if bits not in (32, 64):
            if mn == "mov" and sv is not None and bits:  # mov cx, 0x5a4d; cmp word ptr [rax], cx
                reg_consts[cd] = (sv & ((1 << bits) - 1), i)
            else:
                reg_consts.pop(cd, None)
        elif mn == "lea":
            if sm and sm[1] in reg_consts and sm[2] is None:
                reg_consts[cd] = ((reg_consts[sm[1]][0] + sm[4]) & ((1 << bits) - 1), i)
            else:
                reg_consts.pop(cd, None)
        elif mn in ("mov", "movabs") and sv is not None:
            reg_consts[cd] = (sv & ((1 << bits) - 1), i)
        elif mn == "xor" and dst == src:
            reg_consts[cd] = (0, i)
        elif mn in _FOLD and cd in reg_consts and sv is not None:
            v = reg_consts[cd][0]
            if mn in ("rol", "ror", "shl", "shr"):
                k = sv % bits
                v = {"rol": (v << k) | (v >> (bits - k)), "ror": (v >> k) | (v << (bits - k)), "shl": v << k, "shr": v >> k}[mn]
            else:
                v = {"xor": v ^ sv, "add": v + sv, "sub": v - sv, "and": v & sv, "or": v | sv}[mn]
            reg_consts[cd] = (v & ((1 << bits) - 1), i)
        else:
            reg_consts.pop(cd, None)

    def _track_flow(self, i, mn, op, reg_consts, xmm_consts):
        """One-operand and flow instructions: the stack pointer, pushed constants, calls, branches."""
        frame = self._frame
        step = 8 if self.is64 else 4
        reg = _REG_CANON.get(op)
        if mn == "push":
            frame[_SP] -= step
            pv = _imm(op)
            if pv is None:
                pv = self._const(reg, i, reg_consts)
            self._vstack = self._vstack[-31:] + [pv]
        elif mn == "pop":
            frame[_SP] += step
            pv = self._vstack.pop() if self._vstack else None
            if reg == _SP:
                self._reset_frame()
            elif reg:
                frame.pop(reg, None)
                if pv is not None and _REG_BITS[op] in (32, 64):
                    reg_consts[reg] = (pv & ((1 << _REG_BITS[op]) - 1), i)
                else:
                    reg_consts.pop(reg, None)
        elif mn == "call":
            self._vstack.clear()
            self._harvest_strings()
            for r in ("a", "c", "d", "r8", "r9", "r10", "r11"):
                reg_consts.pop(r, None)
            for r in [r for r in xmm_consts if r[-1] in "012345"]:
                xmm_consts.pop(r, None)
        elif mn == "jmp" or mn[:3] == "ret":
            self._barrier = i  # constants set before this may be from another path
            self._vstack.clear()
        elif mn == "leave":
            if "bp" in frame:
                frame[_SP] = frame.pop("bp") + step
            else:
                self._reset_frame()
        elif reg is not None:
            if reg == _SP:
                self._reset_frame()
            else:
                frame.pop(reg, None)
            if reg in self._smap:
                self._harvest_strings(reg)
            bits = _REG_BITS[op]
            if reg in reg_consts and mn in ("not", "neg", "inc", "dec") and bits in (32, 64):
                v = reg_consts[reg][0]
                v = {"not": ~v, "neg": -v, "inc": v + 1, "dec": v - 1}[mn]
                reg_consts[reg] = (v & ((1 << bits) - 1), i)
            else:
                reg_consts.pop(reg, None)
        elif op and op[-1] == "]" and self._smap and mn not in ("jmp", "call", "push", "nop") and not mn.startswith("j"):
            m = _mem(op)  # inc byte ptr [rsp + 0x20]: that byte is no longer known
            if m and m[1] not in (None, "rip"):
                key, disp = self._slot(m[1], m[4])
                if m[2] is not None:
                    self._harvest_strings(key)
                elif key in self._smap:
                    for d in range(disp, disp + (m[5] or 16)):
                        self._smap[key].pop(d, None)

    def _track_simd(self, off, size, mn, dst, src, xmm_consts):
        """xmm/ymm constants: rip-relative loads of blob data, xor with another constant."""
        if dst[:3] not in ("xmm", "ymm"):
            return
        vex = mn[0] == "v" and src and ", " in src
        width = 32 if dst[0] == "y" else 16
        args = src.split(", ") if vex else [src]
        if mn in _SIMD_LOADS:
            xmm_consts[dst] = self._vec_operand(args[-1], off, size, width, xmm_consts)
        elif mn in _SIMD_XORS:
            a = xmm_consts.get(args[0]) if vex and len(args) == 2 else xmm_consts.get(dst)
            b = self._vec_operand(args[-1], off, size, width, xmm_consts)
            xmm_consts[dst] = bytes(x ^ y for x, y in zip(a, b)) if a and b else None
        else:
            xmm_consts.pop(dst, None)

    def _const(self, reg, i, reg_consts):
        """A register's known value, set on this straight-line path (no jmp/ret since)."""
        if reg in reg_consts:
            v, at = reg_consts[reg]
            if at > self._barrier and i - at <= 256:
                return v
        return None

    def _slot(self, base, disp):
        """Stack-frame registers share one byte map, keyed by offset from the entry stack pointer."""
        if base in self._frame:
            return "frame", self._frame[base] + disp
        return base, disp

    def _reset_frame(self):
        """The stack pointer changed by an unknown amount (and rsp, -16): start a new frame."""
        self._vstack.clear()
        self._harvest_strings("frame")
        self._frame.clear()
        self._frame[_SP] = 0

    def _vec_operand(self, operand, off, size, width, xmm_consts):
        """Bytes of a SIMD source operand: a known register, rip-relative constant data in the
        blob, or known stack bytes."""
        if operand in xmm_consts:
            return xmm_consts[operand]
        if "[rip" not in operand:
            b = _REG_CANON.get(operand[operand.index("[") + 1 :].split(" ", 1)[0].rstrip("]")) if "[" in operand else None
            if b not in self._smap and not (b in self._frame and "frame" in self._smap):
                return None
        m = _mem(operand)
        if not m or m[2] is not None:
            return None
        if m[1] == "rip":
            at = off + size + m[4]
            return bytes(self.buf[at : at + width]) if 0 <= at and at + width <= len(self.buf) else None
        return self._stack_bytes(*self._slot(m[1], m[4]), width) if m[1] else None

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


def find_sleds(data, is64, window, limit):
    """[(start, end)] NOP sleds starting in the first window bytes, for one mode; one that reaches
    the end of the window is followed to its real end (up to limit)."""
    out = []
    for m in SLED_RE[is64].finditer(data, 0, window):
        start, end = m.span()
        if end == window and window < limit:
            end = SLED_RE[is64].match(data, start, limit).end()
        out.append((start, end))
        if len(out) >= MAX_SLEDS:
            break
    return out


def _seeds(buf, md, max_seeds, extra=(), sleds=()):
    seeds = list(extra) + [0]
    for start, end in sleds:
        # code follows the sled; a multi-byte filler (0c 0c: or al, 0xc) may end mid-instruction
        seeds.extend(end - k for k in range(5 if buf[start] in (0x0A, 0x0C, 0x0D) else 1) if 0 <= end - k < len(buf))
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


def _execution_order(d):
    """An island whose blocks are chained by jmps, laid out as it runs: ({virtual offset: insn},
    {virtual: real offset}, backedges). Chaining jmps are dropped, branch targets and RIP-relative
    operands are rewritten for the new offsets, so RIP-relative data still resolves to the blob."""
    insns = d.insns
    junk = d.junk
    order = []
    emitted = set()
    pending = [d.entry] if d.entry in insns else []
    rest = iter(sorted(insns))
    while True:
        a = pending.pop() if pending else next((x for x in rest if x not in emitted and x not in junk), None)
        if a is None:
            break
        while a in insns and a not in emitted and a not in junk:
            emitted.add(a)
            size, mn, op = insns[a]
            tgt = _parse_int(op) if mn == "jmp" or mn == "call" or mn in COND_BRANCHES else None
            if mn == "jmp" and tgt in insns and tgt not in emitted and tgt not in junk:
                a = tgt  # a chaining jmp: carry straight on at its target
                continue
            order.append(a)
            if mn in TERMINATORS:
                break
            if tgt in insns and tgt not in emitted:
                pending.append(tgt)
            a += size
    r2v, v = {}, 0
    for a in order:
        r2v[a] = v
        v += insns[a][0]
    out, backedges = {}, []
    for a in order:
        size, mn, op = insns[a]
        v = r2v[a]
        if mn == "jmp" or mn == "call" or mn in COND_BRANCHES:
            tgt = _parse_int(op)
            if tgt in r2v:
                op = hex(r2v[tgt])
                if r2v[tgt] <= v:
                    backedges.append((v, r2v[tgt]))
        elif "[rip" in op:
            m = _RIP_OPERAND.search(op)
            if m:
                where = a + size + (int(m.group(2), 0) * (-1 if m.group(1) == "-" else 1) if m.group(1) else 0)
                disp = where - (v + size)
                op = op[: m.start()] + f"[rip {'-' if disp < 0 else '+'} {abs(disp):#x}]" + op[m.end() :]
        out[v] = (size, mn, op)
    return out, {v: a for a, v in r2v.items()}, backedges


def _scan_chained(d, ind, is64, va, buf):
    """Jmp-chained code (each block ends in a jmp to the next, blocks out of order) hides every
    multi-instruction pattern from a scan in address order. Scan it again in execution order and
    add what that finds; decoders are left to the normal scan, which reads the blob at real offsets."""
    insns = d.insns
    chained = sum(1 for _, mn, op in insns.values() if mn == "jmp" and _parse_int(op) in insns)
    if chained < CHAINED_MIN_JMPS or chained < CHAINED_JMP_RATIO * len(insns):
        return
    virtual, v2r, backedges = _execution_order(d)
    if len(virtual) < 12:
        return
    ind2 = _Indicators(is64, va, len(buf), buf)
    ind2.nested = True  # indicators only: nothing is decoded from virtual offsets
    ind2.limit = d.far_limit
    ind2._backedges = backedges
    ind2.scan(virtual)

    def real(v):
        return v2r.get(v, v)

    def line(entry):
        off = real(entry[0])
        size_mn_op = insns.get(off)
        return (off, f"{size_mn_op[1]} {size_mn_op[2]}".strip() if size_mn_op else entry[1], entry[2])

    added = False
    for tag, weight in ind2.hits.items():
        if INDICATORS[tag][0] in ("decoders", "framework") or weight <= ind.hits.get(tag, -1):
            continue
        ind.hits[tag] = weight
        added = True
        ind.evidence = [e for e in ind.evidence if e["indicator"] != tag]
        for e in ind2.evidence:
            if e["indicator"] == tag:
                e = dict(e, offset=hex(real(int(e["offset"], 16))))
                if e.get("block"):
                    e["block"] = [line(b) for b in e["block"]]
                ind.evidence.append(e)
    if added:
        ind.add(
            "chained_blocks",
            INFO,
            d.entry or 0,
            f"{chained} jmp-chained blocks out of {len(insns)} instructions: matched in execution order",
        )
    ind.apis |= ind2.apis
    ind.stack_strings.extend(x for x in ind2.stack_strings if x not in ind.stack_strings)
    ind.sockaddrs.extend(x for x in ind2.sockaddrs if x not in ind.sockaddrs)


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
        ind.scan(d.insns, d.junk)
        if len(d.junk) < ninsn:
            _scan_chained(d, ind, is64, va, buf)
        if (
            ninsn >= 32
            and not d.bad_paths
            and not d.rare
            and all(0x20 <= b < 0x7F for o, (size, _, _) in d.insns.items() for b in buf[o : o + size])
        ):
            # text decodes as instructions too, but not cleanly; a printable decoder also has to
            # rewrite memory (xor/sub/add/and into [mem]) with a varied instruction mix
            patches = sum(
                1 for _, mn, op in d.insns.values() if mn in ("xor", "sub", "add", "and") and op.split(", ", 1)[0].endswith("]")
            )
            if patches and len({mn for _, mn, _ in d.insns.values()}) >= 6:
                ind.add(
                    "printable_code",
                    MEDIUM,
                    d.entry or 0,
                    f"{sum(i[0] for i in d.insns.values())} bytes of code, every byte printable; {patches} writes into memory",
                )

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
        # a program built with a runtime (stack checks, /GS cookies) that parses PE files is not a
        # reflective loader: those are built without one
        ind.demote("reflective_pe_loader", MEDIUM)
        ind.demote("exception_control_flow", MEDIUM)

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


def _analyse_mode(buf, mode, va, max_insns, max_seeds, opts, extra_seeds=(), extent=None, sleds=()):
    """Each seed is descended as its own island. Returns (best island, all
    islands worth reporting, far branch targets)."""
    is64 = mode == CS_MODE_64
    md = Cs(CS_ARCH_X86, mode)
    best = None
    good = []
    far = []
    covered = set()  # instructions belonging to coherent islands already seen
    budget = max_insns * 2
    sleds = [s for s in sleds if s[0] < len(buf)]
    for seed in _seeds(buf, md, max_seeds, extra_seeds, sleds):
        if seed in covered or budget <= 0:
            continue
        d = _Descent(buf, mode, min(max_insns, budget), extent, sleds)
        d.run([seed])
        budget -= len(d.insns)
        r = _evaluate_island(buf, d, is64, va, opts)
        r["entry"] = d.entry if d.entry is not None and d.entry < len(buf) else seed  # past a leading sled
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
# Each generator is a module in shellcode_frameworks/ (see its README.md): reported only when
# identified exactly, from the generator's output layout plus an internal consistency check (a
# length field, a computed offset that lands on a PE, a known plaintext). Shared public code that
# other tools copy (e.g. Metasploit's classic block_api) is an indicator, never a framework.

_M32 = 0xFFFFFFFF
EXTRACT_MAX = 32 * 1024 * 1024  # largest payload extracted from a framework layout


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


def framework_family(name):
    """Family reported for an identified framework when it becomes a CAPE detection (the module's
    FAMILY, default its NAME)."""
    from lib.cuckoo.common.integrations import shellcode_frameworks

    return shellcode_frameworks.family(name)


def identify_frameworks(data):
    """Known generator layouts, each matched exactly by its module in shellcode_frameworks/; the
    first identified one wins, as one generator writes the outer layout. Shared public code that
    other tools copy is reported as an indicator instead (block_api_prologue)."""
    from lib.cuckoo.common.integrations import shellcode_frameworks

    found = shellcode_frameworks.identify(data)
    for fw in found:
        fw["label"] = _framework_label(fw)
    return found


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


_INJECT_WRITE = frozenset(
    {"VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "NtWriteVirtualMemory", "NtMapViewOfSection"}
)
_INJECT_EXEC = frozenset(
    {
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "SetThreadContext",
        "NtSetContextThread",
    }
)
_SLEEP_PARTS = (
    frozenset(
        {"CreateTimerQueueTimer", "RtlCreateTimer", "RtlCreateTimerQueue", "RtlRegisterWait", "NtSignalAndWaitForSingleObject"}
    ),
    frozenset({"NtContinue", "RtlCaptureContext"}),
    frozenset({"SystemFunction032", "SystemFunction033"}),
)


def _api_sets(resolved):
    """Scored API combinations, from APIs the code resolves itself (hash constants, stack strings):
    {indicator: [names]}. Import names lying in a mapped image or in compiled code's data never count."""
    found = {}
    write, execute = sorted(resolved & _INJECT_WRITE), sorted(resolved & _INJECT_EXEC)
    if write and execute:
        found["remote_injection"] = write + execute

    def have(*groups):
        """Names resolved, when every group (alternatives separated by spaces) has one; else []."""
        picked = [sorted(resolved & set(g.split())) for g in groups]
        return [n for p in picked for n in p] if all(picked) else []

    sock = have("WSASocketA WSASocketW socket", "connect WSAConnect", "recv WSARecv") or have("bind", "listen", "accept")
    if sock:
        found["socket_stager"] = sock
    http = have(
        "InternetOpenA InternetOpenW", "InternetConnectA InternetConnectW InternetOpenUrlA InternetOpenUrlW", "InternetReadFile"
    ) or have("WinHttpOpen", "WinHttpConnect", "WinHttpReadData WinHttpReceiveResponse")
    if http:
        found["http_stager"] = http
    dlexec = have(
        "URLDownloadToFileA URLDownloadToFileW URLDownloadToCacheFileA",
        "WinExec CreateProcessA CreateProcessW ShellExecuteA ShellExecuteW ShellExecuteExA ShellExecuteExW",
    )
    if dlexec:
        found["download_execute"] = dlexec
    spoof = have("BaseThreadInitThunk", "RtlUserThreadStart") or have(
        "BaseThreadInitThunk RtlUserThreadStart", "RtlLookupFunctionEntry RtlVirtualUnwind"
    )
    if spoof:
        found["stack_spoofing"] = sorted(set(spoof))
    handlers = sorted(resolved & _EXCEPTION_APIS)
    if handlers:
        found["exception_handler_api"] = handlers
    parts = [sorted(resolved & part) for part in _SLEEP_PARTS]
    if sum(bool(p) for p in parts) >= 2:
        found["sleep_obfuscation"] = [n for p in parts for n in p]
    return found


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
        if blob and len(blob) <= EXTRACT_MAX:  # also caps custom modules that do not check it
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

    sleds = {}
    if not result.get("reason") and stats["size"] >= SLED_MIN:
        for is64 in (False, True):
            if arch != ("x86" if is64 else "x64"):
                sleds[CS_MODE_64 if is64 else CS_MODE_32] = find_sleds(data, is64, window, pe_limit)
    # a sled filling the whole window: the code is where it ends
    past_sled = sorted({end for found in sleds.values() for _, end in found if window <= end < size})

    if result.get("reason"):
        pass
    elif stats["size"] < 5:
        result["reason"] = "too small"
    elif not past_sled and (
        stats["distinct_bytes"] < 4 or (stats["size"] >= 64 and stats["size"] - round(stats["zero_ratio"] * stats["size"]) < 16)
    ):
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
            r, good, far = _analyse_mode(buf, mode, va, max_insns, max_seeds, opts, extra, extent=size, sleds=sleds.get(mode, ()))
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
            for end in reversed(past_sled):
                anchors.insert(0, (end, True))
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
                after_sled = ()
                if off in past_sled:
                    lo = off - 8  # keep the sled's last bytes: its filler decides where code may start
                    after_sled = [(0, 8)]
                sub = bytes(memoryview(data)[lo : lo + DEEP_WINDOW_SIZE])
                seen.append((lo, lo + len(sub)))
                win_best = None
                for mode in modes:
                    r, good, _ = _analyse_mode(
                        sub, mode, va, max_insns, max_seeds, opts, [off - lo], extent=size - lo, sleds=after_sled
                    )
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

    # cipher primitives: supporting weight in shellcode, nothing in compiled code or data
    confirmed = result.get("verdict") in ("shellcode", "likely")
    for tag in CIPHER_TAGS + SUPPORT_TAGS:
        if weights.get(tag) == INFO:  # rc4_ksa next to a linked decoder keeps its own weight
            if confirmed:
                weights[tag] = WEAK
            else:
                del weights[tag]
                result["evidence"] = [e for e in result.get("evidence", []) if e["indicator"] != tag]
    if confirmed:
        for tag, what, at in _crypto_tables(
            bytes(data[:pe_limit]) if not isinstance(data, bytes) else data[:pe_limit], embedded, regions
        ):
            weights[tag] = max(weights.get(tag, INFO), WEAK)
            result["evidence"] = result.get("evidence", []) + [{"offset": hex(at), "indicator": tag, "insn": what}]
        if any(s.startswith("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") for s in result.get("stack_strings", ())):
            if "base64_alphabet" not in weights:
                weights["base64_alphabet"] = WEAK
                result["evidence"] = result.get("evidence", []) + [
                    {"offset": "0x0", "indicator": "base64_alphabet", "insn": "Base64 alphabet built on the stack"}
                ]
        crypto_apis = sorted(_CRYPTO_APIS & set(result.get("apis", ())))
        if crypto_apis:
            weights["crypto_api"] = WEAK
            at = next((e["offset"] for e in result.get("evidence", []) if any(n in e["insn"] for n in crypto_apis)), "0x0")
            result["evidence"] = result.get("evidence", []) + [
                {"offset": at, "indicator": "crypto_api", "insn": ", ".join(crypto_apis)}
            ]
    if confirmed:
        led = sleds.get(CS_MODE_64 if result.get("arch") == "x64" else CS_MODE_32) or ()
        entries = {int(i["entry"], 16) for i in islands + [best] if i and isinstance(i.get("entry"), str)}
        led = [se for se in led if any(se[1] - 4 <= e <= se[1] for e in entries)]  # code was found where it ends
        if led:
            start, end = max(led, key=lambda se: se[1] - se[0])
            weights["nop_sled"] = WEAK
            result["evidence"] = result.get("evidence", []) + [
                {"offset": hex(start), "indicator": "nop_sled", "insn": f"{end - start} bytes of sled ending at {end:#x}"}
            ]
    rc4 = sorted({"SystemFunction032", "SystemFunction033"} & set(result.get("apis", ())))
    if rc4 and confirmed:
        weights["rc4_systemfunction"] = WEAK
        at = next((e["offset"] for e in result.get("evidence", []) if any(n in e["insn"] for n in rc4)), "0x0")
        result["evidence"] = result.get("evidence", []) + [
            {"offset": at, "indicator": "rc4_systemfunction", "insn": ", ".join(rc4)}
        ]
    # API combinations resolved by the code itself (before string names from the buffer are merged in)
    if confirmed:
        for tag, names in _api_sets(set(result.get("apis", ()))).items():
            weights[tag] = MEDIUM
            at = next((e["offset"] for e in result.get("evidence", []) if any(n in e["insn"] for n in names)), "0x0")
            result["evidence"] = result.get("evidence", []) + [{"offset": at, "indicator": tag, "insn": ", ".join(names)}]

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
