import logging
import yara
import re

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    log.error("sudo -u cape poetry run pip install unicorn")

rule = """
    rule Hunting_Rule_ShikataGaNai_Modified {
        meta:
            author    = "Steven Miller"
            company   = "FireEye"
            reference = "https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html"
            id = "fe266a42-0480-5a98-9368-8a18aa5e4f69"
            modified_by = "Mohannad Raafat"

        strings:
            // CASE-1: If the shellcode starts with moving the XOR Key
            $varInitializeAndXorCondition1_XorEAX = { B8 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
            $varInitializeAndXorCondition1_XorEBP = { BD ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
            $varInitializeAndXorCondition1_XorEBX = { BB ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
            $varInitializeAndXorCondition1_XorECX = { B9 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
            $varInitializeAndXorCondition1_XorEDI = { BF ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
            $varInitializeAndXorCondition1_XorEDX = { BA ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }

            // CASE-2: If the shellcode starts with 'fcmovu' instruction and 'fnstenv'
            $varInitializeAndXorCondition2_XorEAX = { (DA | DB | DC | DD) ?? D9 74 24 F4 [0-30] B8 ?? ?? ?? ?? [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
            $varInitializeAndXorCondition2_XorEBP = { (DA | DB | DC | DD) ?? D9 74 24 F4 [0-30] BD ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
            $varInitializeAndXorCondition2_XorEBX = { (DA | DB | DC | DD) ?? D9 74 24 F4 [0-30] BB ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
            $varInitializeAndXorCondition2_XorECX = { (DA | DB | DC | DD) ?? D9 74 24 F4 [0-30] B9 ?? ?? ?? ?? [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
            $varInitializeAndXorCondition2_XorEDI = { (DA | DB | DC | DD) ?? D9 74 24 F4 [0-30] BF ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
            $varInitializeAndXorCondition2_XorEDX = { (DA | DB | DC | DD) ?? D9 74 24 F4 [0-30] BA ?? ?? ?? ?? [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }

            // CASE-3: If the shellcode starts with 'fcmovu' instruction and moving the XOR Key
            $varInitializeAndXorCondition3_XorEAX = { (DA | DB | DC | DD) ?? B8 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
            $varInitializeAndXorCondition3_XorEBP = { (DA | DB | DC | DD) ?? BD ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
            $varInitializeAndXorCondition3_XorEBX = { (DA | DB | DC | DD) ?? BB ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
            $varInitializeAndXorCondition3_XorECX = { (DA | DB | DC | DD) ?? B9 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
            $varInitializeAndXorCondition3_XorEDI = { (DA | DB | DC | DD) ?? BF ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
            $varInitializeAndXorCondition3_XorEDX = { (DA | DB | DC | DD) ?? BA ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }
        condition:
            any of them
    }
    """


def hook_getShellCode(uc, address, size, mode):
    ins = uc.mem_read(address, size)

    # After the shellcode is decoded, there is a near relative 'call' instruction 
    # with fixed opcodes '\xE8\x8F\x00\x00\x00'
    if ins == (b"\xE8\x8F\x00\x00\x00"):
        log.info(f"[!] Reached to the end of decoding the shellcode at: {hex(address)}")
        uc.emu_stop()

    return True


def emulate(binaryEP: bytes, binarySize: int, hook=None):
    stackAddr = 0x00020000
    stackSize = 0x00010000
    codeAddr = 0x00040000
    codeSize = 0x1000

    uc = Uc(UC_ARCH_X86, UC_MODE_32)

    ## Stack Initialization
    uc.mem_map(stackAddr, stackSize)
    regESP = stackAddr + stackSize // 2
    uc.reg_write(UC_X86_REG_ESP, regESP)

    ## Code Initialization
    uc.mem_map(codeAddr, codeSize)
    uc.mem_write(codeAddr, binaryEP)

    if hook:
        uc.hook_add(UC_HOOK_CODE, hook, user_data=UC_MODE_32)

    uc.emu_start(codeAddr, codeAddr + binarySize)
    return uc


def extract_config(data: bytes):
    patternIP_PORT = re.compile(rb'\x68(....)\x68..(..)\x89', re.DOTALL)
    config_dict = {}

    yaraRules = yara.compile(source=rule)
    yaraHit = yaraRules.match(data=data)
    shellCodeSize = 0x400  ## Most of the Metasploit payloads' size between 0x150 and 0x390
    shellCodeStartOffset = 0

    if yaraHit:
        for item in yaraHit[0].strings:
            for instance in item.instances:

                ## Sometimes, there are more than one hits, so to reduce wrong offset, matched bytes size should be
                #  lower than or equal to 25 bytes
                if len(instance.matched_data) <= 25:
                    shellCodeStartOffset = instance.offset

        log.info(f"[!] Got the shellcode offset at: {hex(shellCodeStartOffset)}")
        shellCode = data[shellCodeStartOffset: shellCodeStartOffset + shellCodeSize]

        try:
            log.info(f"[!] Start emulating the shellcode")
            uc = emulate(shellCode, shellCodeSize, hook_getShellCode)
            unpackedSC = uc.mem_read(0x40000, shellCodeSize)

            matches = patternIP_PORT.findall(unpackedSC)
            if matches:
                ip = ''.join('.'.join(f'{c}' for c in matches[0][0]))
                port = int.from_bytes(matches[0][1], byteorder='big')

                config_dict["C2"] = ip
                config_dict["Port"] = port

            return config_dict

        except:
            log.error("[x] Failed to emulate the shellcode\n\n")
            return