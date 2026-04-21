rule STXRatLoader
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/stx-rat-a-new-rat-in-2026-with-infostealer-capabilities"
        cape_type = "STXRat Loader"
    strings: 
        
        // Kernel32 ROR-14
        $ror1 = { B9 4E 15 F5 1F E8 }
        // VirtualProtect ROR-14
        $ror2 = {
            BA 35 EC 33 57
            48 8B C8
            48 8B D8
            E8
        }
        // CreateThread ROR-14
        $ror3 = {
            BA 36 91 AC 32
        }
        // Ntdll ROR-14
        $ror4 = {
            BA 7E 91 90 5A
            48 8B C8
            E8
        }
        // XXTEA constant
        $s1 = {
            69 D0 47 86 C8 61
        }
        // Zlib
        $s2 = {
            B8 85 10 42 08
            41 F7 E2
        }
        // ROR
        $s3 = {
            41 C1 C8 0E
            0F BE C0
            44 03 C0
        }
        $init = "init"
        $run = "run"
    condition: 
        uint16(0) == 0x5a4d and $init and $run and 1 of ($ror*) and 1 of ($s*)
}

rule STXRat 
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/stx-rat-a-new-rat-in-2026-with-infostealer-capabilities"
        cape_type = "STXRat Payload"
    strings: 
        
        // Lowercasing
        $s1 = {
            8D 51 BF
            83 FA 19
            8D 41 20
            0F 47 C1
            C2 
        }
        // AMSI ghosting
        $s2 = {
            48 8D 05 ?? ?? ?? ??
            66 C7 45 ?? 48 B8 [0-6]
            48 89 45 ??
            48 8D 55 ??
            66 C7 45 ?? FF E0
        }
        // Debugger check
        $s3 = {
            65 48 8B 04 25 60 00 00 00
            80 78 02 01
        }
        // Crypto string
        $s4 = "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)" ascii
        
        // AES key/size/algo handling
        $s5 = {
            B9 10 66 00 00 [0-3]
            0F 44 C1
            B9 0F 66 00 00
            41 81 ?? C0 00 00 00
            0F 44 C1
            B9 0E 66 00 00
        }
        // module name copying
        $s6 = {
            48 83 FB 5A
            73 ??
            88 84 1C ?? ?? ?? ??
            48 FF C3
            48 FF C1
            8A 01
            84 C0
            75
        }
        // Sha1 initialization constants
        $s7 = {
            83 61 18 00
            83 61 14 00
            C7 01 01 23 45 67
            C7 41 04 89 AB CD EF
            C7 41 08 FE DC BA 98
            C7 41 0C 76 54 32 10
            C7 41 10 F0 E1 D2 C3
            C3
        }
        // X25519 clamping
        $s8 = {
            80 61 1F 3F
            80 49 1F 40
            80 21 F8
        }
    condition: 
        uint16(0) == 0x5a4d and (4 of ($s*))
}
