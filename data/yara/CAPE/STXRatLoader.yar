import "pe"
rule STXRatLoader
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/stx-rat-a-new-rat-in-2026-with-infostealer-capabilities"
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
    condition: 
        uint16(0) == 0x5a4d and ((pe.exports("init") and pe.exports("run")) and 1 of ($ror*) and 1 of ($s*))
}
