rule BuerLoader
{
    meta:
        author = "Rony (@r0ny_123)"
        cape_type = "BuerLoader"
    strings:
        $s1 = "{%s-%d-%d}" wide ascii
        $s2 = "%02x" wide ascii
        $op = {55 8B EC 53 56 8B 75 08 57 85 F6 74 3? 8B 5D 10 8B 7D 14 85 DB 75 04 85 FF 75 2? [0-5] F? F? F? 8D 50 01 85 FF 75 04 8B C2 EB 1? 33 C0 85 D2 7E 1? 3B C7 7D [0-15] 40 3B C2 7C ?? EB 02}
    condition:
        uint16(0) == 0x5A4D and all of them
}
