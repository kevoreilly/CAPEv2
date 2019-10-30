rule tRat
{
    meta:
        author = "kevoreilly"
        description = "tRat Payload"
        cape_type = "tRat Payload"
    strings:
        $code1 = {8D 45 FC E8 ?? ?? ?? ?? 8B 55 FC 0F B6 54 32 FF 66 33 D3 0F B7 D2 2B D6 33 D6 2B D6 33 D6 88 54 30 FF 43 8B 45 FC E8 ?? ?? ?? ?? 0F B7 F3 3B C6 7F CE}
        $code2 = {5A 83 E2 03 74 22 8B 0E 8B 1F 38 D9 75 41 4A 74 17 38 FD 75 3A 4A 74 10 81 E3 00 00 FF 00 81 E1 00 00 FF 00 39 D9 75 27}
        $string1 = "TCComand"
    condition:
        uint16(0) == 0x5A4D and all of them
}