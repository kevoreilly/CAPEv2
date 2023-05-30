rule PikaBot
{
    meta:
        author = "kevoreilly"
        description = "PikaBot Payload"
        cape_type = "PikaBot Payload"
        hash = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
    strings:
        $rdtsc = {89 55 FC 89 45 F8 0F 31 89 55 F4 89 45 FC 33 C0 B8 05 00 00 00 C1 E8 02 2B C3 3B C1 0F 31 89 55 F0 89 45 F8 8B 44 8D}
        $int2d = {B8 00 00 00 00 CD 2D 90 C3 CC CC CC CC CC CC CC}
        $subsys = {64 A1 30 00 00 00 8B 40 18 C3}
        $rijndael = {EB 0F 0F B6 04 3? FE C? 8A 80 [4] 88 04 3? 0F B6 [3] 7C EA 5? 5? C9 C3}
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
