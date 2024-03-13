rule PikaBotLoader
{
    meta:
        author = "kevoreilly"
        description = "Pikabot Loader"
        cape_type = "PikaBot Loader"
    strings:
        $indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1}
        $sysenter1 = {89 44 24 08 8D 85 ?? FC FF FF C7 44 24 04 FF FF 1F 00 89 04 24 E8}
        $sysenter2 = {C7 44 24 0C 00 00 00 02 C7 44 24 08 00 00 00 02 8B 45 0C 89 44 24 04 8B 45 08 89 04 24 E8}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PikaBot
{
    meta:
        author = "kevoreilly"
        description = "Pikabot Payload"
        cape_type = "PikaBot Payload"
        packed = "89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9"
    strings:
        $decode = {29 D1 01 4B ?? 8D 0C 10 89 4B ?? 85 F6 74 02 89 16}
        $indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1}
        $config = {C7 44 24 [3] 00 00 C7 44 24 [4] 00 89 [1-4] ?? E8 [4] 31 C0 C7 44 24 [3] 00 00 89 44 24 ?? C7 04 24 [4] E8}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Pik23
{
    meta:
        author = "kevoreilly"
        description = "PikaBot Payload February 2023"
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
