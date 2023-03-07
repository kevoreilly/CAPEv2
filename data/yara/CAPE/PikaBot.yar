rule PikaBotLoader
{
    meta:
        author = "kevoreilly"
        description = "PikaBot Loader"
        cape_type = "PikaBot Loader"
        packed = "c666aeb7ed75e58b645a2a4d1bc8c9d0a0a076a8a459e33c6dc60d12f4fa0c01"
    strings:
        $sub = {8A 44 0D ?? 2C ?? 88 44 0D ?? 41 83 F9 0C 7C F0}
        $xor = {8A 44 0D ?? 34 ?? 88 44 0D ?? 41 83 F9 0C 7C F0}
        $antivm = {33 C0 B8 00 00 00 40 0F A2 81 F9 72 65 56 4D 75 ?? 81 FA 77 61 72 65 75}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule PikaBot
{
    meta:
        author = "kevoreilly"
        description = "PikaBot Payload"
        cape_type = "PikaBot Payload"
        hash = "59f42ecde152f78731e54ea27e761bba748c9309a6ad1c2fd17f0e8b90f8aed1"
    strings:
        $setz = {83 FB 01 74 06 43 83 FB 06 7C ?? 8B 84 9D [2] FF FF 33 DB 33 C1 39 85 [2] FF FF 0F 95 C3 EB 06}
    condition:
        uint16(0) == 0x5A4D and all of them
}
