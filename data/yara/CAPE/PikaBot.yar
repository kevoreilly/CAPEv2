rule PikaBot
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
