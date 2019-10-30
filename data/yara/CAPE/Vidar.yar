rule Vidar
{
    meta:
        author = "kevoreilly"
        description = "Vidar Payload"
        cape_type = "Vidar Payload"
    strings:
        $decode = {FF 75 0C 8D 34 1F FF 15 ?? ?? ?? ?? 8B C8 33 D2 8B C7 F7 F1 8B 45 0C 8B 4D 08 8A 04 02 32 04 31 47 88 06 3B 7D 10 72 D8}
        $wallet = "*walle*.dat"
    condition:
        uint16(0) == 0x5A4D and all of them
}
