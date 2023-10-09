rule Bazar
{
    meta:
        author = "kevoreilly"
        cape_type = "Bazar Payload"
    strings:
        $decode = {F7 E9 [0-2] C1 FA 0? 8B C2 C1 E8 1F 03 D0 6B C2 ?? 2B C8}
        $rsa    = {C7 00 52 53 41 33 48 8D 48 09 C7 40 04 00 08 00 00 4C 8D 05 [3] 00 C6 40 08 03 B8 09 00 00 00 [0-3] 48 8D 89 80 00 00 00 41 0F 10 00}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
