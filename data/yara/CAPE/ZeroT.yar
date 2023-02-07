rule ZeroT
{
    meta:
        author = "kevoreilly"
        description = "ZeroT Payload"
        cape_type = "ZeroT Payload"
    strings:
        $decrypt = {8B C1 8D B5 FC FE FF FF 33 D2 03 F1 F7 75 10 88 0C 33 41 8A 04 3A 88 06 81 F9 00 01 00 00 7C E0}
        $string1 = "(*^GF(9042&*"
        $string2 = "s2-18rg1-41g3j_.;"
        $string3 = "GET" wide
        $string4 = "open"
    condition:
        uint16(0) == 0x5A4D and all of them
}
