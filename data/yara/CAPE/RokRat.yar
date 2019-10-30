rule RokRat
{
    meta:
        author = "kevoreilly"
        description = "RokRat Payload"
        cape_type = "RokRat Payload"
    strings:
        $code1 = {8B 57 04 8D 7F 04 33 57 FC 81 E2 FF FF FF 7F 33 57 FC 8B C2 24 01 0F B6 C0 F7 D8 1B C0 D1 EA 25 DF B0 08 99 33 87 30 06 00 00 33 C2 89 87 3C F6 FF FF 83 E9 01 75 C9}
        $string1 = "/pho_%s_%d.jpg" wide
    condition:
        uint16(0) == 0x5A4D and (any of ($code*)) and (any of ($string*))
}