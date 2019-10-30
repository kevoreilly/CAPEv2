rule TClient
{
    meta:
        author = "kevoreilly"
        description = "TClient Payload"
        cape_type = "TClient Payload"
    strings:
        $code1 = {41 0F B6 00 4D 8D 40 01 34 01 8B D7 83 E2 07 0F BE C8 FF C7 41 0F BE 04 91 0F AF C1 41 88 40 FF 81 FF 80 03 00 00 7C D8}
    condition:
        uint16(0) == 0x5A4D and any of ($code*)
}