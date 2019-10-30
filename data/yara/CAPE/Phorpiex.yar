rule Phorpiex
{
    meta:
        author = "kevoreilly"
        description = "Phorpiex Payload"
        cape_type = "Phorpiex Payload"
    strings:
        $code = {99 B9 FF 00 00 00 F7 F9 83 C2 01 52 E8 0F 0D 00 00 99 B9 FF 00 00 00 F7 F9 83 C2 01 52 E8 FE 0C 00 00 99 B9 FF 00 00 00 F7 F9 83 C2 01 52 E8 ED 0C 00 00 99}
    condition:
        uint16(0) == 0x5A4D and ($code)
}
