rule Gootkit
{
    meta:
        author = "kevoreilly"
        description = "Gootkit Payload"
        cape_type = "Gootkit Payload"
    strings:
        $code1 = {C7 45 ?? ?? ?? 4? 00 C7 45 ?? ?? 10 40 00 C7 45 E? D8 ?? ?? 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 [1-2] 00 10 40 00 89 [5-6] 43 00 89 ?? ?? 68 E8 80 00 00 FF 15}
    condition:
        uint16(0) == 0x5A4D and all of them
}
