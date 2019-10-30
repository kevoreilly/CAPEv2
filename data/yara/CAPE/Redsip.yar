rule Redsip
{
    meta:
        author = "kev"
        description = "Redsip Payload"
        cape_type = "Redsip Payload"
    strings:
        $payload1 = {8B 45 F8 99 B9 0A 00 00 00 F7 F9 85 D2 75 1F 8A 55 10 88 55 FF 8B 45 08 03 45 F8 0F BE 08 0F BE 55 FF 33 CA 8B 45 08 03 45 F8 88 08 EB C1}
    condition:
        uint16(0) == 0x5A4D and (any of ($payload*))
}
