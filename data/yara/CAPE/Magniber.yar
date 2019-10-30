rule Magniber
{
    meta:
        author = "kevoreilly"
        description = "Magniber Payload"
        cape_type = "Magniber Payload"
    strings:
        $a1 = {8B 55 FC 83 C2 01 89 55 FC 8B 45 FC 3B 45 08 7D 45 6A 01 6A 00 E8 26 FF FF FF 83 C4 08 89 45 F4 83 7D F4 00 75 18 6A 7A 6A 61 E8 11 FF FF FF 83 C4 08 8B 4D FC 8B 55 F8 66 89 04 4A EB 16}
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
