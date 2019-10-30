rule Hancitor
{
    meta:
        author = "kevoreilly"
        description = "Hancitor Payload"
        cape_type = "Hancitor Payload"
    strings:
        $decrypt1 = {33 C9 03 D6 C7 45 FC ?? ?? ?? ?? 8B 70 10 85 F6 74 12 90 8B C1 83 E0 03 8A 44 05 FC 30 04 11 41 3B CE 72 EF}
        $decrypt2 = {B9 08 00 00 00 8B 75 08 83 C4 04 8B F8 3B D1 76 10 8B C1 83 E0 07 8A 04 30 30 04 31 41 3B CA 72 F0 8D 45 FC}
        $decrypt3 = {8B 45 FC 33 D2 B9 08 00 00 00 F7 F1 8B 45 08 0F BE 0C 10 8B 55 08 03 55 FC 0F BE 02 33 C1 8B 4D 08 03 4D FC 88 01 EB C7}
    condition:
        uint16(0) == 0x5A4D and (any of ($decrypt*))
}
