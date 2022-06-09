rule Blister
{
    meta:
        author = "kevoreilly"
        description = "Blister Loader"
        cape_type = "Blister Loader"
    strings:
        $protect = {50 6A 20 8D 45 ?? 50 8D 45 ?? 50 6A FF FF D7}
        $lock = {56 33 F6 B9 FF FF FF 7F 89 75 FC 8B C1 F0 FF 45 FC 83 E8 01 75 F7}
        $comp = {6A 04 59 A1 [4] 8B 78 04 8B 75 08 33 C0 F3 A7 75 0B 8B 45 0C 83 20 00 33 C0 40 EB 02 33 C0}
     condition:
        uint16(0) == 0x5A4D and 2 of them
}
