rule DridexDropper
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 dropper C2 parsing function"
        cape_type = "DridexDropper Payload"

    strings:
        $c2parse_1 = {57 0F 95 C0 89 35 ?? ?? ?? ?? 88 46 04 33 FF 80 3D ?? ?? ?? ?? 00 76 54 8B 04 FD ?? ?? ?? ?? 8D 4D EC 83 65 F4 00 89 45 EC 66 8B 04 FD ?? ?? ?? ?? 66 89 45 F0 8D 45 F8 50}
        $c2parse_2 = {89 45 00 0F B7 53 04 89 10 0F B6 4B 0C 83 F9 0A 7F 03 8A 53 0C 0F B6 53 0C 85 D2 7E B7 8D 74 24 0C C7 44 24 08 00 00 00 00 8D 04 7F 8D 8C 00}
        $c2parse_3 = {89 08 66 39 1D ?? ?? ?? ?? A1 ?? ?? ?? ?? 0F 95 C1 88 48 04 80 3D ?? ?? ?? ?? 0A 77 05 A0 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 56 8B F3 76 4E 66 8B 04 F5}
    condition:
        uint16(0) == 0x5A4D and any of them
}
