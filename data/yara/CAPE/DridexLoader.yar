rule DridexLoader
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 dropper C2 parsing function"
        cape_type = "DridexLoader Payload"

    strings:
        $c2parse_1 = {57 0F 95 C0 89 35 [4] 88 46 04 33 FF 80 3D [4] 00 76 54 8B 04 FD [4] 8D 4D EC 83 65 F4 00 89 45 EC 66 8B 04 FD [4] 66 89 45 F0 8D 45 F8 50}
        $c2parse_2 = {89 45 00 0F B7 53 04 89 10 0F B6 4B 0C 83 F9 0A 7F 03 8A 53 0C 0F B6 53 0C 85 D2 7E B7 8D 74 24 0C C7 44 24 08 00 00 00 00 8D 04 7F 8D 8C 00}
        $c2parse_3 = {89 08 66 39 1D [4] A1 [4] 0F 95 C1 88 48 04 80 3D [4] 0A 77 05 A0 [4] 80 3D [4] 00 56 8B F3 76 4E 66 8B 04 F5}
        $c2parse_4 = {0F B7 C0 89 01 A0 [4] 3C 0A 77 ?? A0 [4] A0 [4] 57 33 FF 84 C0 74 ?? 56 BE}
        $c2parse_5 = {0F B7 05 [4] 89 02 89 15 [4] 0F B6 15 [4] 83 FA 0A 7F 07 0F B6 05 [4] 0F B6 05 [4] 85 C0}
        $c2parse_6 = {0F B7 53 ?? 89 10 0F B6 4B ?? 83 F9 0A 7F 03 8A 53 ?? 0F B6 53 ?? 85 D2 7E B9}
    condition:
        uint16(0) == 0x5A4D and any of them
}
