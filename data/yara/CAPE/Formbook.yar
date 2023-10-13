rule Formbook
{
    meta:
        author = "kevoreilly"
        description = "Formbook Payload"
        cape_type = "Formbook Payload"
        packed = "9e38c0c3c516583da526016c4c6a671c53333d3d156562717db79eac63587522"
        packed = "2379a4e1ccdd7849ad7ea9e11ee55b2052e58dda4628cd4e28c3378de503de23"
    strings:
        $remap_ntdll = {33 56 0? 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
        $rc4dec = {F7 E9 C1 FA 03 8B C2 C1 E8 1F 03 C2 8D 04 80 03 C0 03 C0 8B D1 2B D0 8A 04 3A 88 8C 0D [4] 88 84 0D [4] 41 81 F9 00 01 00 00 7C}
        $decrypt = {8A 50 01 28 10 48 49 75 F7 83 FE 01 76 14 8B C7 8D 4E FF 8D 9B 00 00 00 00 8A 50 01 28 10 40 49 75 F7}
        $string = {33 C0 66 39 01 74 0B 8D 49 00 40 66 83 3C 41 00 75 F8 8B 55 0C 8D 44 00 02 50 52 51 E8}
        $mutant = {64 A1 18 00 00 00 8B 40 ?? 89 45 ?? 8B 45 ?? 8B 40 ?? 8B E5 5D C3}
        $postmsg = {8B 7D 0C 6A 00 6A 00 68 11 01 00 00 57 FF D6 85 C0 75 ?? 50}
    condition:
        2 of them
}