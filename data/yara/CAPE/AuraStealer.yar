rule AuraStealer
{
    meta:
        author = "enzok"
        description = "AuraStealer Payload"
        cape_type = "AuraStealer Payload"
        unpacked = "a9c47f10d5eb77d7d6b356be00b4814a7c1e5bb75739b464beb6ea03fc36cc85"
        packed = "bac52ffc8072893ff26cdbf1df1ecbcbb1762ded80249d3c9d420f62ed0dc202"
    strings:
        $conf = {8D BE ?? 00 00 00 68 00 40 00 00 5? 5? FF D1 83 C4 ?? 8B 07 8B 57 04 29 C2}
        $key1 = {FF D2 8B 2B 8D 75 ?? 8B 5D ?? 33 5D ?? 8D 45}
        $key2 = {89 0B 89 F9 5? 5? 5? E8 [4] 8B 3F 8D 6F 38 8B 77 30 33 77 34 8D 47 20 8D 4C 24 ?? 89 FA 5? E8}
        $keyexpansion = {31 C0 8A 1C 82 88 1C 81 8A 5C 82 01 88 5C 81 01 8A 5C 82 02 88 5C 81 02 8A 5C 82 03 88 5C 81 03 4? 83 F8 08 75 ?? B? 08 00 00 00}
        $antivm2 = {8B 43 04 8B 0D [4] 3B 81 [4] B? [2] 00 00 B? [2] 00 00 0F 44 D1 85 C0 0F 44 D1 8B 8A [4] 03 8A [4] FF E1 31 FF EB ?? 8B 78 0C 33 78 10 B? [4] 03 05 [4] FF D0}
        $antivm1 = {39 04 11 0f 94 C3 8B 44 ?? ?? 85 C0}
    condition:
        3 of them
}