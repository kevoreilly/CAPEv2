rule UrsnifV3
{
    meta:
        author = "kevoreilly"
        description = "UrsnifV3 Payload"
        cape_type = "UrsnifV3 Payload"
        packed = "75827be0c600f93d0d23d4b8239f56eb8c7dc4ab6064ad0b79e6695157816988"
        packed = "5d6f1484f6571282790d64821429eeeadee71ba6b6d566088f58370634d2c579"
    strings:
        $crypto32_1 = {8B C3 83 EB 01 85 C0 75 0D 0F B6 16 83 C6 01 89 74 24 14 8D 58 07 8B C2 C1 E8 07 83 E0 01 03 D2 85 C0 0F 84 AB 01 00 00 8B C3 83 EB 01 85 C0 89 5C 24 20 75 13 0F B6 16 83 C6 01 BB 07 00 00 00}
        $crypto32_2 = {8B 45 ?? 0F B6 3? FF 45 [2-4] 8B C? 23 C? 40 40 D1 E? 7?}
        $crypto32_3 = {F6 46 03 02 75 5? 8B 46 10 40 50 E8 [10-12] 74 ?? F6 46 03 01 74}
        $crypto32_4 = {C7 44 24 10 01 00 00 00 8B 4? 10 [12] 8B [2] 89 01 8B 44 24 10 5F 5E 5B 8B E5 5D C2 0C 00}
        $cpuid = {8B C4 FF 18 8B F0 33 C0 0F A2 66 8C D8 66 8E D0 8B E5 8B C6 5E 5B 5D C3}
        $cape_string = "cape_options"
    condition:
        uint16(0) == 0x5A4D and 1 of ($crypto32_*) and $cpuid and not $cape_string
}
