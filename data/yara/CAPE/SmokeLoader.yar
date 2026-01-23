rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        description = "SmokeLoader Payload"
        cape_type = "SmokeLoader Payload"
    strings:
        $rc4_decrypt64_1 = {41 8D 41 01 44 0F B6 C8 42 0F B6 [2] 41 8D 04 12 44 0F B6 D0 42 8A [2] 42 88 [2] 42 88 [2] 42 0F B6 [2] 03 CA 0F B6 C1 8A [2] 30 0F 48 FF C7 49 FF CB 75}
        $rc4_decrypt64_2 = {03 C8 8B C1 89 44 [2] 0F B6 8C [2] 01 00 00 33 D2 8B 04 24 F7 F1 8B C2 8B C0 48 8B 8C [2] 01 00 00 0F B6 04 01 8B 4C [2] 03 C8 8B C1 25 FF 00 00 00}
        $rc4_decrypt64_3 = {8B 04 ?? FF C0 25 FF 00 00 00 89 04 ?? 8B 04 ?? 0F B6 44 [2] 8B 4C [2] 03 C8 8B C1 25 FF 00 00 00}
        $rc4_decrypt32 = {47 B9 FF 00 00 00 23 F9 8A 54 [2] 0F B6 C2 03 F0 23 F1 8A 44 [2] 88 44 [2] 88 54 [2] 0F B6 4C [2] 0F B6 C2 03 C8 81 E1 FF 00 00 00 8A 44 [2] 30 04 2B 43 3B 9C 24 [4] 72 C0}
        $fetch_c2_64 = {74 ?? B? E8 03 00 00 B9 58 02 00 00 FF [5] 48 (FF C?|83 EF 01) 75 (F0|EF)}
        $fetch_c2_32 = {8B 96 [2] (00|01) 00 8B CE 5E 8B 14 95 [4] E9}
    condition:
        2 of them
}
