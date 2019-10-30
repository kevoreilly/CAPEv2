rule Ursnif
{
    meta:
        author = "kevoreilly & enzo"
        description = "Ursnif Payload"
        cape_type = "Ursnif Payload"
    strings:
        $crypto64_1 = {41 8B 02 ?? C1 [0-1] 41 33 C3 45 8B 1A 41 33 C0 D3 C8 41 89 02 49 83 C2 04 83 C2 FF 75 D?}
        $crypto64_2 = {44 01 44 24 10 FF C1 41 8B C0 D1 64 24 10 33 C3 41 8B D8 FF 4C 24 10 41 33 C3 01 44 24 10 D3 C8 01 44 24 10 41 89 02 49 83 C2 04 83 C2 FF 75 C3}
        $crypto64_3 = {33 C6 ?? C7 [0-1] 49 83 C2 04 33 C3 8B F1 8B CF D3 C8 89 02 48 83 C2 04 41 83 C3 FF 75 ?? 45 85 C9 75 ?? 41 83 E0 03}
        $crypto64_4 = {41 8B 02 41 8B CB 41 83 F3 01 33 C3 41 8B 1A C1 E1 03 41 33 C0 D3 C8 41 89 02 49 83 C2 04 83 C2 FF 75 C6}
        $decrypt_config64 = {44 8B D9 33 C0 45 33 C9 44 33 1D ?? ?? ?? 00 ?? ?? D2 ?? ?? D2 74 ?? 4C 8D 42 10 45 3B 0A 73 2? 45 39 58 F8 75 1C 41 F6 40 FC 01 74 12}

        $crypto32_1 = {01 45 FC D1 65 FC FF 4D FC 33 C1 33 45 0C 01 45 FC 43 8A CB D3 C8 8B CE 01 45 FC 89 02 83 C2 04 FF 4D 08 75 CD}
        $crypto32_2 = {33 C1 33 44 24 10 43 8A CB D3 C8 8B CE 89 02 83 C2 04 FF 4C 24 0C 75 D9}
        $decrypt_config32 = {8B ?? 08 5? 33 F? 3B [1-2] 74 14 A1 0? ?? ?? ?? 35 ?? ?? ?? ?? 50 8B D? E8 ?? D? 00 00 EB 02 33 C0 ?B ?? ?? ?? ?? ?? ?? ?? 74 14 8D 4D ?? ?? ?? 50 FF D? 85 C0 74 08}
    condition:
        uint16(0) == 0x5A4D and ($decrypt_config64 and any of ($crypto64*)) or ($decrypt_config32 and any of ($crypto32*))
}
