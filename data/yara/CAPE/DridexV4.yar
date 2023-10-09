rule DridexV4
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 Payload"
        cape_type = "DridexV4 Payload"
    strings:
        $decrypt32 = {6A 40 58 3B C8 0F 4D C1 39 46 04 7D 50 53 57 8B F8 81 E7 3F 00 00 80 79 05 4F 83 CF C0 47 F7 DF 99 1B FF 83 E2 3F 03 C2 F7 DF C1 F8 06 03 F8 C1 E7 06 57}
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $getproc64 = {81 FB ?? ?? ?? ?? 75 04 33 C0 EB 2D 8B CB E8 ?? ?? ?? ?? 48 85 C0 75 17 8B CB E8 ?? ?? ?? ?? 84 C0 74 E5 8B CB E8 ?? ?? ?? ?? 48 85 C0 74 D9 8B D7 48 8B C8 E8 ?? ?? ?? ?? 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $bot_stub_32 = {8B 45 E? 8? [5-13] 8A 1C 0? [6-15] 05 FF 00 00 00 8B ?? F? 39 ?? 89 45 E? 72 D?}
        $bot_stub_64 = {8B 44 24 ?? 89 C1 89 CA 4C 8B 05 [4] 4C 8B 4C 24 ?? 45 8A 14 11 83 E0 1F 89 C0 41 89 C3 47 2A 14 18 44 88 54 14}
    condition:
        uint16(0) == 0x5A4D and any of them
}
