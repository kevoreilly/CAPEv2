rule QakBot5
{
    meta:
        author = "kevoreilly, enzok"
        description = "QakBot v5 Payload"
        cape_type = "QakBot Payload"
        packed = "f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2"
        hash = "59559e97962e40a15adb2237c4d01cfead03623aff1725616caeaa5a8d273a35"
    strings:
        $loop = {8B 75 ?? 48 8B 4C [2] FF 15 [4] 48 8B 4C [2] 48 8B 01 FF 50 ?? 8B DE 48 8B 4C [2] 48 85 C9 0F 85 [4] EB 4E}
        $c2list = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 45 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}
        $campaign = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 44 24 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule QakBot4
{
    meta:
        author = "kevoreilly"
        description = "QakBot v4 Payload"
        cape_type = "QakBot Payload"
    strings:
        $crypto1 = {8B 5D 08 0F B6 C2 8A 16 0F B6 1C 18 88 55 13 0F B6 D2 03 CB 03 CA 81 E1 FF 00 00 80 79 08 49 81 C9 00 FF FF FF 41}
        $sha1_1 = {5? 33 F? [0-9] 89 7? 24 ?? 89 7? 24 ?? 8? [1-3] 24 [1-4] C7 44 24 ?0 01 23 45 67 C7 44 24 ?4 89 AB CD EF C7 44 24 ?8 FE DC BA 98 C7 44 24 ?C 76 54 32 10 C7 44 24 ?0 F0 E1 D2 C3}
        $sha1_2 = {33 C0 C7 01 01 23 45 67 89 41 14 89 41 18 89 41 5C C7 41 04 89 AB CD EF C7 41 08 FE DC BA 98 C7 41 0C 76 54 32 10 C7 41 10 F0 E1 D2 C3 89 41 60 89 41 64 C3}
        $anti_sandbox1 = {8D 4? FC [0-1] E8 [4-7] E8 [4] 85 C0 7E (04|07) [4-7] 33 (C0|D2) 74 02 EB FA}
        $anti_sandbox2 = {8D 45 ?? 50 E8 [2] 00 00 59 68 [4] FF 15 [4] 89 45 ?? 83 7D ?? 0F 76 0C}
        $decrypt_config1 = {FF 37 83 C3 EC 53 8B 5D 0C 8D 43 14 50 6A 14 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 ?? 26 ?? ?? 86 20 02 00 00 66 85 C0 ?? ?? FF 37 FF 75 10 53}
        $decrypt_config2 = {8B 45 08 8B 88 24 04 00 00 51 8B 55 10 83 EA 14 52 8B 45 0C 83 C0 14 50 6A 14 8B 4D 0C 51 E8 6C 08 00 00}
        $decrypt_config3 = {6A 13 8B CE 8B C3 5A 8A 18 3A 19 75 05 40 41 4A 75 F5 0F B6 00 0F B6 09 2B C1 74 05 83 C8 FF EB 0E}
        $call_decrypt = {83 7D ?? 00 56 74 0B FF 75 10 8B F3 E8 [4] 59 8B 45 0C 83 F8 28 72 19 8B 55 08 8B 37 8D 48 EC 6A 14 8D 42 14 52 E8}
    condition:
        uint16(0) == 0x5A4D and any of ($*)
}
