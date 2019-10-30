rule QakBot
{
    meta:
        author = "kevoreilly"
        description = "QakBot Payload"
        cape_type = "QakBot Payload"
    strings:
        $crypto = {8B 5D 08 0F B6 C2 8A 16 0F B6 1C 18 88 55 13 0F B6 D2 03 CB 03 CA 81 E1 FF 00 00 80 79 08 49 81 C9 00 FF FF FF 41}
        $anti_sandbox = {8D 4D FC 51 E8 ?? ?? ?? ?? 83 C4 04 E8 ?? ?? ?? ?? 85 C0 7E 07 C7 45 F8 00 00 00 00 33 D2 74 02 EB FA 8B 45 F8 EB 08 33 C0 74 02 EB FA 33 C0 8B E5 5D C3}
        $decrypt_config1 = {FF 37 83 C3 EC 53 8B 5D 0C 8D 43 14 50 6A 14 53 E8 ?? ?? ?? ?? 83 C4 14 85 C0 ?? 26 ?? ?? 86 20 02 00 00 66 85 C0 ?? ?? FF 37 FF 75 10 53}
        $decrypt_config2 = {8B 45 08 8B 88 24 04 00 00 51 8B 55 10 83 EA 14 52 8B 45 0C 83 C0 14 50 6A 14 8B 4D 0C 51 E8 6C 08 00 00}
    condition:
        uint16(0) == 0x5A4D and any of ($*)
}
