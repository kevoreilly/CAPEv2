rule Zloader
{
    meta:
        author = "kevoreilly, enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
        hash = "adbd0c7096a7373be82dd03df1aae61cb39e0a155c00bbb9c67abc01d48718aa"
    strings:
        $rc4_init = {31 [1-3] 66 C7 8? 00 01 00 00 00 00 90 90 [0-5] 8? [5-90] 00 01 00 00 [0-15] (74|75)}
        $decrypt_conf = {83 C4 04 84 C0 74 5? E8 [4] E8 [4] E8 [4] E8 [4] ?8 [4] ?8 [4] ?8}
        $decrypt_conf_1 = {48 8d [5-11] e8 [4] 48 [3-4] 48 [3-4] 48 [6] E8}
        $decrypt_conf_2 = {48 8d [5] 4? [5] e8 [4] 48 [3-4] 48 8d [5] E8 [4] 48}
        $decrypt_key_1 = {66 89 C2 4? 8D 0D [3] 00 4? B? FC 03 00 00 E8 [4] 4? 83 C4 [1-2] C3}
        $decrypt_key_2 = {48 8d 0d [3] 00 66 89 ?? 4? 89 F0 4? [2-5] E8 [4-5] 4? 83 C4}
        $decrypt_key_3 = {48 8d 0d [3] 00 e8 [4] 66 89 [3] b? [4] e8 [4] 66 8b}
    condition:
        uint16(0) == 0x5A4D and 1 of ($decrypt_conf*) and (1 of ($decrypt_key*) or $rc4_init)
}

rule Zloader2024
{
    meta:
        author = "enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
        hash = "49405370a33abbf131c5d550cebe00780cc3fd3cbe888220686582ae88f16af7 "
    strings:
        $conf_1 = {48 01 ?? 48 8D 15 [4] 41 B8 ?? 04 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00}
        $confkey_1 = {48 8D 15 [4] 48 89 ?? 49 89 ?? E8 [4] [0-5] C7 [1-2] 00 00 00 00}
        $confkey_2 = {48 01 ?? 48 8D 15 [4] 41 B8 10 00 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00 (48 8B|8B)}
        $confkey_3 = {48 01 ?? 48 8D 15 [4] 41 B8 10 00 00 00 E8 [4] [0-5] C7 [1-2] 00 00 00 00 48 83 C4}
    condition:
        uint16(0) == 0x5A4D and $conf_1 and 2 of ($confkey_*)
}

rule Zloader2025
{
    meta:
        author = "enzok"
        description = "Zloader Payload"
        cape_type = "Zloader Payload"
        hash = "86ffd411b42d8d06bdb294f48e79393adeea586c56c5c75c1a68ce6315932881"
    strings:
        $conf = {4? 01 ?? [4] E8 [4] 4? 8D 15 [4] 4? 89 ?? 4? 89 ?? E8 [4] C7 46 30 00 00 00 00 8B 7E 34}
        $confkey_1 = {4? 01 ?? [2] E8 [4] 4? 8D 15 [4] 4? 89 ?? 4? 89 ?? E8 [4] C7 46 34 00 00 00 00 8B 46 38}
        $confkey_2 = {4? 01 ?? [2] E8 [4] 4? 8D 15 [4] 4? 89 ?? 4? 89 ?? E8 [4] C7 46 38 00 00 00 00 48 83 C4 28}
    condition:
        uint16(0) == 0x5A4D and $conf and all of ($confkey_*)
}
