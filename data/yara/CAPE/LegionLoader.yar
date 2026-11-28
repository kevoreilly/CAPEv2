rule LegionLoader {
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/romulus-clickfix-to-legionloader-and-warden-stealer-breaking-down-a-multi-stage-malware-intrusion"
        cape_type = "LegionLoader Payload"
    strings:
        $crc32 = {
            8B 04 24 D1 E8 8B 4C 24 ??
            81 E1 20 83 B8 ED 33 C1 89 04 24
        }
        $rc4_ksa = {
            81 7C 24 ?? 00 01 00 00 7D ??
            48 63 44 24 ?? 0F B6 44 04 ?? 8B 4C 24 ??
            03 C8 8B C1 48 63 4C 24 ??
            0F B6 8C 0C ?? ?? ?? ?? 03 C1 25 FF 00 00 00
        }
        $rc4_prga = {
            48 63 44 24 ?? 0F B6 44 04 ??
            48 63 4C 24 ?? 0F B6 4C 0C ??
            03 C1 25 FF 00 00 00 89 44 24 ??
            48 63 44 24 ?? 0F B6 44 04 ?? 88 44 24
        }
        $hash_ntdll = { B9 40 5E C0 84 E8 }
        $hash_kernel32 = { B9 02 9F E6 6A E8 }
        $hash_mbstowcs = { BA CD 8F 26 06 48 8B 4C 24 ?? E8 }
        $hash_ntclose = { BA 50 C7 09 0D 48 8B 4C 24 ?? E8 }
        $hash_ntsetcontext = { BA 98 3B 45 E1 48 8B 4C 24 ?? E8 }
        $hash_winhttp_close = { BA F4 F9 29 6A 48 8B 4C 24 ?? E8 }
        $hash_winhttp_send = { BA F7 B4 E9 CE 48 8B 4C 24 ?? E8 }
        $hash_winhttp_connect = { BA C6 B6 50 6F 48 8B 4C 24 ?? E8 }
        $hash_winhttp_receive = { BA F9 61 BB 46 48 8B 4C 24 ?? E8 }
        $hash_shellexecute = {
            BA 99 15 6D 49 48 8B
            (4C 24 ?? | 8C 24 ?? ?? ?? ??) E8
        }
        $feature_lowercase = {
            83 F8 5A 7F ?? 0F BE 44 24 ?? 83 F8 41 7C ??
            0F BE 44 24 ?? 83 C0 20 88 44 24
        }
        $feature_config = {
            BA (3D 49 36 DC | 17 0F 0F FF) 48 8B C8 E8
        }
        $feature_registration = {
            (
                C7 84 24 ?? ?? ?? ?? A7 45 C8 B3
                |
                48 B9 57 69 6E 64 6F 77 73 20 [8-32]
                48 B9 25 64 2E 25 64 2E 25 64
            )
        }
        $feature_suspended = {
            C7 44 24 38 01 00 00 00
            C7 44 24 30 00 02 00 00
            48 C7 44 24 28 00 00 00 00
            48 C7 44 24 20 00 00 00 00
            41 B9 FF FF 1F 00 41 B8 FF FF 1F 00
        }
        $feature_context_flags = {
            C7 84 24 ?? ?? ?? ?? 02 00 10 00
            48 8B 05
        }
        $feature_systemroot = {
            48 C7 44 24 ?? 30 00 FE 7F
            [16-40]
            48 63 44 24 ?? 48 8B 4C 24 ?? 0F B7 04 41 85 C0 74
        }
        $feature_victim_format = {
            B8 04 00 00 00 48 6B C0 00 C7 44 04 ?? 25 30 38 58
        }
    condition:
        uint16(0) == 0x5A4D and
        $crc32 and 1 of ($rc4_*) and
        2 of ($hash_*) and
        2 of ($feature_*)
}
