rule citadel {
    meta:
        author      = "CERT.pl"
        description = "Citadel Configuration Extractor"
    strings:
        $briankerbs = "Coded by BRIAN KREBS for personal use only. I love my job & wife."

        $cit_aes_xor = {81 30 [4] 0F B6 50 03 0F B6 78 02 81 70 04 [4] 81 70 08 [4] 81 70 0C [4] C1 E2 08 0B D7 }
        $cit_salt = { 8A D1 80 E2 07 C0 E9 03 47 83 FF 04 }
        $cit_login = { 30 [1-2] 8A 8? [4] 32  }
        // $cit_getpes_0 = { 68 [2] 00 00 8D 85 [4] 50 8D  85 [4] 50 E8 [4] B8 [2] 00 00 50 68 [4]}
        // $cit_getpes_1 = { 68 [2] 00 00 8D 84 24 [4] 50 8D 44 24 ?? 50 E8 [4] B8 [2] 00 00 50 68 [4]
        $cit_getpes = { 68 [2] 00 00 8D ( 84 24 | 85) [4] 50 8D ( 85 ?? ?? ?? ?? | 44 24 ?? ) 50 E8 [4] B8 [2] 00 00 50 68 }
        $cit_base_off = { 5? 8D 85 [4] E8 [4] 6A 20 68 [4] 8D [2] 50 E8 [4] 8D 85 [4] 50 }
    condition:
        3 of them
}
