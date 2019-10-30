rule Nymaim {
    meta:
        author = "mak, msm, CERT.pl"
        contribution = "Slavo Greminger, SWITCH-CERT"
        malpedia_version = "20170621"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:GREEN"
        cape_type = "Nymaim Payload"

    strings:
        $kpatt_1_a = { 8F 45 E8 89 4D E4 E8 [4] 89 C3 E8 [4] 89 C2 89 45 FC 8B 4D E4 B8 }
        $kpatt_1_b = { ?? [3] 29 C1 89 4D E0 C1 E9 02 83 F9 00 74 05 01 D3 }
        $kpatt_2 = { 8B 45 D8 3D [4] 0F 84 [4] 3D [4] 0F 84 [4] 3D [4] 0F 84 }
        $kpatt_3 = { ( 29 C1 89 ?? ?? | 81 E? [4] 5? | 2B ?? ?? 5? )  C1 E9 02 83 F9 00  (74 ?? | 0F 8? [3] ?? )  01 D3 49 (75 | 0F 8? ) }

    condition:
        any of ($kpatt_*)
}
