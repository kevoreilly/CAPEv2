rule AlienCrypter {
    meta:
        author = "ditekSHen"
        description = "AlienCrypter payload"
        cape_type = "AlienCrypter Payload"
    strings:
        $s1 = ".AlienRunPE." ascii wide
        $s2 = "RunAsNewUser_RunDLL" fullword wide
        $s3 = { 00 50 52 4f 43 45 53 53 5f 53 55 53 50 45 4e 44 5f 52 45 53 55 4d 45 00 64 6e 6c 69 62 2e 50 45 00 }
        $s4 = { 2e 41 6c 69 65 6e 52 75 6e 50 45 00 50 52 4f 43 45 53 53 5f 54 45 52 4d 49 4e 41 54 45 00 }
        $s5 = "@@@http" wide
        $resp1 = "</p><p>@@@77,90," ascii wide
        $resp2 = "</p><p>@@@HH,JA," ascii wide
    condition:
        (uint16(0) == 0x5a4d and 3 of them) or (1 of ($resp*) and 2 of ($s*))
}
