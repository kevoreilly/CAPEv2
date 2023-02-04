rule GoldenAxe {
    meta:
        author = "ditekshen"
        description = "GoldenAxe ransomware payload"
        cape_type = "GoldenAxe payload"
    strings:
        $s1 = "Go build ID: " ascii
        $s2 = "taskkill.exe" ascii
        $s3 = "cmd.exe" ascii
        $s4 = "Speak.Speak" ascii
        $s5 = "CLNTSRVRnull" ascii
        $s6 = "-----END" ascii
        $s7 = "-----BEGIN" ascii
        $s8 = ".EncryptFile" ascii
        $g1 = "GoldenAxe/Utils." ascii
        $g2 = "GoldenAxe/Cryptography." ascii
        $g3 = "GoldenAxe/Walker." ascii
        $g4 = "C:/Users/alpha/go/src/GoldenAxe/" ascii
        $g5 = "'Golden Axe ransomware'" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($g*) and 1 of ($s*)))
}
