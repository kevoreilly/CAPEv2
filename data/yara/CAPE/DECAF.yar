rule DECAF {
    meta:
        author = "ditekSHen"
        description = "Detects DECAF ransomware"
        cape_type = "DECAF Payload"
    strings:
        $s1 = "main.EncWorker" fullword ascii
        $s2 = "Paths2Encrypt" fullword ascii
        $s3 = "/cmd/encryptor/main.go" ascii
        $s4 = "*win.FileUtils; .autotmp_41 *lib.Encryptor; .autotmp_" ascii
        $s5 = "\"Microsoft Window" fullword wide
        $s6 = "Legal_Policy_Statement" fullword wide
        $s7 = ").Encrypt." ascii
        $s8 = "*struct { F uintptr; pw *os.File; c *" ascii
        $s9 = ".ListFilesToEnc." ascii
        $m1 = "WINNER WINNER CHICKEN DINNER" ascii
        $m2 = "All your servers and computers are encrypted" ascii
        $m3 = "We guarantee to decrypt one image file for free." ascii
        $m4 = "We WILL NOT be able to RESTORE them." ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or 3 of ($m*) or (1 of ($m*) and 2 of ($s*)))
}
