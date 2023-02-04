rule Spyro {
    meta:
        author = "ditekSHen"
        description = "Detects Spyro / VoidCrypt / Limbozar ransomware"
        cape_type = "Spyro Payload"
    strings:
        $s1 = "Decrypt-info.txt" ascii wide
        $s2 = "AbolHidden" ascii wide
        $s3 = "C:\\ProgramData\\prvkey" ascii wide
        $s4 = ".?AV?$TF_CryptoSystemBase@VPK_Encryptor@CryptoPP" ascii
        $s5 = "C:\\Users\\LEGION\\" ascii
        $s6 = "C:\\ProgramData\\pkey.txt" fullword ascii
        $s7 = ".Spyro" fullword ascii
        $m1 = "Go to C:\\ProgramData\\ or in Your other Drives" wide
        $m2 = "saving prvkey.txt.key file will cause" wide
        $m3 = "in Case of no Answer:" wide
        $m4 = "send us prvkey*.txt.key" wide
        $m5 = "Somerhing went wrong while writing payload on disk" ascii
        $m6 = "this country is forbidden.\"}" ascii
        $c1 = "Voidcrypt/1.0" ascii
        $c2 = "h1dd3n.cc" ascii
        $c3 = "/voidcrypt/index.php" ascii
        $c4 = "&user=" ascii
        $c5 = "&disk-size=" ascii
        $c6 = "unique-id=" ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 4 of ($c*) or 3 of ($m*) or 8 of them)
}
