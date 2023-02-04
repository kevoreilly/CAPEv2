rule PYSA {
    meta:
        author = "ditekSHen"
        description = "PYSA/Mespinoza ransomware payload"
        cape_type = "PYSA Payload"
    strings:
        $s1 = "%s\\Readme.README" fullword wide
        $s2 = "Every byte on any types of your devices was encrypted" ascii
        $s3 = { 6c 65 67 61 6c 6e 6f 74 69 63 65 74 65 78 74 00 (50|70) (59|79) (53|73) (41|61) }
        $s4 = { 6c 65 67 61 6c 6e 6f 74 69 63 65 63 61 70 74 69 6f 6e 00 00 (50|70) (59|79) (53|73) (41|61) }
        $s5 = { 2e 62 61 74 00 00 6f 70 65 6e 00 00 00 00 53
                4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f
                66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72
                65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69
                63 69 65 73 5c 53 79 73 74 65 6d 00 00 00 }
        $f1 = ".?AVPK_EncryptorFilter@CryptoPP@@" ascii
        $f2 = ".?AV?$TF_EncryptorImpl@" ascii
        $f3 = "@VTF_EncryptorBase@CryptoPP@@" ascii
    condition:
        int16(0) == 0x5a4d and all of ($f*) and 3 of ($s*)
}
