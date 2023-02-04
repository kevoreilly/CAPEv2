rule Chinotto {
    meta:
        author = "ditekSHen"
        description = "Detects Chinotto"
        cape_type = "Chinotto Payload"
    strings:
        $x1 = "xxxchinotto" ascii wide
        $x2 = "\\Chinotto.pdb" ascii wide
        $x3 = { 50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31
                0d 0a 41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e
                67 3a 20 67 7a 69 70 2c 20 64 65 66 6c 61 74 65
                0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f
                7a 69 6c 6c 61 2f 34 2e 30 28 63 6f 6d 70 61 74
                69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20
                57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20
                53 56 31 29 0d 0a 41 63 63 65 70 74 3a 20 69 6d
                61 67 65 2f 67 69 66 2c 20 69 6d 61 67 65 2f 78
                2d 78 62 69 74 6d 61 70 2c 20 69 6d 61 67 65 2f
                6a 70 65 67 2c 20 69 6d 61 67 65 2f 70 6a 70 65
                67 2c 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78
                2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68
                2c 20 2a 0d 0a 41 63 63 65 70 74 2d 4c 61 6e 67
                75 61 67 65 3a 20 65 6e 2d 75 73 0d 0a 43 6f 6e
                74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69
                70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 3b 62
                6f 75 6e 64 61 72 79 3d 25 73 0d 0a 48 6f 73 74
                3a 20 25 73 3a 25 64 0d 0a 43 6f 6e 74 65 6e 74
                2d 4c 65 6e 67 74 68 3a 20 25 64 0d 0a 43 6f 6e
                6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c
                69 76 65 0d 0a 43 61 63 68 65 2d 43 6f 6e 74 72
                6f 6c 3a 20 6e 6f 2d 63 61 63 68 65 0d 0a 0d 0a
                00 00 00 00 48 54 54 50 2f 31 2e 31 20 32 30 30
                20 4f 4b 00 0d 0a 0d 0a 00 00 00 00 65 72 72 6f
                72 3c 2f 62 3e }
        $s1 = "Run /v xxxzexs /t REG_SZ /d %s /f" ascii wide
        $s2 = "ShellExecute Error, ret" ascii wide
        $s3 = "Run app succeed" ascii
        $s4 = "cleartemp:" fullword ascii
        $s5 = "wakeup:" fullword ascii
        $s6 = "updir:" fullword ascii
        $s7 = "regstart:" fullword ascii
        $s8 = "chdec:" fullword ascii
        $s9 = "cmd:" fullword ascii
        $s10 = "error</b>" fullword ascii
        $c1 = "Host: %s:%d" ascii wide
        $c2 = "Mozilla/4.0(compatible; MSIE 6.0; Windows NT 5.1; SV1)" ascii wide
        $c3 = "Mozilla/5.0(Windows NT 10.0; Win64; x64)AppleWebKit/537.36(KHTML, like Gecko)Chrome/78.0.3904.108 Safari/537.36" ascii wide
        $c4 = "id=%s&type=hello&direction=send" ascii wide
        $c5 = "id=%s&type=command&direction=receive" ascii wide
        $c6 = "id=%s&type=file&direction=" ascii wide
        $c7 = "id=%s&type=result&direction=" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and (2 of ($s*) or 2 of ($c*))) or 4 of ($c*) or 5 of ($s*))
}
