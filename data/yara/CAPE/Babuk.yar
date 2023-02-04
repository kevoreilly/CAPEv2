rule Babuk {
    meta:
        author = "ditekSHen"
        description = "Detects Babuk ransomware"
        cape_type = "Babuk Payload"
    strings:
        $s1 = "ecdh_pub_k.bin" wide
        $s2 = "How To Restore Your Files.txt" wide
        $s3 = /(babuk|babyk)\s(ransomware|locker)/ ascii nocase
        $s4 = "/login.php?id=" ascii
        $s5 = "http://babuk" ascii
        $s6 = "bootsect.bak" fullword wide
        $s7 = "Can't open file after killHolder" ascii
        $s8 = "Can't OpenProcess" ascii
        $s9 = "DoYouWantToHaveSexWithCuongDong" ascii
        $arg1 = "-lanfirst" fullword ascii
        $arg2 = "-lansecond" fullword ascii
        $arg3 = "-nolan" fullword ascii
        $arg4 = "shares" fullword wide
        $arg5 = "paths" fullword wide
        $arg6 = "gdebug" fullword wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or (3 of ($arg*) and 2 of ($s*)))
}
