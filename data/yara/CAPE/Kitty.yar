rule Kitty {
    meta:
        author = "ditekSHen"
        description = "Detects Kitty ransomware"
        cape_type = "Kitty Payload"
    strings:
        $s1 = "Kitty" wide
        $s2 = "-path" fullword wide
        $s3 = "select * from Win32_ShadowCopy" fullword wide
        $s4 = "Win32_ShadowCopy.ID='%s'" fullword wide
        $s5 = "programdata" fullword wide
        $s6 = "$recycle.bin" fullword wide
        $s7 = ".crypt" fullword wide
        $s8 = "%s/secret/%S" wide
        $s9 = "decrypts3nln3tic.onion" wide
        $n1 = "read_me_lkd.txt" wide
        $n2 = "DECRYPT_NOTE.txt" wide
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or 1 of ($n*) and 4 of ($s*))
}
