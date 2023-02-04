rule DecryptMyFiles {
    meta:
        author = "ditekSHen"
        description = "Detects DecryptMyFiles ransomware"
        cape_type = "DecryptMyFiles Payload"
    strings:
        $s1 = "FILES ENCRYPTED" wide
        $s2 = "pexplorer.exe" fullword wide
        $s3 = "uniquesession" fullword ascii
        $s4 = ".[decryptmyfiles.top]." fullword ascii
        $s5 = "decrypt 1 file" ascii
        $s6 = "(databases,backups, large excel" ascii
        $c1 = "api/connect.php" ascii
        $c2 = "decryptmyfiles.top" ascii
        $c3 = "/contact/" ascii
    condition:
        uint16(0) == 0x5a4d and (4 of ($s*) or all of ($c*) or (2 of ($c*) and 2 of ($s*)))
}
