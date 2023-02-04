rule Nermer {
    meta:
        author = "ditekSHen"
        description = "Detects Nermer ransomware"
        cape_type = "Nermer Payload"
    strings:
        $x1 = "gPROTECT_INFO.TXT" fullword wide
        $x2 = ".nermer" fullword wide
        $s1 = "db_journal" fullword wide
        $s2 = "quicken2015backup" fullword wide
        $s3 = "mysql" fullword wide
        $s4 = "sas7bdat" fullword wide
        $s5 = "httpd.exe" fullword wide
        $s6 = "Intuit.QuickBooks.FCS" fullword wide
        $s7 = "convimage" fullword wide
        $s8 = ".?AV?$_Binder@U_Unforced@std@@P8shares_t@" ascii
        $s9 = "BgIAAACkAABSU0ExAAgAAAEAAQCt" ascii
        $m1 = "YOUR FILES WERE ENCRYPTED" ascii
        $m2 = "MARKED BY EXTENSION .nermer" ascii
        $m3 = "send us your id: >> {id} <<" ascii
        $m4 = "email us: >> {email} <<" ascii
        $c1 = "/repeater.php" ascii
        $c2 = "HTTPClient/0.1" fullword ascii
        $c3 = "94.156.35.227" ascii
        $c4 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($m*) or all of ($c*) or all of ($s*)  or (4 of ($s*) and (1 of ($x*) or 1 of ($m*) or 2 of ($c*))) or 14 of them)
}
