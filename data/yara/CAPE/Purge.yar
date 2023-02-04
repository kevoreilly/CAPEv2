rule Purge {
    meta:
        author = "ditekSHen"
        description = "Detects Purge ransomware"
        cape_type = "Purge Payload"
    strings:
        $n1 = "imagesave/imagesize.php" ascii
        $n2 = "imageinfo.html" ascii
        $n3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" ascii
        $n4 = "Content-Type: application/x-www-form-urlencoded" ascii
        $m1 = "YOUR_ID: %x%x" wide
        $m2 = "Specially for your PC was generated personal" wide
        $m3 = "which is on our Secret Server" wide
        $m4 = "wait for a miracle and get your price" wide
        $s1 = "%s\\SpyHunter Remove Ransomware" wide
        $s2 = "$recycle.bin" fullword wide
        $s3 = "TheEnd" fullword wide
        $s4 = "%s\\HELP_DECRYPT_YOUR_FILES.TXT" fullword wide
        $s5 = "%s.id_%x%x_email_" wide
        $s6 = "scmd" fullword wide
        $s7 = "process call create \"%s\"" wide
        $s8 = "FinishEnds" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($n*) or 2 of ($m*) or (3 of ($s*) and (1 of ($n*) or 1 of ($m*))))
}
