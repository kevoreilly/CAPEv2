rule JoeGo {
    meta:
        author = "ditekshen"
        description = "JoeGo ransomware payload"
        cape_type = "JoeGo payload"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "%SystemRoot%\\system32\\%v." ascii
        $s2 = "REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V" ascii
        $s3 = "/t REG_SZ /F /D %userprofile%\\" ascii
        $s4 = "(sensitive) [recovered]" ascii
        $s5 = "/dev/stderr/dev/stdout/index.html" ascii
        $s6 = "%userprofile%\\SystemApps" ascii
        $s7 = "p=<br>ACDTACSTAEDTAESTAKDTAKSTAWSTA" ascii
        $cnc1 = "/detail.php" ascii
        $cnc2 = "/checkin.php" ascii
        $cnc3 = "/platebni_brana.php" ascii
        $cnc4 = "://nebezpecnyweb.eu/" ascii
    condition:
        uint16(0) == 0x5a4d and $go and (all of ($s*) or (3 of ($s*) and 1 of ($cnc*)))
}
