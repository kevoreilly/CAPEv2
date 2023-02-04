rule Koxic {
    meta:
        author = "ditekSHen"
        description = "Detects Koxic ransomware"
        cape_type = "Koxic Payload"
    strings:
        $c1 = " INFO: >> %TEMP%\\" ascii wide
        $c2 = "cmd /c \"wmic" ascii wide
        $c3 = "cmd /c \"echo" ascii wide
        $c4 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"" fullword wide
        $c5 = /sc config.{1,30}start=disabled/ fullword ascii wide
        $s1 = "Container: %s" fullword wide
        $s2 = "Shotcut dir : %s" fullword wide
        $s3 = "\\Microsoft\\Windows\\Network Shortcuts\\" fullword wide
        $s4 = "Thread %d started." fullword ascii
        $s5 = "ADD our TOXID:" wide
        $s6 = "[Recommended] Using an email" wide
    condition:
        uint16(0) == 0x5a4d and ((4 of ($s*) and 1 of ($c*)) or (2 of ($s*) and (#c1 > 5 or #c2 > 5 or #c3 > 5 or #c5 > 5)))
}
