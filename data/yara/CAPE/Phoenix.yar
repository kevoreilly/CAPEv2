rule Phoenix {
    meta:
        author = "ditekshen"
        description = "Phoenix keylogger payload"
        cape_type = "Phoenix payload"
    strings:
        $s1 = "FirefoxPassReader" fullword ascii
        $s2 = "StartKeylogger" fullword ascii
        $s3 = "CRYPTPROTECT_" ascii
        $s4 = "Chrome_Killer" fullword ascii
        $s5 = "Clipboardlog.txt" fullword wide
        $s6 = "Leyboardlogs.txt" fullword wide
        $s7 = "Persistence'" wide
        $s8 = "set_HKB" fullword ascii
        $s9 = "loloa" fullword ascii
        $s10 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR1.0.3705;)" fullword wide
        // Memory
        $m1 = "- Screenshot -------|" ascii wide
        $m2 = "- Clipboard -------|" ascii wide
        $m3 = "- Logs -------|" ascii wide
        $m4 = "- Passwords -------|" ascii wide
        $m5 = "PSWD" ascii wide
        $m6 = "Screenshot |" ascii wide
        $m7 = "Logs |" ascii wide
    condition:
        (uint16(0) == 0x5a4d and 6 of ($s*) or 3 of ($m*)) or 9 of them
}
