rule Robbinhood {
    meta:
        author = "ditekshen"
        description = "Robbinhood ransomware payload"
        cape_type = "Robbinhood payload"
    strings:
        $go = "Go build ID:" ascii
        $cmd1 = "cmd.exe /c" ascii
        $cmd2 = "net use * /DELETE" nocase ascii
        $cmd3 = "sc.exe stop" ascii
        $cmd4 = "vssadmin resize shadowstorage" nocase ascii
        $s1 = /Skipping\s(file|dir)/ ascii
        $s2 = "Encrypt[ERR] GET Size:" ascii
        $s3 = ".taskkilltasklistunknown(" ascii
        $s4 = ".sysvssadmin.exewevtutil.exe MB released" ascii
        $s5 = ".sysvssadmin.exewevtutil.exewinlogin.exewinlogon.exe MB released" ascii
        $s6 = ".enc_robbinhood" ascii
        $s7 = "c:\\windows\\temp\\pub.key" nocase ascii
        $s8 = "main.CoolMaker" ascii
        $s9 = "/valery/go/src/oldboy/" ascii
    condition:
        uint16(0) == 0x5a4d and ($go and 1 of ($cmd*) and 3 of ($s*))
}
