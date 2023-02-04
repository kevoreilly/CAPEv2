rule FakeWMI {
    meta:
        author = "ditekshen"
        description = "FakeWMI payload"
        cape_type = "FakeWMI payload"
    strings:
        $s1 = "-BEGIN RSA PUBLIC KEY-" ascii
        $s2 = ".exe|" ascii
        $s3 = "cmd /c wmic " ascii
        $s4 = "cmd /c sc " ascii
        $s5 = "schtasks" ascii
        $s6 = "taskkill" ascii
        $s7 = "findstr" ascii
        $s8 = "netsh interface" ascii
        $s9 = "CreateService" ascii
    condition:
       uint16(0) == 0x5a4d and (all of ($s*) and #s2 > 10)
}
