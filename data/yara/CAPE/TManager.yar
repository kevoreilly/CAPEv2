rule TManager {
    meta:
        author = "ditekSHen"
        description = "Detects TManager RAT. Associated with TA428"
        cape_type = "TManager RAT Payload"
    strings:
        $s1 = "WSAStartup Error!" fullword wide
        $s2 = "KB3112342.LOG" fullword wide
        $s3 = "\\cmd.exe -c" fullword wide
        $s4 = "sock_hmutex" fullword wide
        $s5 = "cmd_hmutex" fullword wide
        $s6 = "powershell" fullword wide
        $s7 = "%s_%d.bmp" fullword wide
        $s8 = "!Error!" fullword wide
        $s9 = "[Execute]" fullword ascii
        $s10 = "[Snapshot]" fullword ascii
        $s11 = "GetLanIP error!" fullword ascii
        $s12 = "chcp & exit" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
