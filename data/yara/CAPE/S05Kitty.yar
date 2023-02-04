rule S05Kitty {
    meta:
        author = "ditekshen"
        description = "Sector05 Kitty RAT payload"
        cape_type = "S05Kitty payload"
    strings:
        $s1 = "Execute Comand" ascii
        $s2 = "InjectExplorer" ascii
        $s3 = "targetProcess = %s" fullword ascii
        $s4 = "Process attach (%s)" fullword ascii
        $s5 = "process name: %s" fullword ascii
        $s6 = "cmd /c %s >%s" fullword ascii
        $s7 = "CmdDown: %s, failed" fullword ascii
        $s8 = "http://%s%s/%s" fullword ascii
        $s9 = "tmp.LOG" fullword ascii
        $x1 = "zerodll.dll" fullword ascii
        $x2 = "OneDll.dll" fullword ascii
        $x3 = "kkd.bat" fullword ascii
        $x4 = "%s\\regsvr32.exe /s \"%s\"" fullword ascii
        $x5 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\fontchk.jse" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (8 of ($s*) or all of ($x*))
}
