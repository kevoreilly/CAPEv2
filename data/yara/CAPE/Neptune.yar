rule Neptune {
    meta:
        author = "ditekSHen"
        description = "Detects Neptune keylogger / infostealer"
        cape_type = "Neptune Keylogger Payload"
    strings:
        $x1 = "your keylogger has been freshly installed on" wide
        $x2 = "Attached is a screenshot of the victim" wide
        $x3 = "color: rgb(2, 84, 138);'>Project Neptune</span><br>" wide
        $x4 = ">{Monitor Everything}</span><br><br>" wide
        $x5 = "[First Run] Neptune" wide
        $x6 = "Neptune - " wide
        $s1 = "Melt" fullword wide
        $s2 = "Hide" fullword wide
        $s3 = "SDDate+" fullword wide
        $s4 = "DelOff+" fullword wide
        $s5 = "MsgFalse+" fullword wide
        $s6 = "Clipboard:" fullword wide
        $s7 = "information is valid and working!" wide
        $s8 = ".exe /k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" wide
        $s9 = "http://www.exampleserver.com/directfile.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 7 of ($s*) or (1 of ($x*) and 5 of ($s*)))
}
