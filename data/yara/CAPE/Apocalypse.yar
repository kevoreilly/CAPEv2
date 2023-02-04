rule Apocalypse {
    meta:
      author = "ditekshen"
      description = "Apocalypse infostealer payload"
      cape_type = "Apocalypse payload"
    strings:
        $s1 = "OpenClipboard" fullword ascii
        $s2 = "SendARP" fullword ascii
        $s3 = "GetWebRequest" fullword ascii
        $s4 = "DotNetGuard" fullword ascii
        $s5 = "set_CreateNoWindow" fullword ascii
        $s6 = "UploadFile" fullword ascii
        $s7 = "GetHINSTANCE" fullword ascii
        $s8 = "Kill" fullword ascii
        $s9 = "GetProcesses" fullword ascii
        $s10 = "get_PrimaryScreen" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
