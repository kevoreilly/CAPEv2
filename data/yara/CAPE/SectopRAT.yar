rule SectopRAT {
    meta:
        author = "ditekSHen"
        description = "Detects SectopRAT"
        cape_type = "SectopRAT Payload"
    strings:
        $s1 = "\\\\.\\root\\cimv2:Win32_Process" wide
        $s2 = "\\\\.\\root\\cimv2:CIM_DataFile.Name=" wide
        $s3 = "^.*(?=Windows)" fullword wide
        $s4 = "C:\\Windows\\System32\\cmd.exe" wide
        $s5 = "C:\\Windows\\explorer.exe" wide
        $s6 = "Disabling IE protection" wide
        $s7 = "stream started succces" wide
        $b1 = "/C start Firefox" wide
        $b2 = "/C start chrome" wide
        $b3 = "/C start iexplore" wide
        $m1 = "DefWindowProc" fullword ascii
        $m2 = "AuthStream" fullword ascii
        $m3 = "KillBrowsers" fullword ascii
        $m4 = "GetAllNetworkInterfaces" fullword ascii
        $m5 = "EnumDisplayDevices" fullword ascii
        $m6 = "RemoteClient.Packets" fullword ascii
        $m7 = "IServerPacket" fullword ascii
        $m8 = "keybd_event" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((5 of ($s*) and 2 of ($b*)) or all of ($s*) or (all of ($b*) and (4 of ($s*) or 5 of ($m*))))
}
