rule FatalRAT {
    meta:
        author = "ditekSHen"
        description = "Detects FatalRAT"
        cape_type = "FatalRAT Payload"
    strings:
        $x1 = "XXAcQbcXXfRSScR" fullword ascii
        $s1 = "CHROME_NO_DATA" fullword ascii
        $s2 = "CHROME_UNKNOW" fullword ascii
        $s3 = "-Thread running..." ascii
        $s4 = "InetCpl.cpl,ClearMyTracksByProcess" ascii nocase
        $s5 = "MSAcpi_ThermalZoneTemperature" ascii nocase
        $s6 = "taskkill /f /im rundll32.exe" fullword ascii nocase
        $s7 = "del /s /f %appdata%\\Mozilla\\Firefox" ascii nocase
        $s8 = "\\\\%s\\C$\\" ascii
        $s9 = "fnGetChromeUserInfo" fullword ascii
        $s10 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or 5 of ($s*))
}
