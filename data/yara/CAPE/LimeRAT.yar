rule LimeRAT {
    meta:
        author = "ditekshen"
        description = "LimeRAT payload"
        cape_type = "LimeRAT Payload"
    strings:
        $s1 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr" wide
        $s2 = "\\vboxhook.dll" fullword wide
        $s3 = "Win32_Processor.deviceid=\"CPU0\"" fullword wide
        $s4 = "select CommandLine from Win32_Process where Name='{0}'" wide
        $s5 = "Minning..." fullword wide
        $s6 = "Regasm.exe" fullword wide
        $s7 = "Flood!" fullword wide
        $s8 = "Rans-Status" fullword wide
        $s9 = "cmd.exe /c ping 0"  wide
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
