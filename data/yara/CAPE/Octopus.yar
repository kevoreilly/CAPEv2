rule Octopus {
    meta:
        author = "ditekSHen"
        description = "Detects Octopus trojan payload"
        cape_type = "Octopus Payload"
    strings:
        $s1 = "\\Mozilla\\Firefox\\Profiles\\" fullword wide
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
        $s3 = "\\wbem\\WMIC.exe" fullword wide
        $s4 = ".profiles.ini" fullword wide
        $s5 = "PushEBP_" ascii
        $s6 = "MovEBP_ESP_" ascii
        $s7 = "Embarcadero Delphi for Win32 compiler" ascii
        $s8 = "TempWmicBatchFile.bat" fullword wide
        $wq1 = "computersystem get Name /format:list" wide
        $wq2 = "os get installdate /format:list" wide
        $wq3= "get serialnumber /format:list" wide
        $wq4 = "\\\\\\\\.\\\\PHYSICALDRIVE" wide
        $wq5= "path CIM_LogicalDiskBasedOnPartition" wide
        $wq6 = "get Antecedent,Dependent" wide
        $wq7 = "path win32_physicalmedia" wide
    condition:
        uint16(0) == 0x5a4d and (6 of ($s*) and 5 of ($wq*))
}
