rule Orion {
    meta:
        author = "ditekshen"
        description = "Orion Keylogger payload"
        cape_type = "Orion payload"
    strings:
        $s1 = "\\Ranger.BrowserLogging" ascii wide nocase
        $s2 = "GrabAccounts" fullword ascii
        $s3 = "DownloadFile" fullword ascii
        $s4 = "Internet Explorer Recovery" wide
        $s5 = "Outlook Recovery" wide
        $s6 = "Thunderbird Recovery" wide
        $s7 = "Keylogs -" wide
        $s8 = "WebCam_Capture.dll" wide
        $s9 = " is not installed on this computer!" wide
        $s10 = "cmd /c bfsvc.exe \"" wide
        $s11 = "/Keylogs - PC:" fullword wide
        $s12 = "/PC:" fullword wide
        $s13 = "<p style=\"color:#CC7A00\">[" wide
    condition:
        (uint16(0) == 0x5a4d and 5 of ($s*)) or (6 of ($s*))
}
