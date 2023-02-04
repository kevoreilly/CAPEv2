rule Alkhal {
    meta:
        author = "ditekSHen"
        description = "Detects Alkhal ransomware"
        cape_type = "Alkhal Payload"
    strings:
        $s1 = "ReadMe.txt" fullword wide
        $s2 = "Recovery.bmp" fullword wide
        $d1 = "\\$RECYCLE.BIN\\" fullword wide
        $d2 = "\\BOOT\\" fullword wide
        $d3 = "\\RECOVERY\\" fullword wide
        $d4 = "\\MICROS~1\\" fullword wide
        $d5 = "\\CODECA~1\\js\\" fullword wide
        $a1 = "takeown.exe" fullword wide
        $a2 = "AppLaunch.exe" fullword wide
        $a3 = "MpCmdRun.exe" fullword wide
        $a4 = "wordpad.exe" fullword wide
        $a5 = "winload.exe" fullword wide
        $a6 = "prevhost.exe" fullword wide
        $a7 = "credwiz.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) and 4 of ($d*) and 3 of ($a*))
}
