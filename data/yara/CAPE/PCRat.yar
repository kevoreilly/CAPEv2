rule PCRat {
    meta:
        author = "ditekSHen"
        description = "Detects PCRat / Gh0st"
        cape_type = "PCRat / Gh0st Payload"
    strings:
        $s1 = "ClearEventLogA" fullword ascii
        $s2 = "NetUserAdd" fullword ascii
        $s3 = "<H1>403 Forbidden</H1>" fullword ascii
        $s4 = ":]%d-%d-%d  %d:%d:%d" fullword ascii
        $s5 = "Mozilla/4.0 (compatible)" fullword ascii
        $s6 = "<Enter>" fullword ascii
        $s7 = "\\cmd.exe" fullword ascii
        $s8 = "Program Files\\Internet Explorer\\IEXPLORE.EXE" fullword ascii
        $s9 = "Collegesoft ScenicPlayer" fullword wide
        $a1 = "360tray.exe" fullword ascii
        $a2 = "avp.exe" fullword ascii
        $a3 = "RavMonD.exe" fullword ascii
        $a4 = "360sd.exe" fullword ascii
        $a5 = "Mcshield.exe" fullword ascii
        $a6 = "egui.exe" fullword ascii
        $a7 = "kxetray.exe" fullword ascii
        $a8 = "knsdtray.exe" fullword ascii
        $a9 = "TMBMSRV.exe" fullword ascii
        $a10 = "avcenter.exe" fullword ascii
        $a11 = "ashDisp.exe" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of ($s*) and 6 of ($a*)
}
