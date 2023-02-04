rule Zegost {
    meta:
        author = "ditekSHen"
        description = "Detects Zegost"
        cape_type = "Zegost Payload"
    strings:
        $s1 = "rtvscan.exe" fullword ascii
        $s2 = "ashDisp.exe" fullword ascii
        $s3 = "KvMonXP.exe" fullword ascii
        $s4 = "egui.exe" fullword ascii
        $s5 = "avcenter.exe" fullword ascii
        $s6 = "K7TSecurity.exe" fullword ascii
        $s7 = "TMBMSRV.exe" fullword ascii
        $s8 = "RavMonD.exe" fullword ascii
        $s9 = "kxetray.exe" fullword ascii
        $s10 = "mssecess.exe" fullword ascii
        $s11 = "QUHLPSVC.EXE" fullword ascii
        $s12 = "360tray.exe" fullword ascii
        $s13 = "QQPCRTP.exe" fullword ascii
        $s14 = "knsdtray.exe" fullword ascii
        $s15 = "V3Svc.exe" fullword ascii
        $s16 = "??1_Winit@std@@QAE@XZ" fullword ascii
        $s17 = "ClearEventLogA" fullword ascii
        $s18 = "SeShutdownPrivilege" fullword ascii
        $s19 = "%s\\shell\\open\\command" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
