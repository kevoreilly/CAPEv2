rule DllHijacker01 {
    meta:
        author = "ditekSHen"
        description = "Hunt for VSNTAR21 / DllHijacker01 IronTiger / LuckyMouse / APT27 malware"
        cape_type = "DllHijacker01 Payload"
    strings:
        $s1 = "libvlc_add_intf" fullword ascii
        $s2 = "libvlc_dllonexit" fullword ascii
        $s3 = "libvlc_getmainargs" fullword ascii
        $s4 = "libvlc_initenv" fullword ascii
        $s5 = "libvlc_set_app_id" fullword ascii
        $s6 = "libvlc_set_app_type" fullword ascii
        $s7 = "libvlc_set_user_agent" fullword ascii
        $s8 = "libvlc_wait" fullword ascii
        $s9 = "dll.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule HyperBro02 {
    meta:
        author = "ditekSHen"
        description = "Detects HyperBro IronTiger / LuckyMouse / APT27 malware"
        cape_type = "HyperBro Payload"
    strings:
        $s1 = "\\cmd.exe /A" fullword wide
        $s2 = "C:\\windows\\explorer.exe" fullword wide
        $s3 = "\\\\.\\pipe\\testpipe" fullword wide
        $s4 = "Elevation:Administrator!new:{" wide
        $s5 = "log.log" fullword wide
        $s6 = "%s\\%d.exe" fullword wide
        $s7 = ".?AVTPipeProtocol@@" fullword ascii
        $s8 = ".?AVTCaptureMgr@@" fullword ascii
        $s9 = "system-%d" fullword wide
        $s10 = "[test] %02d:%02d:%02d:%03d %s" fullword wide
        $s11 = "\\..\\data.dat" fullword wide
        $s12 = "\\..\\config.ini" fullword wide
        $s13 = { 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 20 00 2d 00 77 00 6f 00 72 00 6b 00 65 00 72 00 }
        $s14 = { 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 20 00 2d 00 64 00 61 00 65 00 6d 00 6f 00 6e 00 }
        $cnc1 = "https://%s:%d/ajax" fullword wide
        $cnc2 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.116 Safari/537.36" fullword wide
        $cnc3 = "139.180.208.225" fullword wide
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (2 of ($cnc*) and 2 of ($s*)))
}

/*
Too many FPs
rule HyperBro03 {
    meta:
        author = "ditekSHen"
        description = "Hunt HyperBro IronTiger / LuckyMouse / APT27 malware"
        cape_type = "HyperBro Payload"
    strings:
        //$h1 = "HControl" ascii wide
        //$h2 = "HSleep" ascii wide
        //$h3 = "HTrans" ascii wide
        $i1 = "IAgent" ascii wide
        $i2 = "ITcpAgent" ascii wide
        $i3 = "IAgentListener" ascii wide
        $t1 = "TCommon" ascii
        $t2 = "TFileInfo" ascii
        $t3 = "TFileRename" ascii
        $t4 = "TFileUpload" ascii
        $t5 = "TServicesInfo" ascii
        $t6 = "TListUser" ascii
        $t7 = "TTransmit" ascii
        $vc1 = "CSSLAgent" ascii wide
        $vc2 = "CSocks5" ascii wide
        $vc3 = "CTcpAgent" ascii wide
        $cm1 = "CMCapture" ascii wide
        $cm2 = "CMFile" ascii wide
        $cm3 = "CMPipeClient" ascii wide
        $cm4 = "CMPipeServer" ascii wide
        $cm5 = "CMProcess" ascii wide
        $cm6 = "CMServices" ascii wide
        $cm7 = "CMShell" ascii wide
    condition:
        // Reduce potential FPs
        uint16(0) == 0x5a4d and (all of ($i*) or 6 of ($t*) or 6 of ($cm*) or all of ($vc*))
        //uint16(0) == 0x5a4d and (all of ($h*) or all of ($i*) or 6 of ($t*) or 6 of ($cm*) or all of ($vc*))
}
*/

rule DllHijacker02 {
    meta:
        author = "ditekSHen"
        description = "Detects ServiceCrt / DllHijacker03 IronTiger / LuckyMouse / APT27 malware"
        cape_type = "DllHijacker02 Payload"
    strings:
        $s1 = "ServiceCrtMain" fullword ascii
        $s2 = "mpsvc.dll" fullword ascii
        $o1 = { 84 db 0f 85 4c ff ff ff e8 14 06 00 00 8b f0 83 }
        $o2 = { f7 c1 00 ff ff ff 75 c5 eb 13 0f ba 25 10 20 01 }
        $o3 = { 8d 04 b1 8b d9 89 45 fc 8d 34 b9 a1 18 20 01 10 }
        $o4 = { b0 01 c3 68 b8 2c 01 10 e8 83 ff ff ff c7 04 24 }
        $o5 = { eb 34 66 0f 12 0d 00 fe 00 10 f2 0f 59 c1 ba cc }
        $o6 = { 73 c7 dc 0d 4c ff 00 10 eb bf dd 05 34 ff 00 10 }
    condition:
        uint16(0) == 0x5a4d and all of ($s*) and 5 of ($o*)
}
