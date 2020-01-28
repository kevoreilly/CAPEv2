rule XpertRAT {
    meta:
        author = "ditekshen"
        description = "XpertRAT payload"
        cape_type = "XpertRAT Payload"
    strings:
        $v1 = "[XpertRAT-Mutex]" fullword wide
        $v2 = "XPERTPLUGIN" fullword wide
        $v3 = "+Xpert+3." wide
        $v4 = "keylog.tmp" fullword wide
        $v5 = "\\TempReg.reg" fullword wide
        
        $s1 = "ClsKeylogger" fullword ascii nocase
        $s2 = "clsCamShot" fullword ascii nocase
        $s3 = "ClsShellCommand" fullword ascii nocase
        $s4 = "ClsRemoteDesktop" fullword ascii nocase
        $s5 = "ClsScreenRemote" fullword ascii nocase
        $s6 = "ClsSoundRemote" fullword ascii nocase
        $s7 = "MdlHidder" fullword ascii
        $s8 = "modKeylog" fullword ascii
        $s9 = "modWipe" fullword ascii
        $s10 = "modDelProcInUse" fullword ascii
        $s11= "Socket_DataArrival" fullword ascii
        $s12 = "cZip_EndCompress" fullword ascii

    condition:
        uint16(0) == 0x5a4d and (3 of ($v*) or 6 of ($s*))
}
