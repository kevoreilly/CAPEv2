rule RunningRAT {
    meta:
        author = "ditekSHen"
        description = "Detects RunningRAT"
        cape_type = "RunningRAT Payload"
    strings:
        $s1 = "%s%d.dll" fullword ascii
        $s2 = "/c ping 127.0.0.1 -n" ascii
        $s3 = "del /f/q \"%s\"" ascii
        $s4 = "GUpdate" fullword ascii
        $s5 = "%s\\%d.bak" fullword ascii
        $s6 = "\"%s\",MainThread" ascii
        $s7 = "rundll32.exe" fullword ascii
        $rev1 = "emankcosteg" fullword ascii
        $rev2 = "ini.revreS\\" fullword ascii
        $rev3 = "daerhTniaM,\"s%\" s%" ascii
        $rev4 = "s% etadpUllD,\"s%\" 23lldnuR" ascii
        $rev5 = "---DNE yromeMmorFdaoL" fullword ascii
        $rev6 = "eMnigulP" fullword ascii
        $rev7 = "exe.23lldnuR\\" fullword ascii
        $rev8 = "dnammoc\\nepo\\llehs\\" ascii
        $rev9 = "\"s%\" k- exe.tsohcvs\\23metsyS\\%%tooRmetsyS%" ascii
        $rev10 = "emanybtsohteg" fullword ascii
        $rev11 = "tekcosesolc" fullword ascii
        $rev12 = "tpokcostes" fullword ascii
        $rev13 = "emantsohteg" fullword ascii
        // variant
        $v2_1 = "%%SystemRoot%%\\System32\\svchost.exe -k \"%s\"" fullword ascii
        $v2_2 = "LoadFromMemory END---" fullword ascii
        $v2_3 = "hmProxy!= NULL" fullword ascii
        $v2_4 = "Rundll32 \"%s\",DllUpdate %s" fullword ascii
        $v2_5 = "ipip.website" fullword ascii
        $v2_6 = "%d*%sMHz" fullword ascii
        $v2_7 = "\\Server.ini" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 5 of ($rev*) or 6 of ($v*) or 8 of them)
}
