rule TigerRAT {
    meta:
        author = "ditekSHen"
        description = "Detects TigerRAT"
        cape_type = "TigerRAT Payload"
    strings:
        $m1 = ".?AVModuleKeyLogger@@" fullword ascii
        $m2 = ".?AVModulePortForwarder@@" fullword ascii
        $m3 = ".?AVModuleScreenCapture@@" fullword ascii
        $m4 = ".?AVModuleShell@@" fullword ascii
        $s1 = "\\x9891-009942-xnopcopie.dat" fullword wide
        $s2 = "(%02d : %02d-%02d %02d:%02d:%02d)--- %s[Clipboard]" fullword ascii
        $s3 = "[%02d : %02d-%02d %02d:%02d:%02d]--- %s[Title]" fullword ascii
        $s4 = "del \"%s\"%s \"%s\" goto " ascii
        $s5 = "[<<]" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (all of ($m*) and 1 of ($s*)) or (2 of ($m*) and 2 of ($s*)))
}
