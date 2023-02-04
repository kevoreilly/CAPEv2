rule ExMatter {
    meta:
        author = "ditekSHen"
        description = "Detects BlackMatter data exfiltration tool"
        cape_type = "ExMatter Payload"
    strings:
        $s1 = "Renci.SshNet." ascii
        $s2 = "DirNotEmpty" fullword ascii
        $s3 = "MkDir" fullword ascii
        $s4 = "RmDir" fullword ascii
        $s5 = "get_MainWindowHandle" fullword ascii
        $s6 = "GetCurrentProcess" fullword ascii
        $s7 = "]]>]]>" fullword wide
        $s8 = "1.3.132.0.35" fullword wide
        $s9 = "1.3.132.0.34" fullword wide
        $s10 = "1.2.840.10045.3.1.7" fullword wide
        $x1 = "sender2.pdb" fullword ascii
        $x2 = { 64 00 61 00 74 00 61 00 ?? 72 00 6f 00 6f 00 74 }
        $x3 = "157.230.28.192" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($x*) and 7 of ($s*)))
}
