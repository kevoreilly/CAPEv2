rule STOP {
    meta:
        author = "ditekSHen"
        description = "Detects STOP ransomware"
        cape_type = "STOP Payload"
    strings:
        $x1 = "C:\\SystemID\\PersonalID.txt" fullword wide
        $x2 = "/deny *S-1-1-0:(OI)(CI)(DE,DC)" wide
        $x3 = "e:\\doc\\my work (c++)\\_git\\encryption\\" ascii wide nocase
        $s1 = "\" --AutoStart" fullword ascii wide
        $s2 = "--ForNetRes" fullword wide
        $s3 = "--Admin" fullword wide
        $s4 = "%username%" fullword wide
        $s5 = "?pid=" fullword wide
        $s6 = /&first=(true|false)/ fullword wide
        $s7 = "delself.bat" ascii
        $mutex1 = "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}" fullword ascii
        $mutex2 = "{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}" fullword ascii
        $mutex3 = "{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((2 of ($x*) and 1 of ($mutex*)) or (all of ($x*)) or (6 of ($s*) and (1 of ($x*) or 1 of ($mutex*))) or (9 of them))
}
