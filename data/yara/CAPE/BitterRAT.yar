rule BitterRAT {
    meta:
        author = "ditekshen"
        description = "BitterRAT payload"
        cape_type = "BitterRAT payload"
    strings:
        $s1 = "getfile" fullword wide
        $s2 = "getfolder" fullword wide
        $s3 = "winmgmts://./root/default:StdRegProv" fullword wide
        $s4 = "winlog" fullword wide
        $s5 = "winprt" fullword wide
        $s6 = "c:\\intel\\" fullword ascii
        $s7 = "AXE: #" fullword ascii
        $s8 = "Bld: %s.%s.%s" fullword ascii
        $s9 = "53656C656374202A2066726F6D2057696E33325F436F6D707574657253797374656D" wide nocase
        $pdb1 = "\\28NovDwn\\Release\\28NovDwn.pdb" ascii
        $pdb2 = "\\Shellcode\\Release\\Shellcode.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($*) or (4 of ($s*) and 1 of ($pdb*)))
}
