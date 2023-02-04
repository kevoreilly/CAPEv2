rule Konni {
    meta:
        author = "ditekshen"
        description = "Konni payload"
        cape_type = "Konni payload"
    strings:
        $s1 = "uplog.tmp" fullword wide
        $s2 = "upfile.tmp" fullword wide
        $s3 = "%s-log-%s" fullword ascii wide
        $s4 = "%s-down" ascii wide
        $s5 = "%s-file-%s" fullword ascii wide
        $s6 = "\"rundll32.exe\" \"%s\" install" fullword wide
        $s7 = "subject=%s&data=" fullword ascii
        $s8 = "dll-x64.dll" fullword ascii
        $s9 = "dll-x32.dll" fullword ascii
        $pdb1 = "\\virus-dropper\\Release\\virus-dropper.pdb" ascii
        $pdb2 = "\\virus-init\\Release\\virus-init.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (3 of ($s*) and 1 of ($pdb*)))
}
