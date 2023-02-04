rule LockFile {
    meta:
        author = "ditekSHen"
        description = "Detects LockFile ransomware"
        cape_type = "LockFile Payload"
    strings:
        $x1 = "LOCKFILE" fullword ascii
        $x2 = "25a01bb859125507013a2fe9737d3c33" fullword ascii
        $s1 = "</key>" fullword ascii
        $s2 = "<computername>%s</computername>" fullword ascii
        $s3 = "<blocknum>%d</blocknum>" fullword ascii
        $s4 = "%s\\%s-%s-%d%s" fullword ascii
        $s5 = ">RAC=OQD:S>P@:AO?R:EEOS:ARDD=N?EENSB" ascii wide
        $m1 = "<title>LOCKFILE</title>" ascii wide nocase
        $m2 = "<hta:application id=LOCKFILE applicationName=LOCKFILE" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or (1 of ($x*) and (2 of ($s*) or 1 of ($m*))) or (1 of ($m*) and (1 of ($x*) or 2 of ($s*))))
}
