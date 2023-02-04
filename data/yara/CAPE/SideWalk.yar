rule SideWalk {
    meta:
        author = "ditekSHen"
        description = "Detects SideWalk"
        cape_type = "SideWalk Payload"
    strings:
        $s1 = "Decommit" fullword ascii
        $s2 = "Shellc0deRunner" fullword ascii
        $s3 = "shellc0de" fullword ascii
        $s4 = "C:\\Windows\\System32\\msdt.exe" fullword wide
        $s5 = "StartProcessWOPid" fullword ascii
        $s6 = "StartProcessWithParent" fullword ascii
        $m1 = "alloctype" fullword ascii
        $m2 = "ThreadIoPriority" fullword ascii
        $m3 = "PebAddress" fullword ascii
        $m4 = "dotnet.4.x64.dll" fullword wide
        $m5 = "LogonNetCredentialsOnly" fullword ascii
        $m6 = "ThreadIdealProcessor" fullword ascii
        $m7 = "LogonWithProfile" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or all of ($m*) or (11 of them))
}
