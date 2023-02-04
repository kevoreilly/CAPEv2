rule GloomaneStealer {
    meta:
        author = "ditekSHen"
        description = "Detects GloomaneStealer"
        cape_type = "GloomaneStealer Payload"
    strings:
        $x1 = "=GLOOMANE STEALER=" wide
        $x2 = "Maded by GLOOMANE" wide
        $s1 = "\\44CALIBER" ascii
        $s2 = "Ethernet()" fullword wide
        $s3 = ":spy: NEW LOG FROM" wide
        $s4 = ":eye: IP:" wide
        $s5 = ":file_folder: Grabbed Files" wide
        $s6 = "$ebc25cf6-9120-4283-b972-0e5520d0000C" fullword ascii
        $s7 = "$3b0e2d3d-3d66-42bb-8f9c-d6e188f359ae" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and 3 of ($s*)) or 5 of ($s*))
}
