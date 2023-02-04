rule BHunt {
    meta:
        author = "ditekSHen"
        description = "Detects BHunt infostealer"
        cape_type = "BHunt Infostealer Payload"
    strings:
        $x1 = "BHUNT.Resources.resources" fullword ascii
        $x2 = "//minecraftsquid.hopto.org/" wide
        $s1 = "chaos_crew" ascii wide
        $s2 = "golden7" ascii wide
        $s3 = "mrpropper" ascii wide
        $s4 = "/ifo.php?" ascii wide
        $s5 = "bonanza=:=" ascii wide
        $s6 = "blackjack=:=" ascii wide
        $s7 = "SendPostData" fullword ascii
        $c1 = "cmd /c REG ADD" wide
        $c2 = "taskkill /F /IM" wide
        $c3 = "cmd.exe /c wmic" wide
        $g1 = "$ca9a291d-266c-41dc-9f1c-93cfe0dcac16" fullword ascii
        $g2 = "$6d0feb35-213d-4b9f-afc7-06d168cfcb5e" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and (5 of ($s*) or 2 of ($c*))) or (6 of ($s*) and 2 of ($c*)) or (all of ($g*) and 2 of them))
}
