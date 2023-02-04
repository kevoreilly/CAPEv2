import "pe"

rule WinDealer {
    meta:
        author = "ditekSHen"
        description = "Detects WinDealer"
        cape_type = "WinDealer"
    strings:
        $d1 = "downfile" fullword ascii
        $d2 = "getmypath" fullword ascii
        $d3 = "content-type: monitor" fullword ascii
        $d4 = "content-type: UsedType" fullword ascii
        $d5 = "write command error" fullword ascii
        $d6 = "C:\\WINDOWS\\system32\\kernel32.dll" fullword ascii
        $l1 = "currentconfig" fullword ascii
        $l2 = "remotedomain" fullword ascii
        $l3 = "reserveip" fullword ascii
        $l4 = "otherinfo" fullword ascii
        $l5 = "filelen" fullword ascii
        $l6 = "%s%s.bak" fullword wide
        $l7 = "localmachine" fullword ascii
        $l8 = "remoteip" fullword ascii
        $l9 = "datastate" fullword ascii
        $l10 = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection" fullword ascii
        $s1 = "%s\\%s\\V5_History.dat" fullword wide
        $s2 = "%s\\%s\\history2.dat" fullword wide
        $s3 = "%s\\%s\\history.imw" fullword wide
        $s4 = "%s\\%s\\main.imw" fullword wide
        $s5 = "%s%d.%d.%d.%dWindows/%u" fullword ascii
        $s6 = "%s\\%c_%s_tmp" fullword wide
        $s7 = "%s\\%s\\main.db" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((4 of ($d*) and 1 of ($s*)) or (5 of ($s*) and 1 of ($d*)) or 6 of ($l*) or (pe.exports("DealC") and pe.exports("DealR") and pe.exports("DealS") and 1 of them))
}
