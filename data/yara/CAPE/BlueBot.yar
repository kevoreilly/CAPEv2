rule BlueBot {
    meta:
        author = "ditekSHen"
        description = "Detects BlueBot"
        cape_type = "BlueBot Payload"
    strings:
        $x1 = "Blue_Botnet" wide
        $x2 = "5-START-http" ascii
        $x3 = "*300-END-" ascii
        $x4 = "botlogger.php" wide
        $s1 = "//TARGET//" wide
        $s2 = "//BLOG//" wide
        $s3 = "MCBOTALPHA" wide
        $s4 = "//IPLIST//" wide
        $s5 = "Host: //BLOG//" wide
        $s6 = "User-Agent: //USERAGENT//" wide
        $s7 = "<string>//TARGET//</string>" wide
        $s8 = "POST //URL// HTTP/1.1/r/n" wide
        $v1 = "<attack>b__" ascii
        $v2 = "PressData" fullword ascii
        $v3 = "POSTPiece" fullword ascii
        $v4 = /(load|tcp|udp)Stuff/ fullword ascii
        $v5 = "isAttacking" fullword ascii
        $v6 = "DoSAttack" fullword ascii
        $v7 = "prv_attack" fullword ascii
        $v8 = "blogList"fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 5 of ($s*) or 5 of ($v*) or 9 of them)
}
