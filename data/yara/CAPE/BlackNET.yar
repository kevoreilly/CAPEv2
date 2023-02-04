rule BlackNET {
    meta:
        author = "ditekSHen"
        description = "BlackNET RAT payload"
        cape_type = "BlackNET Payload"
    strings:
        $s1 = "SbieCtrl" fullword wide
        $s2 = "SpyTheSpy" fullword wide
        $s3 = "\\BlackNET.dat" fullword wide
        $s4 = "StartDDOS" fullword wide
        $s5 = "UDPAttack" fullword wide
        $s6 = "ARMEAttack" fullword wide
        $s7 = "TCPAttack" fullword wide
        $s8 = "HTTPGetAttack" fullword wide
        $s9 = "RetriveLogs" fullword wide
        $s10 = "StealPassword" fullword wide
        $s11 = "/create /f /sc ONSTART /RL HIGHEST /tn \"'" fullword wide
        $b1 = "DeleteScript|BN|" fullword wide
        $b2 = "|BN|Online" fullword wide
        $b3 = "NewLog|BN|" fullword wide
        $cnc1 = "/getCommand.php?id=" fullword wide
        $cnc2 = "/upload.php?id=" fullword wide
        $cnc3 = "connection.php?data=" fullword wide
        $cnc4 = "/receive.php?command=" fullword wide
    condition:
        uint16(0) == 0x5a4d and (9 of ($s*) or all of ($cnc*) or all of ($b*) or 12 of them)
}
