rule NGLite {
    meta:
        author = "ditekSHen"
        description = "Detects NGLite"
        cape_type = "NGLite Payload"
    strings:
        $x1 = "/lprey/main.go" ascii
        $x2 = "/NGLiteV1.01/lprey/" ascii
        $x3 = "/ng.com/lprey/" ascii
        $x4 = "/mnt/hgfs/CrossC2-2.2/src/" ascii
        $x5 = "WHATswrongwithUu" ascii
        $s1 = "main.Preylistener" fullword ascii
        $s2 = "main.Runcommand" fullword ascii
        $s3 = "main.RandomPass" fullword ascii
        $s4 = "main.AesEncode" fullword ascii
        $s5 = "main.RsaEncode" fullword ascii
        $s6 = "main.AesDecode" fullword ascii
        $s7 = "main.initonce" fullword ascii
        $s8 = "main.SendOnce" fullword ascii
        $s9 = "main.clientConf" fullword ascii
        $s10 = "main.Sender" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and ((1 of ($x*) and 2 of ($s*)) or (6 of ($s*)))
}
