rule PingBack {
    meta:
        author = "ditekSHen"
        description = "Detects PingBack ICMP backdoor"
        cape_type = "PingBack Payload"
    strings:
        $s1 = "Sniffer ok!" fullword ascii
        $s2 = "recv icmp packet!" fullword ascii
        $s3 = "WSASocket() failed: %d" fullword ascii
        $s4 = "file on remote computers success" ascii
        $s5 = "listen port error!" fullword ascii
        $s6 = "\\PingBackService" ascii
        $c1 = "exec" fullword ascii
        $c2 = "rexec" fullword ascii
        $c3 = "exep" fullword ascii
        $c4 = "download" fullword ascii
        $c5 = "upload" fullword ascii
        $c6 = "shell" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or all of ($c*) or (4 of ($c*) and 2 of ($s*)))
}
