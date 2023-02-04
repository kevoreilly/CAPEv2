rule DeepRats {
    meta:
        author = "ditekSHen"
        description = "Detects DeepRats"
        cape_type = "DeepRats Payload"
    strings:
        $s1 = "https://freegeoip.live/json/https://myexternalip.com/rawin" ascii
        $s2 = "github.com/cretz/bine" ascii
        $s3 = "github.com/kbinani/screenshot" ascii
        $s4 = "socks5://%s:%d" ascii
        $s5 = "socks5://%s:%s@%s:%d" ascii
        $s6 = "http://%s:%d" ascii
        $s7 = "http://%s@%s:%d" ascii
        $s8 = "%SystemRoot%\\system32\\--CookieAuthentication" ascii
        $s9 = "tor_addr_" ascii
        $f1 = ".GetVnc" ascii
        $f2 = ".GetCommand" ascii
        $f3 = ".GetPayload" ascii
        $f4 = ".ListenCommands" ascii
        $f5 = ".ReceiveFile" ascii
        $f6 = ".RegisterImplant" ascii
        $f7 = ".Screenshot" ascii
        $f8 = ".SendFile" ascii
        $f9 = ".StartShell" ascii
        $f10 = ".UnregisterImplant" ascii
        $f11 = ".VncInstalled" ascii
        $f12 = ".PingPong" ascii
        $f13 = ".ListenCMD" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or 8 of ($f*))
}
