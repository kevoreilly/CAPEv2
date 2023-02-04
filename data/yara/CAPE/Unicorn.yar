rule Unicorn {
    meta:
        author = "ditekSHen"
        description = "Detects Unicorn infostealer"
        cape_type = "Unicorn Infostealer Payload"
    strings:
        $x1 = "WinHTTP Downloader/1.0" fullword wide
        $x2 = "[CTRL + %c]" fullword wide
        $x3 = "\\UnicornLog.txt" fullword wide
        $x4 = "/*INITIALIZED*/" fullword wide
        $s1 = { 2f 00 63 00 20 00 22 00 43 00 4f 00 50 00 59 00
               20 00 2f 00 59 00 20 00 2f 00 42 00 20 00 22 00
               25 00 73 00 22 00 20 00 22 00 25 00 73 00 22 00
               22 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00
               65 }
        $s2 = { 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00
               2e 00 65 00 78 00 65 00 00 00 00 00 25 00 73 00
               20 00 22 00 25 00 73 00 22 00 2c 00 25 00 68 00
               73 }
        $s3 = "%*[^]]%c%n" fullword ascii
        $s4 = "file://%s%s%s" fullword ascii
        $s5 = "%s://%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" fullword ascii
        $s6 = "regex_start_injects" fullword ascii
        $s7 = "DLEXEC" fullword ascii
        $s8 = "^((((3|1)[A-Za-z0-9]{33}))(\\s|$)|(bc1q)[A-Za-z0-9]{38}(\\s|$))" fullword ascii
        $s9 = "^(0x)?[A-Za-z0-9]{40}(\\s|$)" fullword ascii
        $s10 = "clipRegex" fullword ascii
        $s11 = "%s?k=%s&src=clip&id=%s" fullword ascii
        $s12 = "http://izuw6rclbgl2lwsh.onion/o.php" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or 8 of ($s*) or (3 of ($x*) and 5 of ($s*)))
}
