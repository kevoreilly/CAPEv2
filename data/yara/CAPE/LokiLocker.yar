rule LokiLocker {
    meta:
        author = "ditekSHen"
        description = "Detects LokiLocker ransomware"
        cape_type = "LokiLocker Payload"
    strings:
        $x1 = "SOFTWARE\\Loki" fullword wide
        $x2 = "Cpriv.Loki" fullword wide
        $x3 = "Loki/" wide
        $x4 = /loki(\s)?locker/ fullword wide nocase
        $s1 = "Restore-My-Files.txt" wide
        $s2 = "loading encryption keys" wide
        $s3 = "Kill switch -> enabled" wide
        $s4 = "ScanSMBShares" fullword ascii
        $s5 = "RewriteMBR" fullword ascii
        $s6 = /Encrypt(Drives|File|WinVolume|OsDrive)/ fullword ascii
        $n1 = "unique-id=" ascii wide
        $n2 = "&disk-size=" ascii wide
        $n3 = "&user=Darwin&cpu-name=" ascii wide
        $n4 = "&ram-size=" ascii wide
        $n5 = "&os-name=" ascii wide
        $n6 = "&chat-id=" ascii wide
        $n7 = "&msg-id=" ascii wide
        $n8 = "&elapsed-time=" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or 4 of ($s*) or 6 of ($n*) or (3 of ($s*) and 3 of ($n*)) or (1 of ($x*) and (2 of ($s*) or 2 of ($n*))))
}
