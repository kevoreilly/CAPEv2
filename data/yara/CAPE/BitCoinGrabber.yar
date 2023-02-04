rule BitCoinGrabber {
    meta:
        author = "ditekSHen"
        description = "Detects generic bitcoin stealer"
        cape_type = "BitCoinGrabber Payload"
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s2 = "Bitcoin-Grabber" ascii
        $s3 = "Bitcoin_Grabber" ascii
        $s4 = "encrypt resources [compress]T" fullword ascii
        $s5 = "code control flow obfuscationT" fullword ascii
        $s6 = "\\Users\\lakol\\Desktop\\a\\Crypto Currency Wallet Changer\\" ascii
        $pat1 = "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}\\b" fullword wide
        $pat2 = "\\b0x[a-fA-F0-9]{40}\\b" fullword wide
        $pat3 = "\\b4([0-9]|[A-B])(.){93}\\b" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*) or (all of ($pat*) and 2 of ($s*))
}
