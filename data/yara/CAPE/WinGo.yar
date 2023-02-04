rule WinGo {
    meta:
        author = "ditekSHen"
        description = "Detects specific malicious Golang executables"
        cape_type = "WinGo Payload"
    strings:
        $s1 = "Go build ID:" ascii
        $s2 = /main\.[a-z]{9}Delete/ fullword ascii
        $s3 = /main\.[a-z]{9}Update/ fullword ascii
        $s4 = /main\.[a-z]{9}rundll/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of them and #s2 > 2 and #s3 > 2 and #s4 > 2)
}
