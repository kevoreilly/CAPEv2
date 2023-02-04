rule TYRAT {
    meta:
        author = "ditekSHen"
        description = "Detects TYRAT"
        cape_type = "TYRAT Payload"
    strings:
        $s1 = "C:\\$MSIRecycle.Bin\\" fullword ascii
        $s2 = "Range: bytes=%d-" fullword ascii
        $s3 = "GET%sHTTP/1.1" fullword ascii
        $s4 = "DllServer.dll" fullword ascii
        $s5 = ".Bin\\bnch" ascii
        $s6 = "User-Agent: wget" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
