rule AvosLocker {
    meta:
        author = "ditekSHen"
        description = "Detect/Hunt for AvosLocker ransomware"
        cape_type = "AvosLocker Payload"
    strings:
        $s1 = "GET_YOUR_FILES_BACK.txt" ascii wide
        $s2 = ".avos" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
