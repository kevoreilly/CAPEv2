rule Gaudox {
    meta:
        author = "ditekshen"
        description = "Detects Gaudox RAT"
        cape_type = "Gaudox Payload"
    strings:
        $s1 = "hdr=%s&tid;=%s&cid;=%s&trs;=%i" ascii wide
        $s2 = "\\\\\\\\.\\\\PhysicalDrive%u" ascii wide
        //$s3 = "Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0" ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
