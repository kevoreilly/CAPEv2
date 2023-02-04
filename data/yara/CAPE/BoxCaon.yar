rule BoxCaon {
    meta:
        author = "ditekSHen"
        description = "Detects IndigoZebra BoxCaon"
        cape_type = "BoxCaon Payload"
    strings:
        $s1 = "<RetCMD null>" fullword wide
        $s2 = "<txt null>" fullword wide
        $s3 = "C:\\Users\\Public\\%d\\" fullword wide
        $s4 = "api.dropboxapi.com" fullword wide
        $s5 = "/2/files/upload" fullword wide
        $ts1 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" ascii wide
        $ts2 = "%s /A /C \"%s\" > %s" ascii wide
        $ts3 = "ersInfo" ascii wide
        $ts4 = "%svmpid%d.log" ascii wide
        $ts5 = "%scscode%d.log" ascii wide
    condition:
        (uint16(0) == 0x5a4d and all of ($s*)) or all of ($ts*)
}
