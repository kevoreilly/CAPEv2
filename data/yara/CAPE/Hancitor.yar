rule Hancitor
{
    meta:
        author = "threathive"
        description = "Hancitor Payload"
        cape_type = "Hancitor Payload"
    strings:
       $fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
       $fmt_string2 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
       $ipfy = "http://api.ipify.org"
       $user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
    condition:
        uint16(0) == 0x5A4D and all of them
}
