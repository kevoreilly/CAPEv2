rule Socks5Systemz
{
    meta:
        author = "kevoreilly"
        description = "Socks5Systemz Payload"
        cape_type = "Socks5Systemz Payload"
        packed = "9b997d0de3fe83091726919a0dc653e22f8f8b20b1bb7d0b8485652e88396f29"
    strings:
        $chunk1 = {0F B6 84 8A [4] E9 [3] (00|FF)}
        $chunk2 = {0F B6 04 8D [4] E9 [3] (00|FF)}
        $chunk3 = {0F B6 04 8D [4] E9 [3] (00|FF)}
        $chunk4 = {0F B6 04 8D [4] E9 [3] (00|FF)}
        $chunk5 = {66 0F 6F 05 [4] E9 [3] (00|FF)}
        $chunk6 = {F0 0F B1 95 [4] E9 [3] (00|FF)}
        $chunk7 = {83 FA 04 E9 [3] (00|FF)}
    condition:
        uint16(0) == 0x5A4D and 6 of them
}
