rule Socks5Systemz
{
    meta:
        author = "kevoreilly"
        description = "Socks5Systemz config extraction"
        cape_options = "br0=user32::wsprintfA,br1=ntdll::sprintf,action2=string:[esp],action3=string:[esp],count=0,typestring=Socks5Systemz Config"
        packed = "9b997d0de3fe83091726919a0dc653e22f8f8b20b1bb7d0b8485652e88396f29"
    strings:
        $chunk1 = {0F B6 84 8A [4] E9 [3] (00|FF)}
        $chunk2 = {0F B6 04 8D [4] E9 [3] (00|FF)}
        $chunk3 = {66 0F 6F 05 [4] E9 [3] (00|FF)}
        $chunk4 = {F0 0F B1 95 [4] E9 [3] (00|FF)}
        $chunk5 = {83 FA 04 E9 [3] (00|FF)}
        $chunk6 = {8A 04 8D [4] E9 [3] (00|FF)}
        $chunk7 = {83 C4 04 83 C4 04 E9}
        $chunk8 = {83 C2 04 87 14 24 5C E9}
    condition:
        uint16(0) == 0x5A4D and 5 of them
}
