rule NitroBunnyDownloader
{
    meta:
        author = "enzok"
        description = "NitroBunnyDownloader"
        cape_type = "NitroBunnyDownloader Payload"
        hash = "960e59200ec0a4b5fb3b44e6da763f5fec4092997975140797d4eec491de411b"
    strings:
        $config1 = {E8 [3] 00 41 B8 ?? ?? 00 00 48 8D 15 [3] 00 48 89 C1 48 89 ?? E8 [3] 00}
        $config2 = {E8 [3] 00 48 8D 15 [3] 00 41 B8 ?? ?? 00 00 48 89 C1 48 89 ?? E8 [3] 00}
        $string1 = "X-Amz-User-Agent:" wide
        $string2 = "Amz-Security-Flag:" wide
        $string3 = "/cart" wide
        $string4 = "Cookie: " wide
        $string5 = "wishlist" wide
    condition:
        uint16(0) == 0x5A4D and 1 of ($config*) and 2 of ($string*)
}
