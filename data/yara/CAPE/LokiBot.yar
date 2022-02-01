rule LokiBot
{
    meta:
        author = "kevoreilly"
        description = "LokiBot Payload"
        cape_type = "LokiBot Payload"
    strings:
        $a1 = "DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW"
        $a2 = "last_compatible_version"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
