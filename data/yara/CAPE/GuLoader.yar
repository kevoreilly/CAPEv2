rule GuLoader
{
    meta:
        author = "kevoreilly"
        description = "Shellcode injector and downloader"
        cape_type = "GuLoader Payload"
    strings:
        $trap0 = {0F 85 [2] FF FF 81 BD ?? 00 00 00 [2] 00 00 0F 8F [2] FF FF 39 D2 83 FF 00}
        $trap1 = {49 83 F9 00 75 [1-20] 83 FF 00 [2-6] 81 FF}
        $trap2 = {39 CB 59 01 D7 49 85 C8 83 F9 00 75 B3}
        $trap3 = {61 0F AE E8 0F 31 0F AE E8 C1 E2 20 09 C2 29 F2 83 FA 00 7E CE C3}
        $antihook = {FF 34 08 [0-48] 8F 04 0B [0-80] 83 C1 04 83 F9 18 75 [0-128] FF E3}
        $cape_string = "cape_options"
    condition:
        2 of them and not $cape_string
}
