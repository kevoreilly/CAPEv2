rule Guloader
{
    meta:
        author = "kevoreilly"
        description = "Shellcode injector and downloader"
        cape_type = "Guloader Payload"
    strings:
        $trap0 = {0F 85 [2] FF FF 81 BD ?? 00 00 00 [2] 00 00 0F 8F [2] FF FF 39 D2 83 FF 00}
        $trap1 = {49 83 F9 00 75 [1-20] 83 FF 00 [2-6] 81 FF}
        $trap2 = {39 CB 59 01 D7 49 85 C8 83 F9 00 75 B3}
        $trap3 = {61 0F AE E8 0F 31 0F AE E8 C1 E2 20 09 C2 29 F2 83 FA 00 7E CE C3}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-800] FF E3}
        $antidbg = {39 48 04 0F 85 [4] 39 48 08 0F 85 [4] 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [4] 39 48 18 0F 85}
        $except = {8B 45 08 8B 00 [0-1] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}
        $cape_string = "cape_options"
    condition:
        2 of them and not $cape_string
}
