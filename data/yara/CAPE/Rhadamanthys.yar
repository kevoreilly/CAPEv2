rule Rhadamanthys
{
    meta:
        author = "kevoreilly, YungBinary"
        description = "Rhadamanthys Loader"
        cape_type = "Rhadamanthys Loader"
    strings:
        $rc4 = {88 4C 01 08 41 81 F9 00 01 00 00 7C F3 89 75 08 33 FF 8B 4D 08 3B 4D 10 72 04 83 65 08 00}
        $code = {8B 4D FC 3B CF 8B C1 74 0D 83 78 04 02 74 1C 8B 40 1C 3B C7 75 F3 3B CF 8B C1 74 57 83 78 04 17 74 09 8B 40 1C 3B C7 75 F3 EB}
        $conf = {46 BB FF 00 00 00 23 F3 0F B6 44 31 08 03 F8 23 FB 0F B6 5C 39 08 88 5C 31 08 88 44 39 08 02 C3 8B 5D 08 0F B6 C0 8A 44 08 08}
        $beef = {57 8D 44 33 FC 53 83 C6 FC 50 56 E8 [4] 83 C4 10 66 81 3F EF BE 0F 85}
        $config_2 = {0F B6 4F 2A 8D 77 2A 33 C0 6A 03 89 45 F8 89 45 FC 89 45 08 8B C1}
        $cape_string = "cape_options"
    condition:
        2 of them and not $cape_string
}
