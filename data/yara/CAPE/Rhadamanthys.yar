rule Rhadamanthys
{
    meta:
        author = "kevoreilly, YungBinary"
        description = "Rhadamanthys Payload"
        cape_type = "Rhadamanthys Payload"
    strings:
        $rc4 = {88 4C 01 08 41 81 F9 00 01 00 00 7C F3 89 75 08 33 FF 8B 4D 08 3B 4D 10 72 04 83 65 08 00}
        $code = {8B 4D FC 3B CF 8B C1 74 0D 83 78 04 02 74 1C 8B 40 1C 3B C7 75 F3 3B CF 8B C1 74 57 83 78 04 17 74 09 8B 40 1C 3B C7 75 F3 EB}
        $conf_1 = {46 BB FF 00 00 00 23 F3 0F B6 44 31 08 03 F8 23 FB 0F B6 5C 39 08 88 5C 31 08 88 44 39 08 02 C3 8B 5D 08 0F B6 C0 8A 44 08 08}
        $conf_2 = {0F B6 4F 2A 8D 77 2A 33 C0 6A 03 89 45 F8 89 45 FC 89 45 08 8B C1}
        $beef = {57 8D 44 33 FC 53 83 C6 FC 50 56 E8 [4] 83 C4 10 66 81 3F EF BE 0F 85}
        $anti = {50 68 [4] 68 [4] E8 [4] 83 C4 0C A3 [4] 85 C0 74}
        $dnr = {99 52 50 8D 45 ?? 99 52 50 8B C7 99 52 50 8B C3 99 52 50}
        $sys = {83 E4 F0 6A 33 E8 00 00 00 00 83 04 24 05 CB}
        $cape_string = "cape_options"
    condition:
        2 of them and not $cape_string
}

rule RhadamanthysLoader
{
    meta:
        author = "kevoreilly"
        description = "Rhadamanthys Loader"
        cape_type = "Rhadamanthys Loader"
    strings:
        $ref = {33 D2 B9 0B 00 00 00 F7 F1 B8 01 00 00 00 6B C8 00 8D 84 0D [4] 0F BE 0C 10 8B 95 [4] 03 95 [4] 0F B6 02 33 C1 8B 8D [4] 03 8D [4] 88 01}
        $ntdll = {B9 6E 00 00 00 66 89 8D [4] BA 74 00 00 00 66 89 95 [4] B8 64 00 00 00 66 89 85 [4] B9 6C 00 00 00 66 89 8D [4] BA 6C 00 00 00 66 89 95}
        $exit = {6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 8B 95 [4] 52 8B 85 [4] 50 6A 00 68 FF FF 1F 00}
    condition:
        2 of them
}
