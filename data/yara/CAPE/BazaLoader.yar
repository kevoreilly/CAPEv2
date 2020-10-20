rule BazaLoader
{
    meta:
        author = "kevoreilly"
        description = "BazaLoader Loader"
        cape_type = "BazaLoader Loader"
    strings:
        $snippet1 = {C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F [2-3] B8 09 04 02 81 [0-1] 83 C? 7F [3-5] D? C1 FA 06 8B C2 C1 E8 1F 03 D0 6B C2 7F}
    condition:
        uint16(0) == 0x5A4D and any of them
}
