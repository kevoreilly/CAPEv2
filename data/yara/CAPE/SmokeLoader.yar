rule SmokeLoader
{
    meta:
        author = "kevoreilly"
        cape_type = "SmokeLoader"
    strings:
        $snippet1 = {8A 10 80 CA 60 03 DA D1 E3 03 45 10 8A 08 84 C9 E0 EE 33 C0 8B 4D 0C 3B D9 74 01 40 5A 5B 59 8B E5 5D C2 0C 00}
        $snippet2 = {0F B6 51 01 0F B6 19 C1 EA 02 C1 E3 06 03 D3 2B FA 83 C1 02 3B F8 74 76 81 EF 00 40 00 00 8B D8 2B DF}
    condition:
        any of them
}
