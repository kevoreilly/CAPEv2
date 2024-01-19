rule Latrodectus
{
    meta:
        author = "enzok"
        description = "Latrodectus Payload"
        cape_type = "Latrodectus Payload"
        hash = "a547cff9991a713535e5c128a0711ca68acf9298cc2220c4ea0685d580f36811"
    strings:
        $fnvhash1 = {C7 04 24 C5 9D 1C 81 48 8B 44 24 20 48 89 44 24 08}
        $fnvhash2 = {8B 0C 24 33 C8 8B C1 89 04 24 69 04 24 93 01 00 01}
        $procchk1 = {E8 [3] FF 85 C0 74 [2] FF FF FF FF E9 [4] E8 [4] 89 44 24 ?? E8 [4] 83 F8 4B 73 ?? 83 [3] 06}
        $procchk2 = {72 [2] FF FF FF FF E9 [4] E8 [4] 83 F8 32 73 ?? 83 [3] 06}
    condition:
        all of them
}