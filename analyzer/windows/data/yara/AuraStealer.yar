rule AuraStealerBypass
{
    meta:
        author = "enzok"
        description = "Bypass AuraStealer"
        cape_options = "bp0=$antivm1+3,action0=skip,count=0"
        packed = "a9c47f10d5eb77d7d6b356be00b4814a7c1e5bb75739b464beb6ea03fc36cc85"
    strings:
        $antivm1 = {39 04 11 0f 94 C3 8B 44 ?? ?? 85 C0}  //+3, skip
        $conf = {8D BE ?? 00 00 00 68 00 40 00 00 5? 5? FF D1 83 C4 ?? 8B 07 8B 57 04 29 C2}
        $keyexpansion = {31 C0 8A 1C 82 88 1C 81 8A 5C 82 01 88 5C 81 01 8A 5C 82 02 88 5C 81 02 8A 5C 82 03 88 5C 81 03 4? 83 F8 08 75 ?? B? 08 00 00 00}
    condition:
        all of them
}

rule AuraStealerConfig
{
    meta:
        author = "enzok"
        description = "AuraStealer Config"
        cape_options = "bp1=$conf*-1,action1=string:eax,count=1,hc1=1,typestring=AuraStealer Config"
        packed = "a9c47f10d5eb77d7d6b356be00b4814a7c1e5bb75739b464beb6ea03fc36cc85"
    strings:
        $conf = {8D BE ?? 00 00 00 68 00 40 00 00 5? 5? FF D1 83 C4 ?? 8B 07 8B 57 04 29 C2}
        $antivm1 = {39 04 11 0f 94 C3 8B 44 ?? ?? 85 C0}
        $keyexpansion = {31 C0 8A 1C 82 88 1C 81 8A 5C 82 01 88 5C 81 01 8A 5C 82 02 88 5C 81 02 8A 5C 82 03 88 5C 81 03 4? 83 F8 08 75 ?? B? 08 00 00 00}
    condition:
        all of them
}
