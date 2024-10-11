rule FormhookA
{
    meta:
        author = "kevoreilly"
        description = "Formbook Anti-hook Bypass"
        cape_options = "clear,bp0=$remap_ntdll_0,action0=setedx:ntdll,count0=1,bp1=$remap_ntdll_1,action1=setdst:ntdll,count1=1,force-sleepskip=1"
        packed = "9e38c0c3c516583da526016c4c6a671c53333d3d156562717db79eac63587522"
        packed = "b8e44f4a0d92297c5bb5b217c121f0d032850b38749044face2b0014e789adfb"
    strings:
        $remap_ntdll_0 = {33 56 04 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
        $remap_ntdll_1 = {33 56 0C 8D 86 [2] 00 00 68 F0 00 00 00 50 89 56 ?? E8 [4] 8B [1-5] 6A 00 6A 04 8D 4D ?? 51 6A 07 52 56 E8 [4] 8B 45 ?? 83 C4 20 3B}
    condition:
        any of them
}

rule FormhookB
{
    meta:
        author = "kevoreilly"
        description = "Formbook Anti-hook Bypass"
        cape_options = "clear,bp0=$entry,action0=scan,hc0=1,bp1=$new_remap+6,action1=setdst:ntdll,count=0,force-sleepskip=1"
        packed = "08c5f44d57f5ccc285596b3d9921bf7fbbbf7f9a827bb3285a800e4c9faf6731"
    strings:
        $remap_ntdll = {33 96 [2] 00 00 8D 86 [2] 00 00 68 F0 00 00 00 50 89 [2-5] E8 [4-10] 6A 00 6A 0? 8D 4D ?? 51 6A}
        $entry = {55 8B EC 83 EC ?4 53 56 57 [480-520] 8B E5 5D C3}
        $new_remap = {90 90 90 90 90 90 8B (86 [2] 00 00|46 ??|06) 5F 5E 5B 8B E5 5D C3}
    condition:
        2 of them
}

rule FormconfA
{
    meta:
        author = "kevoreilly"
        description = "Formbook Config Extraction"
        cape_options = "clear,bp0=$c2,action0=string:rcx+1,bp1=$decoy+67,action1=string:rcx+1,count=0,typestring=Formbook Config"
        packed = "b8e44f4a0d92297c5bb5b217c121f0d032850b38749044face2b0014e789adfb"
    strings:
        $c2 = {44 8B C6 48 8B D3 49 8B CE E8 [4] 44 88 23 41 8B DD 48 8D [2] 66 66 66 0F 1F 84 00 00 00 00 00 BA 8D 00 00 00 41 FF C4}
        $decoy = {8B D7 0F 1F 44 00 00 0F B6 03 FF C0 48 98 48 03 D8 48 FF CA 75 ?? 44 0F B6 03 48 8D 53 01 48 8D 4C [2] E8}
    condition:
        all of them
}

rule Formhelper
{
    meta:
        author = "kevoreilly"
        description = "Formbook Config Extraction"
        cape_options = "clear,bp2=$config,action2=scan,count=0"
        packed = "0270016f451f9ba630f2ea4e2ea006fb89356627835b560bb2f4551a735ba0e1"
    strings:
        $config = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 [4] 48 81 EC [2] 00 00 45 33 ?? 33 C0 4C 8B E9 4C 89}
        $decode = {66 66 66 66 0F 1F 84 00 00 00 00 00 0F B6 41 01 48 FF C9 28 41 01 49 FF C9}
    condition:
        all of them
}

rule FormconfB
{
    meta:
        author = "kevoreilly"
        description = "Formbook Config Extraction"
        cape_options = "clear,bp0=$c2_1,bp0=$c2_2+38,action0=string:rcx+1,bp1=$decoy,action1=string:rcx+1,bp2=$config,action2=scan,count=0,typestring=Formbook Config"
        packed = "60571b2683e7b753a77029ebe9b5e1cb9f3fbfa8d6a43e4b7239eefd13141ae4"
    strings:
        $c2_1 = {44 0F B6 5D ?? 45 84 DB 74 ?? 48 8D 4D [1-5] 41 80 FB 2F 74 11 0F B6 41 01 48 FF C1 FF C3 44 0F B6 D8 84 C0 75}
        $c2_2 = {49 8D 8D [2] 00 00 B2 ?? E8 [4] 4D 8D 85 [2] 00 00 49 8D 8D [2] 00 00 BA ?? 00 00 00 E8}
        $decoy = {45 3B B5 [2] 00 00 [0-7] 44 8D 1C 33 48 8D 7D [1-5] 42 C6 44 [2] 00 [0-4] 48 8B CF E8}
        $config = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 [4] 48 81 EC [2] 00 00 45 33 F6 33 C0 4C 8B E9 4C 89 75}
    condition:
        2 of them
}

rule FormconfC
{
    meta:
        author = "kevoreilly"
        description = "Formbook Config Extraction"
        cape_options = "clear,bp0=$c2,hc0=1,action0=string:rcx+1,bp1=$decoy,action1=string:rcx+1,count=0,typestring=Formbook Config"
        packed = "0270016f451f9ba630f2ea4e2ea006fb89356627835b560bb2f4551a735ba0e1"
    strings:
        $c2 = {49 8D 95 [2] 00 00 49 8D 8D [2] 00 00 41 B8 07 00 00 00 E8 [4] 49 8B CD 45 88 [3] 00 00 E8 [4] 33 C0}
        $decoy = {48 8B CF E8 [4] 48 8B D7 44 8B C0 49 8B 85 [4] 49 (8D 8C 04 [2] 00 00|8D 0C 04) E8 [4] 48 8B CF E8}
    condition:
        all of them
}
