rule Lumma
{
    meta:
        author = "kevoreilly"
        description = "Lumma config extraction"
        cape_options = "bp0=$decode+5,action0=string:ebp,count=0,bp1=$patch+8,action1=skip,typestring=Lumma Config"
        packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
    strings:
        $c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
        $decode = {C6 44 05 00 00 83 C4 2C 5E 5F 5B 5D C3}
        $patch = {66 C7 0? 00 00 8B 46 1? C6 00 01 8B}
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule LummaRemap
{
    meta:
        author = "kevoreilly"
        description = "Lumma ntdll-remap bypass"
        cape_options = "ntdll-remap=0"
        packed = "7972cbf2c143cea3f90f4d8a9ed3d39ac13980adfdcf8ff766b574e2bbcef1b4"
    strings:
        $remap = {C6 44 24 20 00 C7 44 24 1C C2 00 00 90 C7 44 24 18 00 00 FF D2 C7 44 24 14 00 BA 00 00 C7 44 24 10 B8 00 00 00 8B ?? 89 44 24 11}
    condition:
        uint16(0) == 0x5a4d and any of them
}
