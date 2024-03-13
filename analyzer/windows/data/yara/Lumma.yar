rule Lumma
{
    meta:
        author = "kevoreilly"
        description = "Lumma config extraction"
        cape_options = "bp0=$c2+57,action0=string:esp+64,count=0,typestring=Lumma Config"
        packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
    strings:
        $c2 = {B8 FF FF FF FF 0F 1F 84 00 00 00 00 00 80 7C [2] 00 8D 40 01 75 F6 C7 44 [2] 00 00 00 00 8D}
    condition:
        uint16(0) == 0x5a4d and any of them
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
