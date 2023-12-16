rule RisePro
{
    meta:
        author = "kevoreilly"
        //cape_options = "br0=$decode1-49,action1=string:eax,count=1,bp2=$decode2+25,action2=string:eax"
        cape_options = "bp0=$c2+15,action0=string:edx,bp1=$c2+41,action1=string:ecx,count=1"
        hash = "1b69a1dd5961241b926605f0a015fa17149c3b2759fb077a30a22d4ddcc273f6"
    strings:
        $decode1 = {8A 06 46 84 C0 75 F9 2B F1 B8 FF FF FF 7F 8B 4D ?? 8B 51 ?? 2B C2 3B C6 72 38 83 79 ?? 10 72 02 8B 09 52 51 56 53 51 FF 75 ?? 8B CF E8}
        $decode2 = {8B D9 81 FF FF FF FF 7F 0F [2] 00 00 00 C7 43 ?? 0F 00 00 00 83 FF 10 73 1A 57 FF 75 ?? 89 7B ?? 53 E8 [4] 83 C4 0C C6 04 1F 00 5F 5B 5D C2 08 00}
        $c2 = {FF 75 30 83 3D [4] 10 BA [4] B9 [4] 0F 43 15 [4] 83 3D [4] 10 0F 43 0D [4] E8 [4] A3}
    condition:
        uint16(0) == 0x5A4D and any of them
}
