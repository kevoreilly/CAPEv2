rule CargoBayLoader
{
    meta:
        author = "kevoreilly"
        description = "CargoBayLoader anti-vm bypass"
        cape_options = "bp0=$jmp1+4,action0=skip,bp1=$jmp2+2,action1=skip,count=1,force-sleepskip=1"
        hash = "75e975031371741498c5ba310882258c23b39310bd258239277708382bdbee9c"
    strings:
        $jmp1 = {40 42 0F 00 0F 82 [2] 00 00 48 8D 15 [4] BF 04 00 00 00 41 B8 04 00 00 00 4C 8D [3] 4C 89 F1 E8}
        $jmp2 = {84 DB 0F 85 [2] 00 00 48 8D 15 [4] 41 BE 03 00 00 00 41 B8 03 00 00 00 4C 8D 7C [2] 4C 89 F9 E8}
    condition:
        uint16(0) == 0x5A4D and all of them
}
