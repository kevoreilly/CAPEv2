rule PrivateLoader
{
    meta:
        author = "kevoreilly"
        description = "PrivateLoader"
        cape_options = "bp0=$jmp1+4,action0=skip,bp1=$jmp2+2,action1=skip,count=1,force-sleepskip=1"
        hash = ""
    strings:
        $code = {0F 28 85 [2] FF FF 0F 29 85 [2] FF FF 0F 28 85 [2] FF FF 0F 29 85 [2] FF FF 0F 28 85 [2] FF FF 66 0F EF 85 [2] FF FF 0F 29 85 [2] FF FF 0F 28 85 [2] FF FF 0F 29 85 [2] FF FF 8D 95 [2] FF FF 52}
    condition:
        uint16(0) == 0x5A4D and all of them
}
