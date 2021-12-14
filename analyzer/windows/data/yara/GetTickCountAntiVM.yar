rule GetTickCountAntiVM
{
    meta:
        author = "kevoreilly"
        description = "GetTickCountAntiVM bypass"
        cape_options = "bp0=$antivm1-13,action0=wret,hc0=1,bp1=$antivm2-6,action1=wret,hc1=1,count=1"
    strings:
        $antivm1 = {57 FF D6 FF D6 BF 01 00 00 00 FF D6 F2 0F 10 0D [4] 47 66 0F 6E C7 F3 0F E6 C0 66 0F 2F C8 73}
        $antivm2 = {F2 0F 11 45 ?? FF 15 [4] 6A 00 68 10 27 00 00 52 50 E8 [4] 8B C8 E8 [4] F2 0F 59 45}
    condition:
        any of them
}
