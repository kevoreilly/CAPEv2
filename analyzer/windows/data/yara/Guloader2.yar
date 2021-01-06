rule Guloader2
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2021 Edition"
        cape_options = "bp0=$trap0+12,action0=ret,bp1=$trap1,action1=ret3,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,"
    strings:
        $trap0 = {81 C6 00 10 00 00 81 FE 00 F0 FF 7F 0F 84 [2] 00 00}
        $trap1 = {60 0F 31 B8 01 00 00 00 0F A2 61}
        $antihook = {FF 34 08 [0-48] 8F 04 0B [0-80] 83 C1 04 83 F9 18 75 [0-128] FF E3}
    condition:
        2 of them
}
