rule Guloader
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass"
        cape_options = "bp0=$trap0,bp0=$trap1+4,action0=skip,bp1=$trap2+11,bp1=$trap3+19,action1=skip,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0"
    strings:
        $trap0 = {0F 85 [2] FF FF 81 BD ?? 00 00 00 [2] 00 00 0F 8F [2] FF FF 39 D2 83 FF 00}
        $trap1 = {49 83 F9 00 75 [1-20] 83 FF 00 [2-6] 81 FF}
        $trap2 = {39 CB 59 01 D7 49 85 C8 83 F9 00 75 B3}
        $trap3 = {61 0F AE E8 0F 31 0F AE E8 C1 E2 20 09 C2 29 F2 83 FA 00 7E CE C3}
        $antihook = {FF 34 08 [0-300] 8F 04 0B [0-300] 83 F9 18 [0-300] FF E3}
    condition:
        2 of them
}

rule GuloaderB
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2021 Edition"
        cape_options = "bp0=$trap0,action0=ret,bp1=$trap1,action1=ret2,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0"
    strings:
        $trap0 = {81 C6 00 10 00 00 [0-88] 81 FE 00 F0 [2] 0F 84 [2] 00 00}
        $trap1 = {31 FF [0-128] (B9|C7 85 F8 00 00 00) 60 5F A9 00}
        $antihook = {FF 34 08 [0-300] 8F 04 0B [0-300] 83 F9 18 [0-300] FF E3}
    condition:
        2 of them
}
