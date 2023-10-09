rule GuloaderB
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2021 Edition"
        cape_options = "bp0=$trap0,action0=ret,bp1=$trap1,action1=ret:2,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0,bp3=$trap2+7,action3=skip"
        packed = "9ec05fd611c2df63c12cc15df8e87e411f358b7a6747a44d4a320c01e3367ca8"
    strings:
        $trap0 = {81 C6 00 10 00 00 [0-88] 81 FE 00 F0 [2] 0F 84 [2] 00 00}
        $trap1 = {31 FF [0-128] (B9|C7 85 F8 00 00 00) 60 5F A9 00}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-360] 83 F9 18 [0-460] FF E3}
        $trap2 = {83 BD 9C 00 00 00 00 0F 85 [2] 00 00}
    condition:
        3 of them
}

rule GuloaderPrecursor
{
    meta:
        author = "kevoreilly"
        description = "Guloader precursor"
        cape_options = "bp0=$antidbg,action0=scan,hc0=1,count=0"
    strings:
        $antidbg = {39 48 04 (0F 85 [3] ??|75 ??) 39 48 08 (0F 85 [3] ??|75 ??) 39 48 0C (0F 85 [3] ??|75 ??)}
        $except = {8B 45 08 [0-3] 8B 00 [0-3] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}
    condition:
        2 of them and not uint16(0) == 0x5A4D
}

rule GuloaderC
{
    meta:
        author = "kevoreilly"
        description = "Guloader bypass 2023 Edition"
        cape_options = "clear,bp0=$trap0,bp0=$trap0A,hc0=0,action0=ret,bp1=$trap1,action1=ret:4,bp2=$antihook,action2=goto:ntdll::NtAllocateVirtualMemory,count=0"
        packed = "d0c1e946f02503a290d24637b5c522145f58372a9ded9e647d24cd904552d235"
        packed = "26760a2ef432470c7fd2d570746b7decdcf34414045906871f33d80ff4dfc6ba"
    strings:
        $antidbg = {39 48 04 0F 85 [4] 39 48 08 0F 85 [4] 39 48 0C 0F 85 [4] 39 48 10 0F 85 [4] 39 48 14 0F 85 [4] 39 48 18 0F 85}
        $except = {8B 45 08 [0-3] 8B 00 [0-3] 8B 58 18 [0-20] 81 38 05 00 00 C0 0F 85 [4-7] 83 FB 00 (0F 84|74)}
        $trap0 = {81 C6 00 10 00 00 [0-148] (39 CE|3B B5) [0-6] 0F 84 [2] 00 00}
        $trap0A = {E8 00 00 00 00 59 [0-2800] 81 C6 00 10 00 00 [0-148] (39 CE|3B B5) [0-6] 0F 84 [2] 00 00}
        $trap1 = {89 D6 60 0F 31 B8 [4] (05|35|2D|B8) [4] (05|35|2D|B8) [4] (05|35|2D|B8) [4] 0F A2}
        $antihook = {FF 34 08 [0-360] 8F 04 0B [0-800] FF E3}
    condition:
        3 of them
}
