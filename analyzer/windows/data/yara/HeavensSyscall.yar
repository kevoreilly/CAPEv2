rule HeavensSyscall
{
    meta:
        author = "kevoreilly"
        description = "Bypass variants of heaven's gate direct syscalls"
        cape_options = "clear,br0=$gate1-9,action1=seteax:0,count=0,sysbp=$sysenter+10"
        packed = "2950b4131886e06bdb83ab1611b71273df23b0d31a4d8eb6baddd33327d87ffa"
    strings:
        $gate1 = {00 00 00 00 74 24 8D 45 F8 50 6A FF FF 95 [4] 85 C0 74 08 8B 4D F8 89 4D FC EB 07 C7 45 FC 00 00 00 00 8B 45 FC EB 02 33 C0 8B E5 5D C2 C0}
        $sysenter = {68 [4] E8 [4] E8 [4] C2 ?? 00 CC CC CC CC CC CC CC CC}
    condition:
        uint16(0) == 0x8B55 and all of them
}
