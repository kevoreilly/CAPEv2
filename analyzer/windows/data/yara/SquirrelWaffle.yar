rule SquirrelWaffle
{
    meta:
        author = "kevoreilly"
        description = "SquirrelWaffle Config Extraction"
        cape_options = "bp0=$config-67,dumpsize=edx,action0=dump:eax,typestring1=SquirrelWaffle Config,count=1"
    strings:
        $config = {83 C2 04 83 C1 04 83 EE 04 73 EF 83 FE FC 74 34 8A 02 3A 01 75 27 83 FE FD 74 29 8A 42 01 3A 41 01 75 1A 83 FE FE 74 1C 8A 42 02 3A 41 02 75 0D}
        $decode = {F7 75 ?? 83 7D ?? 10 8D 4D ?? 8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39}
    condition:
        uint16(0) == 0x5A4D and all of them
}
