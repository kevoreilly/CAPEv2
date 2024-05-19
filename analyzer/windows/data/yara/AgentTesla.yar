rule AgentTeslaV4JIT
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla V4 JIT native config extractor"
        cape_options = "bp0=$decode1+8,count=0,action0=string:ecx,typestring=AgentTesla Strings,no-logs=2"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode1 = {8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
        $decode2 = {83 F8 18 75 2? 8B [2-5] D1 F8}
        $decode3 = {8D 4C 0? 08 0F B6 01 [0-3] 0F B6 5? 04 33 C2 88 01 B8 19 00 00 00}
    condition:
        2 of them
}

rule AgentTeslaV3JIT
{
    meta:
        author = "ClaudioWayne"
        description = "AgentTesla V3 JIT native string decryption"
        cape_options = "bp0=$decode+20,count=0,action0=string:eax+8,typestring=AgentTesla Strings,no-logs=2"
    strings:
        $decode = {8B C8 57 FF 75 08 8B [5] 8B 01 8B 40 3C FF [2] 8B F0 B8 03 00 00 00}
    condition:
        all of them
}
