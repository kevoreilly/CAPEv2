rule AgentTeslaV4JIT
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla V4 JIT native config extractor"
        cape_options = "bp0=$decode+22,count=0,hc0=30,action0=string:ecx,typestring=AgentTesla Config,no-logs=2"
        packed = "7f8a95173e17256698324886bb138b7936b9e8c5b9ab8fffbfe01080f02f286c"
    strings:
        $decode = {83 F8 19 75 20 E8 [4] 8B C8 8B D3 8B 01 8B 40 3C FF 50 10 8B C8 E8 [4] 89 45 CC B8 1A 00 00 00}
    condition:
        all of them
}
