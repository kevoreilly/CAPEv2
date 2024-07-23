rule BruteRatelSyscall
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Syscall Bypass"
        cape_options = "sysbp=$syscall1+6,sysbp=$syscall2+8"
    strings:
        $syscall1 = {49 89 CA 4? 89 ?? (41 FF|FF)}
        $syscall2 = {49 89 CA 48 8B 44 24 ?? FF 64 24}
    condition:
        all of them
}

rule BruteRatelPacker
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Outer Encryption Layer"
        cape_options = "bp1=$outer*,action1=scan,count=0"
    strings:
        $outer = {83 45 F8 01 81 7D F8 FF 00 00 00 7E ?? 83 45 FC 01 8B 45 FC 3B 45 ?? 7E ?? 48}
        $inner = {88 E3 32 1C 0E 88 5C 15 00 48 8D 49 01 48 8D 52 01 38 C1 76 ?? 48 01 CE EB ?? FF}
        $date = {48 8B 17 48 85 D2 0F 85 [2] 00 00 8B 47 08 85 C0 0F 85 [2] 00 00}
    condition:
        ($outer) and not ($inner) and not ($date)
}

rule BruteRatelDate
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Date Check Bypass"
        cape_options = "clear,bp1=$inner*,action1=scan,bp2=$date+6,action2=skip,count=0"
    strings:
        $inner = {88 E3 32 1C 0E 88 5C 15 00 48 8D 49 01 48 8D 52 01 38 C1 76 ?? 48 01 CE EB ?? FF}
        $date = {48 8B 17 48 85 D2 0F 85 [2] 00 00 8B 47 08 85 C0 0F 85 [2] 00 00}
    condition:
        any of them
}

rule BruteRatelConfig
{
    meta:
        author = "kevoreilly"
        description = "BruteRatel Config Extraction"
        cape_options = "clear,br1=$decode,count=0,action0=string:eax,typestring=BruteRatel Config"
    strings:
        $decode = {55 57 56 53 48 83 EC ?? 31 C0 48 89 CB 48 89 D7 44 89 C6 44 89 CD 44 39 01 77 ?? 41 8D 48 01 E8 [4] 31 C9}
    condition:
        all of them
}
