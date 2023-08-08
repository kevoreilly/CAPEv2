rule Syscall
{
    meta:
        author = "kevoreilly"
        description = "x64 syscall instruction (direct)"
        cape_options = "clear,dump,sysbp=$syscall0+8,sysbp=$syscallA+10,sysbp=$syscallB+7,sysbp=$syscallC+18"
    strings:
        $syscall0 = {4C 8B D1 B8 [2] 00 00 (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov eax, X
        $syscallA = {4C 8B D1 66 8B 05 [4] (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov ax, [p]
        $syscallB = {4C 8B D1 66 B8 [2] (0F 05|FF 25 ?? ?? ?? ??) C3}       // mov ax, X
        $syscallC = {4C 8B D1 B8 [2] 00 00 [10] 0F 05 C3}
    condition:
        any of them
}
