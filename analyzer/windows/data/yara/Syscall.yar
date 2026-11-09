rule Syscall
{
    meta:
        author = "kevoreilly"
        description = "x64 syscall instruction (direct)"
        cape_options = "clear,dump,sysbp=$syscall0+8,sysbp=$syscallA+10,sysbp=$syscallB+7,sysbp=$syscallC+18"
    strings:
        $syscall0 = {4C 8B D1 B8 [2] 00 00 (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov r10, rcx; mov eax, X; syscall; ret
        $syscallA = {4C 8B D1 66 8B 05 [4] (0F 05|FF 25 ?? ?? ?? ??) C3}    // mov r10, rcx; mov ax, [p]; syscall; ret
        $syscallB = {4C 8B D1 66 B8 [2] (0F 05|FF 25 ?? ?? ?? ??) C3}       // mov r10, rcx; mov ax, X; syscall; ret
        $syscallC = {4C 8B D1 B8 [2] 00 00 [10] 0F 05 C3}                   // mov r10, rcx; mov eax, X; [padding]; syscall; ret
    condition:
        any of them
}

rule Syscall_Golang
{
    meta:
        author = "kevoreilly, doomedraven"
        description = "x64 Go direct-syscall assembly stubs"
        cape_options = "sysbpmode=1,sysbp=$stub*-1"
    strings:
        $pclntab = {(F0|F1|FA|FB) FF FF FF 00 00 (01|02|04) 08 [3] 00}
        $stub = {(49 89 CA|4C 8B D1) [0-24] 0F 05}                           // mov r10, rcx; [mov eax, SSN]; syscall (Go / BananaPhone)
    condition:
        $pclntab and $stub
}
