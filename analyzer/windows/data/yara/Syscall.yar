rule Syscall
{
    meta:
        author = "kevoreilly"
        description = "x64 syscall instruction (direct)"
        cape_options = "clear,dump,sysbp=$syscall+8"
    strings:
        $syscall = {4C 8B D1 B8 [2] 00 00 0F 05 C3}
    condition:
        all of them
}
