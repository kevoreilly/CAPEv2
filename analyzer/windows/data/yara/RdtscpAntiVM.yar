rule RdtscpAntiVM
{
    meta:
        author = "kevoreilly"
        description = "RdtscpAntiVM bypass"
        cape_options = "nop-rdtscp=1"
    strings:
        $antivm = {46 0F 01 F9 [0-4] 66 0F 6E C6 F3 0F E6 C0 66 0F 2F ?? 73}
    condition:
        any of them
}
