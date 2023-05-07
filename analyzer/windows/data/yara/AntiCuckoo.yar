rule AntiCuckoo
{
    meta:
        author = "kevoreilly"
        description = "AntiCuckoo bypass: https://github.com/therealdreg/anticuckoo"
        cape_options = "bp0=$HKActivOldStackCrash+36,action0=jmp,count=1"
        hash = "ad5e52f144bb4a1dae3090978c6ecb4c7732538c9b62a6cedd32eccee6094be5"
    strings:
        $HKActivOldStackCrash = {5B 81 FB FA FA FA FA 74 01 41 3B E0 75 ?? 83 E9 0B 83 F9 04 7F 04 C6 45 ?? 00 89 4D ?? 89 65 ?? 80 7D ?? 00 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}
