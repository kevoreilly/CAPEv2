rule IcedID
{
    meta:
        author = "kevoreilly"
        description = "IcedID hook fix"
        cape_options = "ntdll-protect=0"
    strings:
        $hook = {C6 06 E9 83 E8 05 89 46 01 8D 45 ?? 50 FF 75 ?? 6A 05 56 6A FF E8 2D FA FF FF}
    condition:
        any of them
}

rule IcedIDPackerA
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "fbad60002286599ca06d0ecb3624740efbf13ee5fda545341b3e0bf4d5348cfe"
    strings:
        $init = "init"
        $export = {48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 81 EC [2] 00 00 41 8B E9 49 8B F0 48 8B FA 48 8B D9}
        $alloc = {8B 50 50 33 C9 44 8D 49 40 41 B8 00 30 00 00 FF 15 [4] 48 89 44 24 28 [0-3] 48 89 84 24 ?? 00 00 00 E9}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerB
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "6517ef2c579002ec62ddeb01a3175917c75d79ceca355c415a4462922c715cb6"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 4C 24 08 41 55 41 56 41 57 48 81 EC ?? 00 00 00 B9 [2] 00 00 4C 8B EA E8}
        $loop = {8B C2 48 8D 49 01 83 E0 07 FF C2 0F B6 44 30 ?? 30 41 FF 3B D5 72}
        //$load = {41 FF D7 33 D2 41 B8 00 80 00 00 49 8B CF FF 54}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerC
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "c06805b6efd482c1a671ec60c1469e47772c8937ec0496f74e987276fa9020a5"
        hash = "265c1857ac7c20432f36e3967511f1be0b84b1c52e4867889e367c0b5828a844"
    strings:
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 3A ED 74}
        $alloc = {41 B8 00 10 00 00 8B D0 33 C9 66 3B ?? (74|0F 84)}
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule IcedIDPackerD
{
    meta:
        author = "kevoreilly"
        description = "IcedID export selection"
        cape_options = "export=$export"
        hash = "7b226f8cc05fa7d846c52eb0ec386ab37f9bae04372372509daa6bacc9f885d8"
    strings:
        $init = "init"
        $export = {44 89 4C 24 20 4C 89 44 24 18 48 89 54 24 10 66 3B ED 74}
        $load = {41 B8 00 80 00 00 33 D2 48 8B 4C [2] EB ?? B9 69 04 00 00 E8 [4] 48 89 84 [2] 00 00 00 66 3B ED 74}
    condition:
        uint16(0) == 0x5A4D and all of them
}
