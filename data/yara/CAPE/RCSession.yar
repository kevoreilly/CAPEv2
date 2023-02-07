rule RCSession
{
    meta:
        author = "kevoreilly"
        description = "RCSession Payload"
        cape_type = "RCSession Payload"
    strings:
        $a1 = {56 33 F6 39 74 24 08 7E 4C 53 57 8B F8 2B FA 8B C6 25 03 00 00 80 79 05 48 83 C8 FC 40 83 E8 00 74 19 48 74 0F 48 74 05 6B C9 09 EB 15 8B C1 C1 E8 02 EB 03 8D 04 09 2B C8}
        $a2 = {83 C4 10 85 C0 74 ?? BE ?? ?? ?? ?? 89 74 24 10 E8 ?? ?? ?? ?? 6A 03 68 48 0B 00 00 56 53 57 68 02 00 00 80 E8 ?? ?? ?? ?? 83 C4 18 85 C0 74 18 E8 ?? ?? ?? ?? 6A 03 68 48}
    condition:
        (any of ($a*))
}
