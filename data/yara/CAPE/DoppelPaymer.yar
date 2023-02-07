rule DoppelPaymer
{
    meta:
        author = "kevoreilly"
        description = "DoppelPaymer Payload"
        cape_type = "DoppelPaymer Payload"

    strings:
        $getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
        $cmd_string = "Setup run\\n" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
