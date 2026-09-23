rule Defendnot
{
    meta:
        author = "kevoreilly"
        description = "Defendnot Payload"
        cape_type = "Defendnot Payload"
        hash = "b0870e105c7ad37fb0bdcb9305279b2943810d55300e8721eb64bdaa588cc84e"
    strings:
        $string1 = "defendnot"
        $string2 = "Got HRESULT={:#x} at\n{}:{}"
        $string3 = "init: {:#x}"
        $string4 = "AV Name can not be empty!"
    condition:
        uint16(0) == 0x5a4d and all of them
}
