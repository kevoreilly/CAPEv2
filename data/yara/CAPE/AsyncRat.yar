rule AsyncRat
{
    meta:
        author = "kevoreilly"
        description = "AsyncRat Payload"
        cape_type = "AsyncRat Payload"
    strings:
        $string1 = "Pastebin"
        $string2 = "Pong"
        $string3 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
