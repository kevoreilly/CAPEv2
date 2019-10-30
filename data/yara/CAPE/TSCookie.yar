rule TSCookie
{
    meta:
        author = "kevoreilly"
        description = "TSCookie Payload"
        cape_type = "TSCookie Payload"
    strings:
        $string1 = "http://%s:%d" wide
        $string2 = "/Default.aspx" wide
        $string3 = "\\wship6"
    condition:
        uint16(0) == 0x5A4D and all of them
}
