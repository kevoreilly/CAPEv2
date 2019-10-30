rule MegaCortex
{
    meta:
        author = "kevoreilly"
        description = "MegaCortex Payload"
        cape_type = "MegaCortex Payload"
    strings:
        $str1 = ".megac0rtx" ascii wide
        $str2 = "vssadmin delete shadows /all" ascii
        $sha256 = {98 2F 8A 42 91 44 37 71 CF FB C0 B5 A5 DB B5 E9}
    condition:
        uint16(0) == 0x5A4D and all of them
}
