rule Clop
{
    meta:
        author = "kevoreilly"
        cape_type = "Clop Payload"
    strings:
        $string1 = "%s%s.Cl0p" wide
        $string2 = "%s\\Cl0pReadMe.txt" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
