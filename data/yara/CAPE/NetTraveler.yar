rule NetTraveler
{
    meta:
        author = "kevoreilly"
        description = "NetTraveler Payload"
        cape_type = "NetTraveler Payload"
    strings:
        $string1 = "Name:\t%s\r\nType:\t%s\r\nServer:\t%s\r\n"
        $string2 = "Password Expiried Time:"
        $string3 = "Memory: Total:%dMB,Left:%dMB (for %.2f%s)"

    condition:
        uint16(0) == 0x5A4D and all of them
}
