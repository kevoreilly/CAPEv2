rule NetTraveler
{
    meta:
        author = "kevoreilly"
        description = "NetTraveler Payload"
        cape_type = "NetTraveler Payload"
    strings:
        $string1 = {4E 61 6D 65 3A 09 25 73 0D 0A 54 79 70 65 3A 09 25 73 0D 0A 53 65 72 76 65 72 3A 09 25 73 0D 0A} // "Name: %s  Type: %s  Server: %s "
        $string2 = "Password Expiried Time:"
        $string3 = "Memory: Total:%dMB,Left:%dMB (for %.2f%s)"
        
    condition:
        uint16(0) == 0x5A4D and all of them
}
