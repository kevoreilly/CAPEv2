rule Kpot
{
    meta:
        author = "kevoreilly"
        description = "Kpot Stealer"
        cape_type = "Kpot Payload"
    strings:
        $format   = "%s | %s | %s | %s | %s | %s | %s | %d | %s"
        $username = "username:s:"
        $os       = "OS: %S x%d"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
