rule MassLogger
{
    meta:
        author = "kevoreilly"
        description = "MassLogger"
        cape_type = "MassLogger Payload"
    strings:
        $name = "MassLogger"
        $fody = "Costura"
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
