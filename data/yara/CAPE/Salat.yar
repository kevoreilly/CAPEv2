rule Salat
{
    meta:
        author = "kevoreilly"
        description = "Salat Payload"
        cape_type = "Salat Payload"
    strings:
        $a1 = "salat"
        $a2 = "screenshot"
        $a3 = "task.go"
        $a4 = "tsc.go"
    condition:
        uint16(0) == 0x5A4D and all of them
}
