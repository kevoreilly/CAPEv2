rule Mole
{
    meta:
        author = "kevoreilly"
        description = "Mole Payload"
        cape_type = "Mole Payload"
    strings:
        $a1 = ".mole0" wide
        $a2 = "_HELP_INSTRUCTION.TXT" wide
        $a3 = "-----BEGIN PUBLIC KEY----- MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
