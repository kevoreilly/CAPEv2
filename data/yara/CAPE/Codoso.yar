rule Codoso
{
    meta:
        author = "kevoreilly"
        description = "Codoso Payload"
        cape_type = "Codoso Payload"
    strings:
        $a1 = "WHO_A_R_E_YOU?"
        $a2 = "DUDE_AM_I_SHARP-3.14159265358979"
        $a3 = "USERMODECMD"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
