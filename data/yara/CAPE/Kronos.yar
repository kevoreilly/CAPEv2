rule Kronos
{
    meta:
        author = "kevoreilly"
        description = "Kronos Payload"
        cape_type = "Kronos Payload"
    strings:
        $a1 = "user_pref(\"network.cookie.cookieBehavior\""
        $a2 = "T0E0H4U0X3A3D4D8"
        $a3 = "wow64cpu.dll" wide
        $a4 = "Kronos" fullword ascii wide
    condition:
        uint16(0) == 0x5A4D and (any of ($a*))
}
