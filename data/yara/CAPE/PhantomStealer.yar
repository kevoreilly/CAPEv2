rule PhantomStealer
{
    meta:
        author = "kevoreilly"
        description = "PhantomStealer Payload"
        cape_type = "PhantomStealer Payload"
    strings:
        $a1 = "PhantomStealer"
        $a2 = "FormatCreditCards"
        $a3 = "Telegram"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
