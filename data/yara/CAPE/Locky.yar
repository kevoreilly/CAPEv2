rule Locky
{
    meta:
        author = "kevoreilly"
        description = "Locky Payload"
        cape_type = "Locky Payload"
    strings:
        $string1 = "wallet.dat" wide
        $string2 = "Locky_recover" wide
        $string3 = "opt321" wide
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}

