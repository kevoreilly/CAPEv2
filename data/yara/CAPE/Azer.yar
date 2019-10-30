rule Azer
{
    meta:
        author = "kevoreilly"
        description = "Azer Payload"
        cape_type = "Azer Payload"
    strings:
        $a1 = "webmafia@asia.com" wide
        $a2 = "INTERESTING_INFORMACION_FOR_DECRYPT.TXT" wide
        $a3 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"  //-----BEGIN PUBLIC KEY-----
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
