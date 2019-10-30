rule Shade
{
    meta:
        author = "kevoreilly"
        description = "Shade Payload"
        cape_type = "Shade Payload"
    strings:
        $crypto = {C1 E1 18 [5-8] 80 80 80 80 [1-6] EE C1 ED 07 [0-5] 81 E7 FE FE FE FE [2-6] 1B 1B 1B 1B}
        $openssl = "openssl" nocase
    condition:
        uint16(0) == 0x5A4D and all of ($*)
}
