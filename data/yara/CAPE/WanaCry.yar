rule WanaCry
{
    meta:
        author = "kevoreilly"
        description = "WanaCry Payload"
        cape_type = "WanaCry Payload"
    strings:
        $exename    = "@WanaDecryptor@.exe"
        $res        = "%08X.res"
        $pky        = "%08X.pky"
        $eky        = "%08X.eky"
        $taskstart  = {8B 35 58 71 00 10 53 68 C0 D8 00 10 68 F0 DC 00 10 FF D6 83 C4 0C 53 68 B4 D8 00 10 68 24 DD 00 10 FF D6 83 C4 0C 53 68 A8 D8 00 10 68 58 DD 00 10 FF D6 53}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}

