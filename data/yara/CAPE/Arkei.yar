rule Arkei
{
    meta:
        author = "kevoreilly"
        description = "Arkei Payload"
        cape_type = "Arkei Payload"
    strings:
        $string1 = "Windows_Antimalware_Host_System_Worker"
        $string2 = "Arkei"
        $string3 = "Bitcoin\\wallet.dat"
        $string4 = "Ethereum\\keystore"
    condition:
        uint16(0) == 0x5A4D and all of them
}
