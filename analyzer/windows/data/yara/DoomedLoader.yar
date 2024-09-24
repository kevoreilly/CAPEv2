rule DoomedLoader
{
    meta:
        author = "kevoreilly"
        cape_options = "clear,bp0=$anti*-4,action0=setzeroflag,sysbp=$syscall+7,count=0,procdump=2"
        packed = "914b1b3180e7ec1980d0bafe6fa36daade752bb26aec572399d2f59436eaa635"
    strings:
        $anti = {48 8B 4C 24 ?? E8 [4] 84 C0 B8 [4] 41 0F 45 C6 EB}
        $syscall = {49 89 CA 8B 44 24 08 FF 64 24 10}
    condition:
        uint16(0) == 0x5A4D and all of them
}
