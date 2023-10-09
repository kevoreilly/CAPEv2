rule Rhadamanthys
{
    meta:
        author = "kevoreilly"
        cape_options = "bp0=$conf-11,hc0=1,action0=setdump:edx::ebx,bp1=$conf+64,hc1=1,action1=dump,count=0,typestring=Rhadamanthys Config,ntdll-protect=0"
        packed = "9e28586ab70b1abdccfe087d81e326a0703f75e9551ced187d37c51130ad02f5"
    strings:
        $rc4 = {88 4C 01 08 41 81 F9 00 01 00 00 7C F3 89 75 08 33 FF 8B 4D 08 3B 4D 10 72 04 83 65 08 00}
        $code = {8B 4D FC 3B CF 8B C1 74 0D 83 78 04 02 74 1C 8B 40 1C 3B C7 75 F3 3B CF 8B C1 74 57 83 78 04 17 74 09 8B 40 1C 3B C7 75 F3 EB}
        $conf = {46 BB FF 00 00 00 23 F3 0F B6 44 31 08 03 F8 23 FB 0F B6 5C 39 08 88 5C 31 08 88 44 39 08 02 C3 8B 5D 08 0F B6 C0 8A 44 08 08}
    condition:
        2 of them
}
