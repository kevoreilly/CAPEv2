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

rule RhadaAnti
{
    meta:
        author = "kevoreilly"
        cape_options = "bp0=$anti,action0=jmp,count=0,ntdll-protect=0,dump-limit=0"
    strings:
        $anti = {74 0E FF 75 ?? 8D 45 ?? 50 E8 [4] 59 59 8D 45 ?? 50 56 68 04 01 00 00}
    condition:
        all of them
}

rule RhadUnhook
{
    meta:
        cape_options = "bp0=$scan*,action0=scan:rbx,count=0,patch=$target+21:9090"
        packed = "dd4af0f1888977f6d9eb820b19f4afc2a73d1c494a132ab4261498328005dda7"
    strings:
        $scan = {48 85 DB 0F 84 E1 00 00 00 4C 8D 44 24 70 48 8D 54 24 40 48 8B CE 44 89 7C 24 50 4C 89 64 24 40 48 C7 44 24 48 00 00 00 00 C6 44 24 54 00 FF}
        $target = {4D 85 C9 48 8B C6 4A 8D 0C 1E 74 15 48 2B D8 49 2B DB 8A 04 0B 88 01 48 83 C1 01 49 83 E9 01 75 F1 5F 5E 5D 5B C3}
    condition:
        any of them
}
