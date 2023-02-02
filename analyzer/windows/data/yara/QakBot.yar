rule QakBot
{
    meta:
        author = "kevoreilly"
        description = "QakBot Config Extraction"
        cape_options = "bp0=$params+23,action0=setdump:eax::ecx,bp1=$c2list1+40,bp1=$c2list2+38,action1=dump,bp2=$conf+13,action2=dump,bp3=$c2list1-5,bp3=$c2list2-5,count=1,typestring=QakBot"
    strings:
        $params = {8B 7D ?? 8B F1 57 89 55 ?? E8 [4] 8D 9E [2] 00 00 89 03 59 85 C0 75 08 6A FC 58 E9}
        $c2list1 = {59 59 8D 4D D8 89 45 E0 E8 [4] 8B 45 E0 85 C0 74 ?? 8B 90 [2] 00 00 51 8B 88 [2] 00 00 6A 00 E8}
        $c2list2 = {59 59 8B F8 8D 4D ?? 89 7D ?? E8 [4] 85 FF 74 52 8B 97 [2] 00 00 51 8B 8F [2] 00 00 53 E8}
        $conf = {5F 5E 5B C9 C3 51 6A 00 E8 [4] 59 59 85 C0 75 01 C3}
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule QakBotLoader
{
    meta:
        author = "kevoreilly"
        description = "QakBot Export Selection"
        cape_options = "export=$export1-307,export=$export2-105"
    strings:
        $export1 = {66 3B E4 74 34 F7 F6 0F B6 44 15 ?? 33 C8 EB ?? BB D2 04 00 00 53 E8 [4] 66 3B FF 74 ?? 0F B6 4C 05 ?? 8B 45 ?? 33 D2 3A D2 74}
        $export2 = {66 3B F6 74 0B FF 75 ?? BB 00 00 00 00 53 EB ?? BB D2 04 00 00 53 E8 [4] 3A FF 74 ?? 0F B6 4C 05 ?? 8B 45 ?? 33 D2 66 3B D2 74}
    condition:
        uint16(0) == 0x5A4D and any of them
}
