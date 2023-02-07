rule TrickBot
{
    meta:
        author = "sysopfb & kevoreilly"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $str1 = "<moduleconfig>*</moduleconfig>" ascii wide
        $str2 = "group_tag" ascii wide
        $str3 = "client_id" ascii wide
        $code1 = {8A 11 88 54 35 F8 46 41 4F 89 4D F0 83 FE 04 0F 85 7E 00 00 00 8A 1D ?? ?? ?? ?? 33 F6 8D 49 00 33 C9 84 DB 74 1F 8A 54 35 F8 8A C3 8D 64 24 00}
        $code2 = {8B 4D FC 8A D1 02 D2 8A C5 C0 F8 04 02 D2 24 03 02 C2 88 45 08 8A 45 FE 8A D0 C0 FA 02 8A CD C0 E1 04 80 E2 0F 32 D1 8B 4D F8 C0 E0 06 02 45 FF 88 55 09 66 8B 55 08 66 89 11 88 41 02}
        $code3 = {0F B6 54 24 49 0F B6 44 24 48 48 83 C6 03 C0 E0 02 0F B6 CA C0 E2 04 C0 F9 04 33 DB 80 E1 03 02 C8 88 4C 24 40 0F B6 4C 24 4A 0F B6 C1 C0 E1 06 02 4C 24 4B C0 F8 02 88 4C 24 42 24 0F}
        $code4 = {53 8B 5C 24 18 55 8B 6C 24 10 56 8B 74 24 18 8D 9B 00 00 00 00 8B C1 33 D2 F7 F3 41 8A 04 2A 30 44 31 FF 3B CF 75 EE 5E 5D 5B 5F C3}
        $code5 = {50 0F 31 C7 44 24 04 01 00 00 00 8D 0C C5 00 00 00 00 F7 C1 F8 07 00 00 74 1B 48 C1 E2 20 48 8B C8 48 0B CA 0F B6 C9 C1 E1 03 F7 D9 C1 64 24 04 10 FF C1 75 F7 59 C3}
        $code6 = {53 8B 5C 24 0C 56 8B 74 24 14 B8 ?? ?? ?? ?? F7 E9 C1 FA 02 8B C2 C1 E8 1F 03 C2 6B C0 16 8B D1 2B D0 8A 04 1A 30 04 31 41 3B CF 75 DD 5E 5B 5F C3}
        $code7 = {B8 ?? ?? 00 00 85 C9 74 32 BE ?? ?? ?? ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 03 F2 8B 2B 83 C3 04 33 2F 83 C7 04 89 29 83 C1 04 3B DE 0F 43 DA}
    condition:
        all of ($str*) or any of ($code*)
}

rule Trickbot_PermaDll_UEFI_Module
{
    meta:
        author = "@VK_Intel | Advanced Intelligence"
        description = "Detects TrickBot Banking module permaDll"
        md5 = "491115422a6b94dc952982e6914adc39"
    strings:
        $module_cfg = "moduleconfig"
        $str_imp_01 = "Start"
        $str_imp_02 = "Control"
        $str_imp_03 = "FreeBuffer"
        $str_imp_04 = "Release"
        $module = "user_platform_check.dll"
        $intro_routine = { 83 ec 40 8b ?? ?? ?? 53 8b ?? ?? ?? 55 33 ed a3 ?? ?? ?? ?? 8b ?? ?? ?? 56 57 89 ?? ?? ?? a3 ?? ?? ?? ?? 39 ?? ?? ?? ?? ?? 75 ?? 8d ?? ?? ?? 89 ?? ?? ?? 50 6a 40 8d ?? ?? ?? ?? ?? 55 e8 ?? ?? ?? ?? 85 c0 78 ?? 8b ?? ?? ?? 85 ff 74 ?? 47 57 e8 ?? ?? ?? ?? 8b f0 59 85 f6 74 ?? 57 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c eb ??}
    condition:
        6 of them
}
