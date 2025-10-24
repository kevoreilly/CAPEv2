rule WinosStager 
{
    meta:
        author = "YungBinary"
        description = "https://www.esentire.com/blog/winos4-0-online-module-staging-component-used-in-cleversoar-campaign"
        cape_type = "WinosStager Payload"
    strings: 
        $s1 = "Windows\\SysWOW64\\tracerpt.exe" ascii fullword
        $s2 = "Windows\\System32\\tracerpt.exe" ascii fullword
        $s3 = { 70 00 31 00 3A 00 00 00 }
        $s4 = { 6F 00 31 00 3A 00 00 00 }
        $s5 = { 70 00 32 00 3A 00 00 00 }
        $s6 = { 6F 00 32 00 3A 00 00 00 }
        $s7 = { 70 00 33 00 3A 00 00 00 }
        $s8 = { 6F 00 33 00 3A 00 00 00 }
        $s9 = "IpDates_info" wide fullword
        $s10 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" wide fullword
        $s11 = "Console\\0" wide fullword
        $s12 = "d33f351a4aeea5e608853d1a56661059" wide fullword

        $config_parse = {
            (3B CE | 7D ??)                                  // cmp ecx, esi or jge short loc_??????
            (7D ?? | 0F 1F ?? 00)                            // jge short loc_?????? or nop dword ptr [??+00h]
            (66 83 3C 4D ?? ?? ?? ?? 7C | 66 41 83 ?? ?? 7C) // cmp ??, 7Ch ; '|'
            74 ??                                            // jz short loc_??????
            (41 | 48 FF C1)                                  // inc ecx or inc rcx
            (3B CE | FF C2)                                  // cmp ecx, esi or inc edx
            (7C ?? | 49 3B CB 7C ??)                         // jl loc_?????? | cmp rcx, r11, jl short loc_??????
        }
        $zero_config = {
            FF [1-5]                    // call
            83 (7C|7D) [1-2] 0A         // cmp [ebp+??], 0Ah
            0F 86 ?? ?? ?? ??           // jbe loc_??????
            (68 D0 07 00 00 | 33 D2)    // push 7D0h or xor edx,edx
            (6A 00 | 41 B8 D0 07 00 00) // push 0 or mov r8d, 0x7D0
            (68 ?? ?? ?? ?? | 48 8B CD) // push offset wszConfig or mov rcx, rbp
            E8                          // call
        }
    condition: 
        uint16(0) == 0x5a4d and ((3 of ($s*)) or ($config_parse or $zero_config))
}
