rule Raccoon {
    meta:
        author = "ditekSHen"
        description = "Raccoon stealer payload"
        cape_type = "Raccoon Infostealer Payload"
    strings:
        $s1 = "inetcomm server passwords" fullword wide
        $s2 = "content-disposition: form-data; name=\"file\"; filename=\"data.zip\"" fullword ascii
        $s3 = ".?AVfilesystem_error@v1@filesystem@experimental@std@@" fullword ascii
        $s4 = "CredEnumerateW" fullword ascii
        $s5 = "%[^:]://%[^/]%[^" fullword ascii
        $s6 = "%99[^:]://%99[^/]%99[^" fullword ascii
        $s7 = "Login Data" wide
        $s8 = "m_it.object_iterator != m_object->m_value.object->end()" fullword wide
        $x1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $x2 = "\\json.hpp" wide
        $x3 = "Microsoft_WinInet_" fullword wide
        $x4 = "Microsoft_WinInet_*" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((3 of ($x*) and 2 of ($s*)) or (4 of ($s*) and 1 of ($x*)))
}

rule RaccoonV2: raccoon_stealer_v2
{
    meta:
	author = "muzi"
	date = "2022-07-22"
        description = "Detects Raccoon Stealer V2 (unpacked)"
        hash = "022432f770bf0e7c5260100fcde2ec7c49f68716751fd7d8b9e113bf06167e03"
        cape_type = "RaccoonV2 Payload"

    strings:
 
       // Simple Strings
        $s1 = "Profile %d" wide
        $s2 = "Login Data" wide
        $s3 = "0Network\\Cookies" wide
        $s4 = "Web Data" wide
        $s5 = "*.lnk" wide
        $s6 = "\\ffcookies.txt" wide
        $s7 = "	%s %s" wide
        $s8 = "wallet.dat" wide
        $s9 = "S-1-5-18" ascii wide // malware checks if running as system

        /*

                             LAB_0040878a                                    XREF[1]:     004087be(j)
        0040878a 8b c3           MOV        EAX,EBX
        0040878c 8b 0c 9f        MOV        this,dword ptr [EDI + EBX*0x4]
        0040878f 99              CDQ
        00408790 f7 7d fc        IDIV       dword ptr [EBP + local_8]
        00408793 8b 45 10        MOV        EAX,dword ptr [EBP + param_3]
        00408796 0f be 04 02     MOVSX      EAX,byte ptr [EDX + EAX*0x1]
        0040879a 03 c1           ADD        EAX,this
        0040879c 03 f0           ADD        ESI,EAX
        0040879e 81 e6 ff        AND        ESI,0x800000ff
                 00 00 80
        004087a4 79 08           JNS        LAB_004087ae
        004087a6 4e              DEC        ESI
        004087a7 81 ce 00        OR         ESI,0xffffff00
                 ff ff ff
        004087ad 46              INC        ESI
        */

        // Decryption Routine
        $decryption_routine = {
                                    8B (C0|C1|C2|C3|C5|C6|C7) [0-8]
                                    8B ?? ?? [0-8]
                                    99 [0-8]
                                    F7 7D ?? [0-8]
                                    8B (45|4D|55|5D|6D|75|7D) ?? [0-8]
                                    0F BE ?? ?? [0-8]
                                    03 (C1|C2|C3|C5|C6|C7) [0-8]
                                    03 (F0|F1|F2|F3|F5|F6|F7) [0-8]
                                    81 E6 ?? ?? ?? ?? [0-8]
                                    7? ?? [0-8]
                                    4E [0-8]
                                    81 CE ?? ?? ?? ?? [0-8]
                                    46
        }

        /*
        00408130 8b 35 14        MOV        ESI,dword ptr [DAT_0040e014]
                 e0 40 00
        00408136 57              PUSH       EDI
        00408137 50              PUSH       EAX
        00408138 ff 75 18        PUSH       dword ptr [EBP + param_7]
        0040813b ff d1           CALL       param_1
        0040813d 8b 7d d0        MOV        EDI,dword ptr [EBP + local_34]
        00408140 50              PUSH       EAX
        00408141 ff 75 18        PUSH       dword ptr [EBP + param_7]
        00408144 57              PUSH       EDI
        00408145 ff d6           CALL       ESI
        00408147 85 c0           TEST       EAX,EAX
        00408149 74 24           JZ         LAB_0040816f
        0040814b be 50 c3        MOV        ESI,0xc350
                 00 00
        00408150 eb 0b           JMP        LAB_0040815d
                             LAB_00408152                                    XREF[1]:     0040816d(j)
        00408152 8b 45 e4        MOV        EAX,dword ptr [EBP + local_20]
        00408155 85 c0           TEST       EAX,EAX
        00408157 74 16           JZ         LAB_0040816f
        00408159 c6 04 18 00     MOV        byte ptr [EAX + EBX*0x1],0x0
                             LAB_0040815d                                    XREF[1]:     00408150(j)
        0040815d a1 fc e0        MOV        EAX,[DAT_0040e0fc]
                 40 00
        00408162 8d 4d e4        LEA        param_1=>local_20,[EBP + -0x1c]
        00408165 51              PUSH       param_1
        00408166 56              PUSH       ESI
        00408167 53              PUSH       EBX
        00408168 57              PUSH       EDI
        00408169 ff d0           CALL       EAX
        0040816b 85 c0           TEST       EAX,EAX
        0040816d 75 e3           JNZ        LAB_00408152

        */

        // C2 Comms
        $c2_comms = {
                      8B 35 ?? ?? ?? ?? [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      FF 75 ?? [0-8]
                      FF (D0|D1|D2|D3|D5|D6|D7) [0-8]
                      8B (45|4D|55|5D|6D|75|7D) ?? [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      FF 75 ?? [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      FF (D0|D1|D2|D3|D5|D6|D7) [0-8]
                      85 C0 [0-8]
                      (E2|EB|72|74|75|7C) ?? [0-8]
                      (B8|B9|BA|BB|BD|BE|BF) ?? ?? ?? ?? [0-8]
                      (E2|EB|72|74|75|7C) ?? [0-8]
                      8B (45|4D|55|5D|6D|75|7D) ?? [0-8]
                      85 C0 [0-8]
                      (E2|EB|72|74|75|7C) ?? [0-8]
                      C6 ?? ?? ?? [0-8]
                      A1 ?? ?? ?? ?? [0-8]
                      8D 4D ?? [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      (50|51|52|53|55|56|57) [0-8]
                      FF ?? [0-8]
                      85 C0 [0-8]
                      (E2|EB|72|74|75|7C)
        }


    condition:
        6 of ($s*) or
        ($c2_comms and $decryption_routine)
}
