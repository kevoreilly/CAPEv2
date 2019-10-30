rule Sakula
{
    meta:
        description = "Sakula v1.0"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou / NCC Group David Cannings"
        cape_type = "Sakula Payload"
        
    strings:
        $s1 = "%d_of_%d_for_%s_on_%s"
        $s2 = "/c ping 127.0.0.1 & del /q \"%s\""
        $s3 = "=%s&type=%d"
        $s4 = "?photoid="
        $s5 = "iexplorer"
        $s6 = "net start \"%s\""
        $s7 = "cmd.exe /c rundll32 \"%s\""

        $v1_1 = "MicroPlayerUpdate.exe"
        $v1_2 = "CCPUpdate"
        $v1_3 = { 81 3E 78 03 00 00 75 57  8D 54 24 14 52 68 0C 05 41 00 68 01 00 00 80 FF  15 00 F0 40 00 85 C0 74 10 8B 44 24 14 68 2C 31  41 00 50 FF 15 10 F0 40 00 8B 4C 24 14 51 FF 15  24 F0 40 00 E8 0F 09 00 }
        $v1_4 = { 50 E8 CD FC FF FF 83 C4  04 68 E8 03 00 00 FF D7 56 E8 54 12 00 00 E9 AE  FE FF FF E8 13 F5 FF FF }

        $serial01 = { 31 06 2e 48 3e 01 06 b1 8c 98 2f 00 53 18 5c 36 } 
        $serial02 = { 01 a5 d9 59 95 19 b1 ba fc fa d0 e8 0b 6d 67 35 }
        $serial03 = { 47 d5 d5 37 2b cb 15 62 b4 c9 f4 c2 bd f1 35 87 }
        $serial04 = { 3a c1 0e 68 f1 ce 51 9e 84 dd cd 28 b1 1f a5 42 }
        
        $opcodes1 = { 89 FF 55 89 E5 83 EC 20 A1 ?? ?? ?? 00 83 F8 00 }
        $opcodes2 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }
        $opcodes3 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }
        $opcodes4 = { 30 14 38 8D 0C 38 40 FE C2 3B C6 }
        $opcodes5 = { 30 14 39 8D 04 39 41 FE C2 3B CE }
         
        $MZ = "MZ"
    condition:
        ($MZ at 0 and (3 of ($s*) and any of ($v1_*))) or (any of ($serial0*)) or (any of ($opcodes*))
}
