rule TAIDOOR
{
   meta:
       author = "CISA Code & Media Analysis"
       description = "TAIDOOR loader payload"
       cape_type = "TAIDOOR payload"
   strings:
       $s0 = { 8A 46 01 88 86 00 01 00 00 8A 46 03 88 86 01 01 00 00 8A 46 05 88 86 02 01 00 00 8A 46 07 88 86 03 01 00 00 }
       $s1 = { 88 04 30 40 3D 00 01 00 00 7C F5 }
       $s2 = { 0F BE 04 31 0F BE 4C 31 01 2B C3 2B CB C1 E0 04 0B C1 }
       $s3 = { 8A 43 01 48 8B 6C 24 60 88 83 00 01 00 00 8A 43 03 }
       $s4 = { 88 83 01 01 00 00 8A 43 05 88 83 02 01 00 00 8A 43 07 88 83 03 01 00 00 }
       $s5 = { 41 0F BE 14 7C 83 C2 80 41 0F BE 44 7C 01 83 C0 80 C1 E2 04 0B D0 }
       $s6 = { 5A 05 B2 CB E7 45 9D C2 1D 60 F0 4C 04 01 43 85 3B F9 8B 7E }
   condition:
       uint16(0) == 0x5a4d and (($s0 and $s1 and $s2) or ($s3 and $s4 and $s5) or ($s6))
}
