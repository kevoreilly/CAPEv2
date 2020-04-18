rule Bokbot
{
    meta:
        author = "@r0ny_123"
        description = "Bokbot loader (unpacked)"
        cape_type = "Bokbot"

    strings:
        $s1 = { 8b 56 04 8d ?? ?4 0c 8b 0e 55 50 e8 ?? ?? ?? ?? 8b 6e 0c 59 85 ed 74 ?? 57 8b 7e 
			10 8b c3 8b 76 08 2b f7 fe c3 0f b6 db 8a 4c ?? ?? 0f b6 d1 02 c2 0f b6 c0 89 44 ?? ?? 
			8a 44 04 14 88 44 ?? ?? 8b 44 ?? ?? 88 4c 04 14 8a 44 ?? ?? 02 c2 0f b6 c0 8a 44 04 14 
			32 04 3e 88 07 47 8b 44 ?? ?? 83 ed 01 75 ?? 5f 33 c0 40 5d eb ??  }

        $s2 = { 51 51 53 55 56 8b ea 89 4c ?? ?? 33 d2 57 8b 7c ?? ?? 8b c2 88 04 38 40 3d 00 01 
			00 00 72 ?? 8a ca 8b da 8b 44 ?? ?? 0f b6 f2 8a 14 3b 8a 04 06 02 c2 02 c8 88 4c ?? ?? 
			0f b6 c9 8a 04 39 88 04 3b 8d 46 01 88 14 39 33 d2 8a 4c ?? ?? f7 f5 43 81 fb 00 01 00 
			00 72 ?? 5f 5e 5d 5b 59 59 c3  }
    condition:
        all of them
}
