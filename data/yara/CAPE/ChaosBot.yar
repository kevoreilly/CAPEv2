rule ChaosBot 
{
    meta:
        author = "YungBinary"
        description = "https://x.com/YungBinary/status/1976580501508182269"
        cape_type = "ChaosBot Payload"
    strings: 
        $s1 = { 48 6f 73 74 20 20 63 6f 6e 6e 65 63 74 65 64 2c 20 63 68 61 6e 6e 65 6c 20 63 72 65 61 74 65 64 3a 20 3c }
        $s2 = { 73 68 65 6c 6c 20 64 6f 77 6e 6c 6f 61 64 20 63 64 20 46 61 69 6c 65 64 20 74 6f 20 63 68 61 6e 67 65 20 64 69 72 65 63 74 6f 72 79 3a }
        $s3 = { 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 41 6d 73 69 53 63 61 6e 42 75 66 66 65 72 45 74 77 45 76 65 6e 74 57 72 69 74 65 43 4f 4d 50 55 54 45 52 4e 41 4d 45 }
        $s4 = { 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6d 65 73 73 61 67 65 5f 2e 74 78 74 }
        $bypass = { 
            74 ?? 
            66 C7 03 31 C0 
            C6 43 02 C3 
        } 
        $antivm = { 
            48 ?? 30 30 3A 30 43 3A 32 39 
            49 39 ?? 00 
        } 
    condition: 
        uint16(0) == 0x5a4d and (1 of ($s*) or ($antivm and $bypass)) 

}
