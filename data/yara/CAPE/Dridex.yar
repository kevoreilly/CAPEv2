rule Dridex
{
    meta:
        author = "kev"
        description = "Dridex encrypt/decrypt function"
        cape_type = "Dridex Payload"

    strings:
        $crypt_32_v1 = {57 53 55 81 EC 0C 02 00 00 8B BC 24 1C 02 00 00 85 FF 74 20 8B AC 24 20 02 00 00 85 ED 74 15 83 BC 24 24 02 00 00 00 74 0B 8B 9C 24 28 02 00 00 85 DB 75 ?? 81 C4 ?? 02 00 00 5D 5B 5F}
        $crypt_32_v2 = {56 57 53 55 81 EC 08 02 00 00 8B BC 24 1C 02 00 00 85 FF 74 20 8B AC 24 20 02 00 00 85 ED 74 15 83 BC 24 24 02 00 00 00 74 0B 8B 9C 24 28 02 00 00 85 DB 75 ?? 81 C4 ?? 02 00 00 5D 5B 5F}
        $crypt_32_v3 = {56 57 53 55 81 EC 08 02 00 00 8B E9 8B FA 85 ED 74 19 85 FF 74 15 83 BC 24 1C 02 00 00 00 74 0B 8B 9C 24 20 02 00 00 85 DB 75 0D}

        $crypt_64_v1 = {41 54 41 55 41 56 41 57 48 81 EC 48 02 00 00 49 89 CE 45 89 CC 4D 89 C5 41 89 D7 4D 85 F6 0F 84 41 02 00 00 45 85 FF 0F 84 38 02 00 00 4D 85 ED 0F 84 2F 02 00 00 45 85 E4 0F 84 26 02 00}
    
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D 

        and 

        ($crypt_32_v1 or $crypt_32_v2 or $crypt_32_v3 or $crypt_64_v1)
}
