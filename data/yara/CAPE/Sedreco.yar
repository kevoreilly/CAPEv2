rule Sedreco
{
    meta:
        author = "kevoreilly"
        description = "Sedreco encrypt function entry"
        cape_type = "Sedreco Payload"
    strings:
        $encrypt1 = {55 8B EC 83 EC 2C 53 56 8B F2 57 8B 7D 08 B8 AB AA AA AA}
        $encrypt2 = {55 8B EC 83 EC 20 8B 4D 10 B8 AB AA AA AA}

        $encrypt64_1 = {48 89 4C 24 08 53 55 56 57 41 54 41 56 48 83 EC 18 45 8D 34 10 48 8B E9 B8 AB AA AA AA 4D 8B E1 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA}
        
    condition:
        uint16(0) == 0x5A4D and $encrypt1 or $encrypt2 or $encrypt64_1
}