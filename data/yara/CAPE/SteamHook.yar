rule SteamHook {
    meta:
        author = "ditekSHen"
        description = "Detects potential Steam stealer"
        cape_type = "SteamHook Payload"
    strings:
        $s1 = "Mozilla/4.0 (compatible; )" fullword ascii
        $s2 = "/steam/upload.php" ascii
        $s3 = ".*?(ssfn\\d+)" fullword ascii
        $s4 = "add cookie failed..." fullword ascii
        $s5 = "Content-Type: multipart/form-data; boundary=--MULTI-PARTS-FORM-DATA-BOUNDARY" fullword ascii
        $pdb1 = "\\SteamHook\\Install\\" ascii
        $pdb2 = "\\SteamHook\\dll\\" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($pdb*) or (1 of ($pdb*) and 3 of ($s*)))
}
