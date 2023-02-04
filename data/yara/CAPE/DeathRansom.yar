rule DeathRansom {
    meta:
        author = "ditekSHen"
        description = "Detects known DeathRansom ransomware"
        cape_type = "DeathRansom Payload"
    strings:
        $s1 = "%s %f %c" fullword ascii
        $pdb1 = ":\\wud.pdb" ascii
        $spdb2 = "\\crypt_server\\runtime\\crypt" ascii
        $spdb3 = "\\bin\\nuvin.pdb" ascii
        $h1 = "#Dunubeyokunov" wide
        $h2 = "^Neyot dehipijakeyelih" wide
        $h3 = "talin%Sanovurenofibiw" wide
        $h4 = "WriteFile" fullword ascii
        $h5 = "ClearEventLogA" fullword ascii
        $h6 = "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0" ascii wide
    condition:
        uint16(0) == 0x5a4d and (all of ($pdb*) or (all of ($s*) and 1 of ($pdb*)) or 5 of ($h*))
}
