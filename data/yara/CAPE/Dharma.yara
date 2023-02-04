rule Dharma {
    meta:
        author = "ditekSHen"
        description = "Detects Dharma ransomware"
        cape_type = "Dharma Payload"
    strings:
        $s1 = "C:\\crysis\\Release\\PDB\\payload.pdb" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
