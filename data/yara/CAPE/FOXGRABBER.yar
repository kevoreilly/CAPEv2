rule FOXGRABBER {
    meta:
        author = "ditekSHen"
        description = "Detects FOXGRABBER utility"
        cape_type = "FOXGRABBER Payload"
    strings:
        $s1 = "start grabbing" wide
        $s2 = "end grabbing in" wide
        $s3 = "error of copying files from comp:" wide
        $s4 = "\\Firefox\\" wide nocase
        $pdb1 = "\\obj\\Debug\\grabff.pdb" ascii
        $pdb2 = "\\obj\\Release\\grabff.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (1 of ($pdb*) and 1 of ($s*)))
}
