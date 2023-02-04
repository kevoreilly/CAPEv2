rule LilithRAT {
    meta:
        author = "ditekSHen"
        description = "Detects LilithRAT"
        cape_type = "LilithRAT Payload"
    strings:
        $pdb1 = "c:\\Users\\Groovi\\Documents\\Visual Studio 2008\\Projects\\TestDll\\" ascii
        $pdb2 = "C:\\Users\\iceberg\\Downloads\\RAT-Server-master\\RAT-Server-master\\RAT\\Debug\\RAT.pdb" ascii
        $pdb3 = "C:\\Users\\Samy\\Downloads\\Compressed\\Lilith-master\\Debug\\Lilith.pdb" ascii
        $s1 = "log.txt" fullword ascii
        $s2 = "keylog.txt" fullword ascii
        $s3 = "File Listing Completed Successfully." fullword ascii
        $s4 = "Download Execute" fullword ascii
        $s5 = "File Downloaded and Executed Successfully." fullword ascii
        $s6 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii
        $s7 = "CMD session closed" ascii
        $s8 = "Restart requested: Restarting self" fullword ascii
        $s9 = "Termination requested: Killing self" fullword ascii
        $s10 = "Couldn't write to CMD: CMD not open" fullword ascii
        $s11 = "keydump" fullword ascii
        $s12 = "remoteControl" fullword ascii
        $s13 = "packettype" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($pdb*) or 6 of ($s*) or (1 of ($pdb*) and 4 of ($s*)))
}
