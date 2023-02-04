rule Nibiru {
    meta:
      author = "ditekSHen"
      description = "Detects Nibiru ransomware"
      cape_type = "Nibiru Payload"
    strings:
        $s1 = ".encrypt" fullword wide
        $s2 = "crypted" fullword wide
        $s3 = ".Nibiru" fullword wide
        $s4 = "Encryption Complete" fullword wide
        $s5 = "All your files,documents,important datas,mp4,mp3 and anything valuable" ascii
        $s6 = "EncryptOrDecryptFile" fullword ascii
        $s7 = "get_hacker" ascii
        $s8 = "/C choice /C Y /N /D Y /T 3 & Del \"" fullword wide
        $s9 = "Once You pay,you get the KEY to decrypt files" ascii
        $pdb = "\\Projects\\Nibiru\\Nibiru\\obj\\x86\\Release\\Nibiru.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of them or ($pdb and 2 of ($s*)))
}
