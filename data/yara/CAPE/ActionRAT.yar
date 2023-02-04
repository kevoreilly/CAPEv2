rule ActionRAT {
    meta:
        author = "ditekSHen"
        description = "Detects ActionRAT, CSharp and Delfi variants"
        cape_type = "ActionRAT Payload"
    strings:
        $x1 = /<action>(connect|command|drives|getfiles|upload|execute|download)<action>/ fullword wide
        $x2 = "aHR0cDovLzE0NC45MS42NS4xMDAv" wide
        $x3 = "aHR0cDovL21mYWhvc3QuZGRucy5uZXQv" wide
        $f1 = "<updateCommand>b__" ascii
        $f2 = "<getDrives>b__" ascii
        $f3 = "<getStatus>b__" ascii
        $f4 = "<getDirectories>b__" ascii
        $f5 = "<updateUpload>b__" ascii
        $f6 = "<infinity>b__" ascii
        $f7 = "<uploadFile>b__" ascii
        $s1 = "beaconURL" ascii
        $s2 = "PingReply" ascii
        $s3 = "updateUpload" ascii
        $s4 = "updateCommand" ascii
        $s5 = "runCommand" ascii
        $s6 = "uploadFile" ascii
        $s7 = "SELECT * FROM MSFT_NetAdapter WHERE ConnectorPresent = True AND DeviceID = '{0}'" fullword wide
        $s8 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $s9 = "Mozilla/3.0" fullword wide
        $s10 = "|directory|N/A|" fullword wide
        $s11 = "cmd.exe /c" fullword wide
        $c1 = /Content-Disposition: form-data; name=(hostname|hid|id|action|secondary)/ fullword wide
        $c2 = /(classification|updatecs|update|beacon)\.php/ wide
        $c3 = "Content-Disposition: form-data;name=\"{0}\";filename=\"{1}\"filepath=\"{2}\"" fullword wide
        $pdb1 = "D:\\Projects\\C#\\HTTP-Simple\\WindowsMediaPlayer - HTTP - " ascii
        $pdb2 = "\\WindowsMediaPlayer10\\obj\\x86\\Release\\winow4.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (#x1 > 5 or (all of ($f*) and (1 of ($s*) or 2 of ($c*))) or 7 of ($s*) or all of ($c*) or (all of ($pdb*) and 4 of them) or ( 2 of ($x*) and 5 of them))
}
