rule Atlas
{
    meta:
        author = "kevoreilly"
        description = "Atlas Payload"
        cape_type = "Atlas Payload"
    strings:
        $a1 = "bye.bat"
        $a2 = "task=knock&id=%s&ver=%s x%s&disks=%s&other=%s&ip=%s&pub="
        $a3 = "process call create \"cmd /c start vssadmin delete shadows /all /q"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
