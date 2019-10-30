rule Ryuk
{
    meta:
        author = "kevoreilly"
        description = "Ryuk Payload"
        cape_type = "Ryuk Payload"
    strings:
        $ext = ".RYK" wide
        $readme = "RyukReadMe.txt" wide
        $main = "InvokeMainViaCRT"
        $code = {48 8B 4D 10 48 8B 03 48 C1 E8 07 C1 E0 04 F7 D0 33 41 08 83 E0 10 31 41 08 48 8B 4D 10 48 8B 03 48 C1 E8 09 C1 E0 03 F7 D0 33 41 08 83 E0 08 31 41 08}
    condition:
        uint16(0) == 0x5A4D and 3 of ($*)
}
