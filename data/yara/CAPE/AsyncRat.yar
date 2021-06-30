rule AsyncRat
{
    meta:
        author = "kevoreilly, JPCERT/CC Incident Response Group"
        description = "AsyncRat Payload"
        cape_type = "AsyncRat Payload"
    strings:
        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}
        $b2 = {09 50 00 6F 00 6E 00 67 00 00}
        $string1 = "Pastebin" ascii wide nocase
        $string2 = "Pong" wide
        $string3 = "Stub.exe" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($salt and (2 of ($str*) or 1 of ($b*))) or (all of ($b*) and 2 of ($str*))
}
