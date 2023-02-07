rule Hermes
{
    meta:
        author = "kevoreilly"
        description = "Hermes Payload"
        cape_type = "Hermes Payload"
    strings:
        $ext = ".HRM" wide
        $vss = "vssadmin Delete"
        $email = "supportdecrypt@firemail.cc" wide
    condition:
        uint16(0) == 0x5A4D and all of ($*)
}
