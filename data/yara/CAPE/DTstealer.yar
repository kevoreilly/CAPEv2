rule DTstealer
{
    meta:
        description = "DTstealer"
        author = "James_inthe_box"
        reference = "4ab065354c6156380645c905823cafde"
        date = "2020/07"
        maltype = "Stealer"

    strings:
        $string1 = "BackingField" ascii
        $string2 = "&date=" wide
        $string3 = "&report=" wide
        $string4 = "&country=" wide
        $string5 = "encrypted_key" wide

    condition:
        uint16(0) == 0x5A4D and all of ($string*) and filesize < 100KB
}
