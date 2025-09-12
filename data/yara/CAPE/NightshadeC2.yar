rule NightshadeC2
{
    meta:
        author = "YungBinary"
        description = "NightshadeC2 AKA CastleRAT - https://x.com/YungBinary/status/1963751038340534482"
        hash = "963c012d56c62093d105ab5044517fdcce4ab826f7782b3e377932da1df6896d"
        cape_type = "NightshadeC2 Payload"
    strings:
        $s1 = "keylog.txt" fullword wide
        $s2 = "\"%ws\" --mute-audio --do-not-de-elevate" fullword wide
        $s3 = "\"%ws\" -no-deelevate" fullword wide
        $s4 = "MachineGuid" fullword wide
        $s5 = "www.ip-api.com" fullword wide
        $s6 = "rundll32 \"C:\\Windows\\System32\\shell32.dll\" #61" fullword wide
        $s7 = "IsabellaWine" fullword wide
        $s8 = "Shell_TrayWnd" fullword wide

    condition:
        uint16(0) == 0x5A4D and 3 of them
}
