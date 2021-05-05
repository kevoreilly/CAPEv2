import "pe"

rule caliber {
    meta:
        author      = "c3rb3ru5"
        description = "44Caliber Stealer"
        type        = "malware.stealer"
        os          = "windows"
        tlp         = "white"
        rev         = "1"
    strings:
        $stealer_name = "44 CALIBER STEALER" ascii wide
        $webhooks     = /https?:\/\/discord.com\/api\/webhooks\// ascii wide
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        pe.imports("mscoree.dll") and
        filesize < 1MB and
        $stealer_name and
        $webhooks
}
