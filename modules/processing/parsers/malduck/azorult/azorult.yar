rule azorult {
    meta:
        author      = "c3rb3ru5"
        description = "Azorult Configuration Extractor"
        hash        = "7fb0d0af8be74dfe47a820523901ed02"
        created     = "2021-04-30"
        os          = "windows"
        tlp         = "amber"
        rev         = 1
    strings:
        $ref_c2 = {6A 00 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? FF 55 F0
                   8B D8 C7 47 10 ?? ?? ?? ?? 90 C7 45 B0 C0 C6 2D
                   00 6A 04 8D 45 B0 50 6A 06 53 FF 55 D4}
   condition:
        uint16(0) == 0x5A4D and
        all of them
}
