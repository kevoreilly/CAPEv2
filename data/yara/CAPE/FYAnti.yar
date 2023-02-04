import "pe"

rule FYAnti {
    meta:
        author = "ditekSHen"
        description = "Hunt for FYAnti third-stage loader DLLs"
        cape_type = "FYAnti Load Payload"
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and pe.exports("FuckYouAnti")
}
