import "pe"

rule GhostEmperorRC {
    meta:
        author = "ditekSHen"
        description = "Detects / Hunts for GhostEmperor Stage 4 Remote Control Payload"
        cape_type = "GhostEmperor Remote Control Payload"
    condition:
        uint16(0) == 0x5a4d and pe.is_dll() and pe.number_of_exports == 2 and pe.exports("1") and pe.exports("__acrt_iob_func")
}
