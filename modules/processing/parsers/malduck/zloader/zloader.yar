rule zloader {
    meta:
        author      = "c3rb3ru5"
        description = "ZLoader"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zloader"
        reference   = "https://github.com/kevoreilly/CAPEv2/blob/master/modules/processing/parsers/mwcp/Zloader.py"
        hash        = "69710e08b572faca056f4410a545aae0"
        type        = "malware.loader"
        created     = "2021-05-04"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $decrypt_conf = {e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8
                         ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ??
                         ?? ?? ?? 83 c4 08 e8 ?? ?? ?? ??}
        $sequence_0   = {51 56 50 6801000080}
        $sequence_1   = {83c408 8d4df0 6a00 51 6a01}
        $sequence_2   = {83c40c 53 57 56 e8???????? 81c410010000 5e}
        $sequence_3   = {89e5 56 8b7508 ff36 e8???????? 83c404}
        $sequence_4   = {ff7518 8d75e4 56 ff7510 ff750c ff7508}
        $sequence_5   = {89c6 56 53 57 e8????????}
        $sequence_6   = {83c408 84c0 7466 ff35???????? e8???????? 83c404 84c0}
        $sequence_7   = {51 e8???????? 83c408 a801}
        $sequence_8   = {56 50 a1???????? 89c1}
        $sequence_9   = {89e5 53 57 56 50 8b4510 31db}
        $sequence_10  = {50 56 56 56 ff7514}
        $sequence_11  = {5e c3 56 57 8b7c2414 83ffff 750c}
        $sequence_12  = {7cf5 5f c6043000 5e c3 56}
        $sequence_13  = {5e 8bc3 5b c3 8b44240c 83f8ff}
        $sequence_14  = {68???????? ff742408 e8???????? 59 59 84c0}
        $sequence_15  = {59 84c0 7432 68???????? ff742408}
        $sequence_16  = {c7460488130000 c7462401000000 c7462800004001 e8???????? 89460c}
        $sequence_17  = {50 89542444 e8???????? 03c0 6689442438 8b442438}
        $sequence_18  = {e8???????? 83c414 c3 8b542404 85d2 7503 33c0}
        $sequence_19  = {6aff 50 e8???????? 8d857cffffff 50}
        $sequence_20  = {83c408 5e 5d c3 55 89e5 57}
        $sequence_21  = {83c414 c3 56 ff742410}
        $sequence_22  = {99 52 50 8d44243c 99 52 50}
        $sequence_23  = {81c4a8020000 5e 5f 5b}
        $sequence_24  = {6689442438 8b442438 83c002 668944243a}
        $sequence_25  = {57 56 83ec20 e8????????}
        $sequence_26  = {55 bd00000001 392b 7404}
        $sequence_27  = {33c9 03c7 13cb 8945f8 894dfc}
        $sequence_28  = {8d742410 89b42430010000 8b842430010000 8b842430010000 890424 c74424041c010000 e8????????}
        $sequence_29  = {e9???????? 31c0 83c40c 5e}
        $sequence_30  = {5d c3 51 64a130000000}
        $sequence_31  = {57 50 e8???????? 68???????? 56 e8???????? 8bf0}
        $sequence_32  = {33db 68???????? 6880000000 50 e8???????? 83c410}
        $sequence_33  = {e8???????? ff7508 8d85f0fdffff 68???????? 6804010000}
        $sequence_34  = {56 68???????? ff742410 e8???????? 6823af2930 56 ff742410}
        $sequence_35  = {57 ff750c 33db 68????????}
        $sequence_36  = {5d 5b c3 8bc2 ebf7 8d442410 50}
        $sequence_37  = {5b c3 8bc2 ebf8 53 8b5c240c}
        $sequence_38  = {c3 56 8b742408 6804010000 68????????}
        $sequence_39  = {50 6a72 e8???????? 59}
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1105920 and
        7 of ($sequence_*) and 
        $decrypt_conf
}
