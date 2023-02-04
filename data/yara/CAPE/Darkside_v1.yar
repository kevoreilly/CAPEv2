rule Ransomware_Win_DARKSIDE_v1_1
{
    meta:
        author = "FireEye"
        date_created = "2021-03-22"
        description = "Detection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values."
        md5 = "1a700f845849e573ab3148daef1a3b0b"
        cape_type = "DarksideV1 Payload"
    strings:
        $consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $consts
}
