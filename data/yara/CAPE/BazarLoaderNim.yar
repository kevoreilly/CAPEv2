rule BazarLoaderNim
{
    meta:
        description = "detects bazarloader written in Nim"
        author = "Vitali Kremez"
        date = "2021-02-07"
        reference = "https://twitter.com/VK_Intel/status/1358139627098558465"
        cape_type = "BazarLoader_Nim Payload"
    strings:
        $cmd_seq = { e8 [4] 4d 85 e4 0f [5] 49 [3] 48 83 f8 09 0f [5] 48 b8 68 61 6e 64 73 68 61 6b 49 [4] 49 [4] 0f [5] b8 01 00 00 00 85 c0 0f [4] ??}
    condition:
        $cmd_seq
}
