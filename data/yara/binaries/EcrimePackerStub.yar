rule EcrimePackerStub
{
    meta:
        author = "ReversingLabs"
        description = "First bytes in decoded unpacker stub."
    strings:
        $stub = {e8 00 00 00 00 5b 81 eb [4] 8d 83 [4] 89 83 [4] 8d b3 [4] 89 b3 [4] 8b 46 ?? 89 83 [4] 8d b3 [4] 56 8d b3 [4] 56 6a ?? 68 [4] 8d bb [4] ff d7}
    condition:
        uint16(0) == 0x5A4D and all of them
}
