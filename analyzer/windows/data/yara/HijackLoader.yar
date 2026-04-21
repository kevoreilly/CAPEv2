rule HijackLoaderStub
{
    meta:
        author = "kevoreilly"
        description = "HijackLoader Stub Executable"
        cape_options = "dump-limit=0,dump"
    strings:
        $stub1 = {50 83 C0 10 50 56 8D 85 [4] 50 E8 [4] 83 C7 30 8D 85 [4] 3B F8 74 08 8B 35 [4] EB D3}
        $stub2 = {33 C5 89 45 ?? (C6 45 ?? 00|C7 45 ?? 61 7A 2D 2D) 8D 45 ?? FF 75 ?? C7 45 ?? 30 39 41 5A 50 8D 45 (??|?? C7 45 ?? 61 7A 2D 2D) 50 E8}
        $app = "\\app-" wide
    condition:
        2 of them
}  
