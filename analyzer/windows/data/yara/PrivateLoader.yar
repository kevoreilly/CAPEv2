rule PrivateLoader
{
    meta:
        author = "kevoreilly"
        description = "PrivateLoader indirect syscall capture"
        cape_options = "clear,sysbp=$syscall*-2"
        packed = "075d0dafd7b794fbabaf53d38895cfd7cffed4a3fe093b0fc7853f3b3ce642a4"
    strings:
        $syscall = {48 31 C0 4C 8B 19 8B 41 10 48 8B 49 08 49 89 CA 41 FF E3}
    condition:
        any of them
}
