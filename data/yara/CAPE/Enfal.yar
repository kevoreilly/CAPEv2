rule Enfal
{
    meta:
        author = "kev"
        description = "Enfal configuration blob"
        cape_type = "Enfal Config"
    strings:
        $config1 = {BF 49 ?? 75 22 12 ?? 75 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C}

    condition:
        $config1
}
