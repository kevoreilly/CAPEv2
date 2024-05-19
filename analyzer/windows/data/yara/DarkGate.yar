rule DarkGate
{
    meta:
        author = "enzok"
        description = "DarkGate config"
        cape_options = "bp0=$config2+3,action0=dump:edx::1025,count=0,typestring=DarkGate Config"
        hash = "c1d35921f4fc3bac681a3d5148f517dc0ec90ab8c51e267c8c6cd5b1ca3dc085"
    strings:
        $part1 = {8B 55 ?? 8A 4D ?? 80 E1 3F C1 E1 02 8A 5D ?? 80 E3 30 81 E3 FF [3] C1 EB 04 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
        $part2 = {8B 55 ?? 8A 4D ?? 80 E1 0F C1 E1 04 8A 5D ?? 80 E3 3C 81 E3 FF [3] C1 EB 02 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
        $part3 = {8B 55 ?? 8A 4D ?? 80 E1 03 C1 E1 06 8A 5D ?? 80 E3 3F 02 CB 88 4C 10 FF FF 45}
        $alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
        $config1 = {B9 01 04 00 00 E8 [4] 8D 45}
        $config2 = {8B 55 ?? 8D 45 ?? E8 [4] 8D 45 ?? 5? B? 06 00 00 00 B? 01 00 00 00 8B 45 ?? E8 [4] 8B 45 ?? B? [4] E8 [4] 75}
    condition:
        ($alphabet) and (any of ($part*) or all of ($config*))
}
