rule LoaderSyscall
{
    meta:
        author = "enzok"
        description = "Loader Syscall"
        cape_options = "sysbp=$syscall*-2,count=0"
    strings:
        $makehashes = {48 89 4C 24 ?? 48 89 54 24 ?? 4? 89 44 24 ?? 4? 89 4C 24 ?? 4? 83 EC ?? B? [4] E8 [3] 00}
        $number = {49 89 C3 B? [4] E8 [3] 00}
        $syscall = {48 83 C4 ?? 4? 8B 4C 24 ?? 4? 8B 54 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 89 CA 4? FF E3}
    condition:
        all of them
}

rule NitrogenLoaderAES
{
    meta:
        author = "enzok"
        description = "NitrogenLoader AES and IV"
        cape_options = "bp0=$keyiv0+8,action0=dump:ecx::64,hc0=1,bp1=$keyiv0*-4,action1=dump:ecx::32,hc1=1,count=0"
    strings:
        $keyiv0 = {48 8B 8C 24 [4] E8 [3] 00 4? 89 84 24 [4] 4? 8B 84 24 [4] 4? 89 84 24 [4] 4? 8B 8C 24 [4] E8 [3] 00}
		$keyiv1 = {48 89 84 24 [4] 4? 8B 84 24 [4] 4? 8B 94 24 [4] 4? 8D 8C 24 [4] E8 [3] FF}
		$keyiv2 = {48 63 84 24 [4] 4? 8B C0 4? 8B 94 24 [4] 4? 8D 8C 24 [4] E8 [3] FF 4? 8B 84 24}
    condition:
        all of them
}

rule NitrogenLoaderBypass
{
    meta:
        author = "enzok"
        description = "Nitrogen Loader Exit Bypass"
		cape_options = "bp2=$exit-2,action2=jmp,count=0"
    strings:
        $string1 = "LoadResource"
		$syscall = {48 83 C4 ?? 4? 8B 4C 24 ?? 4? 8B 54 24 ?? 4? 8B 44 24 ?? 4? 8B 4C 24 ?? 4? 89 CA 4? FF E3}
		$exit = {33 C9 E8 [4] E8 [4] 48 8D 84 24 [4] 48 89 44 24 ?? 4? B? E4 00 00 00 4? 8B 05 [4] B? 03 00 00 00 48 8D}
	condition:
        all of them
}

rule NitrogenLoaderConfig
{
    meta:
        author = "enzok"
        description = "NitrogenLoader Config Extraction"
        cape_options = "bp0=$decrypt1*+1,bp1=$key*,hc0=1,count=0,action0=string:rcx,action1=string:rdx,typestring=NitrogenLoader Config"
    strings:
        $decrypt1 = {48 63 4? 24 ?? 33 D2 48 [0-3] F7 B4 24 [4] 48 8B C2 48 8B 8C 24 [4] 0F BE 04 01}
        $decrypt2 = {8B ?? 24 [1-4] 33 C8 8B C1 48 63 4C 24 ?? 48 8B 94 24 [4] 88 04 0A}
        $decrypt3 = {8B 8C 24 ?? ?? ?? ?? 2B C8 8B C1 48 63 4C 24 ?? 48 8B 94 24 [4] 88 04 0A}
        $key = {74 ?? E8 [4] 85 C0 75 ?? 4? 8B 0D [3] 00 4? 8D 15 [3] 00 E8}
        $taskman_1 = {E8 [4] B9 61 00 00 00 88 84 24 [4] E8 [4] B9 73 00 00 00 88 84 24 [4] E8 [4] B9 6B 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_2 = {B9 4D 00 00 00 88 84 24 [4] E8 [4] B9 61 00 00 00 88 84 24 [4] E8 [4] B9 6E 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_3 = {B9 61 00 00 00 88 84 24 [4] E8 [4] B9 67 00 00 00 88 84 24 [4] E8 [4] B9 65 00 00 00 88 84 24 [4] E8 [3] FF}
        $taskman_4 = {B9 72 00 00 00 88 84 24 [4] E8 [4] 31 C9 88 84 24 [4] E8 [3] FF}
        $rc4decrypt_1 = {48 89 ?? 48 89 ?? E8 [4] 48 8B ?? 24 [1-4] 4? 89 ?? 48 89 ?? 4? 89 C1 89 EA E8 [4] 48 89}
        $rc4decrypt_2 = {E8 [4] 8B ?? 24 [1-4] 4? 89 ?? 48 89 ?? 4? 89 C1 E8 [3] FF}
    condition:
        any of ($decrypt*) or ($key and (3 of ($taskman_*) and 1 of ($rc4decrypt_*)))
}
