import "pe"

rule INDICATOR_EXE_Packed_ConfuserEx {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod"
        snort2_sid = "930016-930018"
        snort3_sid = "930005-930006"
    strings:
        $s1 = "ConfuserEx " ascii
        $s2 = "ConfusedByAttribute" fullword ascii
        $c1 = "Confuser.Core " ascii wide
        $u1 = "Confu v" fullword ascii
        $u2 = "ConfuByAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($c*) or all of ($u*))
}

rule INDICATOR_EXE_Packed_ConfuserExMod_BedsProtector {
    meta:
        description = "Detects executables packed with ConfuserEx Mod Beds Protector"
        author = "ditekSHen"
    strings:
        $s1 = "Beds Protector v" ascii
        $s2 = "Beds-Protector-v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_ConfuserEx_Trinity {
    meta:
        description = "Detects executables packed with ConfuserEx Mod Trinity Protector"
        author = "ditekSHen"
    strings:
        $s1 = "Trinity0-protecor|" ascii
        $s2 = "#TrinityProtector" fullword ascii
        $s3 = /Trinity\d-protector\|/ ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_PS2EXE {
    meta:
        description = "Detects executables built or packed with PS2EXE"
        author = "ditekSHen"
    strings:
        $s1 = "PS2EXE" fullword ascii
        $s2 = "PS2EXEApp" fullword ascii
        $s3 = "PS2EXEHost" fullword ascii
        $s4 = "PS2EXEHostUI" fullword ascii
        $s5 = "PS2EXEHostRawUI" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_LSD {
    meta:
        description = "Detects executables built or packed with LSD packer"
        author = "ditekSHen"
    strings:
        $s1 = "This file is packed with the LSD executable packer" ascii
        $s2 = "http://lsd.dg.com" ascii
        $s3 = "&V0LSD!$" fullword ascii
    condition:
         (uint16(0) == 0x5a4d or uint16(0)== 0x457f) and 1 of them
}

rule INDICATOR_EXE_Packed_AspireCrypt {
    meta:
        description = "Detects executables packed with AspireCrypt"
        author = "ditekSHen"
    strings:
        $s1 = "AspireCrypt" fullword ascii
        $s2 = "aspirecrypt.net" ascii
        $s3 = "protected by AspireCrypt" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Spices {
    meta:
        description = "Detects executables packed with 9Rays.Net Spices.Net Obfuscator."
        author = "ditekSHen"
    strings:
        $s1 = "9Rays.Net Spices.Net" ascii
        $s2 = "protected by 9Rays.Net Spices.Net Obfuscator" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_JAVA_Packed_Allatori {
    meta:
        description = "Detects files packed with Allatori Java Obfuscator"
        author = "ditekSHen"
    strings:
        $s1 = "# Obfuscation by Allatori Obfuscator" ascii wide
    condition:
        all of them
}

rule INDICATOR_EXE_Packed_ASPack {
    meta:
        description = "Detects executables packed with ASPack"
        author = "ditekSHen"
    strings:
        $s1 = { 00 00 ?? 2E 61 73 70 61 63 6B 00 00 }
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack"
            )
        )
}

rule INDICATOR_EXE_Packed_Titan {
    meta:
        description = "Detects executables packed with Titan"
        author = "ditekSHen"
    strings:
        $s1 = { 00 00 ?? 2e 74 69 74 61 6e 00 00 }
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".titan"
            )
        )
}

rule INDICATOR_EXE_Packed_aPLib {
    meta:
        description = "Detects executables packed with aPLib."
        author = "ditekSHen"
    strings:
        $header = { 41 50 33 32 18 00 00 00 [0-35] 4D 38 5A 90 }
    condition:
        ((uint32(0) == 0x32335041 and uint32(24) == 0x905a384d) or (uint16(0) == 0x5a4d and $header ))
}

rule INDICATOR_EXE_Packed_LibZ {
    meta:
        description = "Detects executables built or packed with LibZ"
        author = "ditekSHen"
    strings:
        $s1 = "LibZ.Injected" fullword ascii
        $s2 = "{0:N}.dll" fullword wide
        $s3 = "asmz://(?<guid>[0-9a-fA-F]{32})/(?<size>[0-9]+)(/(?<flags>[a-zA-Z0-9]*))?" fullword wide
        $s4 = "Software\\Softpark\\LibZ" fullword wide
        $s5 = "(AsmZ/{" wide
        $s6 = "asmz://" ascii
        $s7 = "GetRegistryDWORD" ascii
        $s8 = "REGISTRY_KEY_NAME" fullword ascii
        $s9 = "REGISTRY_KEY_PATH" fullword ascii
        $s10 = "InitializeDecoders" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_EXE_Packed_Enigma {
    meta:
        description = "Detects executables packed with Enigma"
        author = "ditekSHen"
    strings:
        $s1 = ".enigma0" fullword ascii
        $s2 = ".enigma1" fullword ascii
        $s3 = ".enigma2" fullword ascii
        $s4 = ".enigma3" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".enigma0" or
                pe.sections[i].name == ".enigma1" or
                pe.sections[i].name == ".enigma2" or
                pe.sections[i].name == ".enigma3"
            )
        )
}

rule INDICATOR_EXE_Python_Byte_Compiled {
    meta:
        description = "Detects python-byte compiled executables"
        author = "ditekSHen"
    strings:
        $s1 = "b64decode" ascii
        $s2 = "decompress" ascii
    condition:
        uint32(0) == 0x0a0df303 and filesize < 5KB and all of them
}

rule INDICATOR_MSI_EXE2MSI {
    meta:
        description = "Detects executables converted to .MSI packages using a free online converter."
        author = "ditekSHen"
    strings:
        $winin = "Windows Installer" ascii
        $title = "Exe to msi converter free" ascii
    condition:
        uint32(0) == 0xe011cfd0 and ($winin and $title)
}

rule INDICATOR_EXE_Packed_MPress {
    meta:
        description = "Detects executables built or packed with MPress PE compressor"
        author = "ditekSHen"
    strings:
        $s1 = ".MPRESS1" fullword ascii
        $s2 = ".MPRESS2" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".MPRESS1" or
                pe.sections[i].name == ".MPRESS2"
            )
        )
}

rule INDICATOR_EXE_Packed_Nate {
    meta:
        description = "Detects executables built or packed with Nate packer"
        author = "ditekSHen"
    strings:
        $s1 = "@.nate0" fullword ascii
        $s2 = "`.nate1" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".nate0" or
                pe.sections[i].name == ".nate1"
            )
        )
}

rule INDICATOR_EXE_Packed_VMProtect {
    meta:
        description = "Detects executables packed with VMProtect."
        author = "ditekSHen"
    strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}

rule INDICATOR_EXE_DotNET_Encrypted {
    meta:
        description = "Detects encrypted or obfuscated .NET executables"
        author = "ditekSHen"
    strings:
        $s1 = "FromBase64String" fullword ascii
        $s2 = "ToCharArray" fullword ascii
        $s3 = "ReadBytes" fullword ascii
        $s4 = "add_AssemblyResolve" fullword ascii
        $s5 = "MemoryStream" fullword ascii
        $s6 = "CreateDecryptor" fullword ascii

         // 08 00 00 00 00 00 1e 01 00 01 00 54 02 16 WrapNonExceptionThrows 01
        $bytes1 = { 08 01 00 08 00 00 00 00 00 1e 01 00 01 00 54 02
                    16 57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f
                    6e 54 68 72 6f 77 73 01 }
        // 00 00 BSJB...v2.0.50727 00 00 00 00 05 00
        // 00 00 BSJB...v4.0.30319 00 00 00 00 05 00
        $bytes2 = { 00 00 42 53 4a 42 01 00 01 00 00 00 00 00 0c 00
                    00 00 76 3? 2e 3? 2e ?? ?? ?? ?? ?? 00 00 00 00
                    05 00 }
        // #Strings...#US...#GUID...#Blob
        $bytes3 = { 00 00 23 53 74 72 69 6e 67 73 00 00 00 00 [5] 00
                    00 00 23 55 53 00 [5] 00 00 00 23 47 55 49 44 00
                    00 00 [6] 00 00 23 42 6c 6f 62 00 00 00 }
        // .GetString.set_WorkingDirectory.WaitForExit.Close.Thread.System.Threading.Sleep.ToInt32.get_MainModule.ProcessModule.get_FileName.Split.
        $bytes4 = { 00 47 65 74 53 74 72 69 6e 67 00 73 65 74 5f 57
                    6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 00
                    57 61 69 74 46 6f 72 45 78 69 74 00 43 6c 6f 73
                    65 00 54 68 72 65 61 64 00 53 79 73 74 65 6d 2e
                    54 68 72 65 61 64 69 6e 67 00 53 6c 65 65 70 00
                    54 6f 49 6e 74 33 32 00 67 65 74 5f 4d 61 69 6e
                    4d 6f 64 75 6c 65 00 50 72 6f 63 65 73 73 4d 6f
                    64 75 6c 65 00 67 65 74 5f 46 69 6c 65 4e 61 6d
                    65 00 53 70 6c 69 74 00 }
    condition:
        uint16(0) == 0x5a4d and 3 of ($bytes*) and all of ($s*)
}

rule INDICATOR_PY_Packed_PyMinifier {
    meta:
        description = "Detects python code potentially obfuscated using PyMinifier"
        author = "ditekSHen"
    strings:
        $s1 = "exec(lzma.decompress(base64.b64decode("
    condition:
        (uint32(0) == 0x6f706d69 or uint16(0) == 0x2123 or uint16(0) == 0x0a0d or uint16(0) == 0x5a4d) and all of them
}

rule INDICATOR_EXE_Packed_BoxedApp {
    meta:
        description = "Detects executables packed with BoxedApp"
        author = "ditekSHen"
    strings:
        $s1 = "BoxedAppSDK_HookFunction" fullword ascii
        $s2 = "BoxedAppSDK_StaticLib.cpp" ascii
        $s3 = "embedding BoxedApp into child processes: %s" ascii
        $s4 = "GetCommandLineA preparing to intercept" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".bxpck"
            )
        )
}

rule INDICATOR_EXE_Packed_eXPressor {
    meta:
        description = "Detects executables packed with eXPressor"
        author = "ditekSHen"
    strings:
        $s1 = "eXPressor_InstanceChecker_" fullword ascii
        $s2 = "This application was packed with an Unregistered version of eXPressor" ascii
        $s3 = ", please visit www.cgsoftlabs.ro" ascii
        $s4 = /eXPr-v\.\d+\.\d+/ ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".ex_cod"
            )
        )
}

rule INDICATOR_EXE_Packed_MEW {
    meta:
        description = "Detects executables packed with MEW"
        author = "ditekSHen"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "MEW" or
                pe.sections[i].name == "\x02\xd2u\xdb\x8a\x16\xeb\xd4"
            )
        )
}

rule INDICATOR_EXE_Packed_RLPack {
    meta:
        description = "Detects executables packed with RLPACK"
        author = "ditekSHen"
    strings:
        $s1 = ".packed" fullword ascii
        $s2 = ".RLPack" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".RLPack"
            )
        )
}

rule INDICATOR_EXE_Packed_Cassandra {
    meta:
        description = "Detects executables packed with Cassandra/CyaX"
        author = "ditekSHen"
    strings:
        $s1 = "AntiEM" fullword ascii wide
        $s2 = "AntiSB" fullword ascii wide
        $s3 = "Antis" fullword ascii wide
        $s4 = "XOR_DEC" fullword ascii wide
        $s5 = "StartInject" fullword ascii wide
        $s6 = "DetectGawadaka" fullword ascii wide
        $c1 = "CyaX-Sharp" ascii wide
        $c2 = "CyaX_Sharp" ascii wide
        $c3 = "CyaX-PNG" ascii wide
        $c4 = "CyaX_PNG" ascii wide
        $pdb = "\\CyaX\\obj\\Debug\\CyaX.pdb" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (4 of ($s*) or 2 of ($c*) or $pdb)) or (7 of them)
}

rule INDICATOR_EXE_Packed_ConfuserEx_Custom {
    meta:
        description = "Detects executables packed with ConfuserEx Custom, outside of GIT"
        author = "ditekSHen"
    strings:
        $s1 = { 43 6f 6e 66 75 73 65 72 45 78 20 76 [1-2] 2e [1-2] 2e [1-2] 2d 63 75 73 74 6f 6d }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Themida {
    meta:
        description = "Detects executables packed with Themida"
        author = "ditekSHen"
        snort2_sid = "930067-930069"
        snort3_sid = "930024"
    strings:
        $s1 = "@.themida" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".themida"
            )
        )
}

rule INDICATOR_EXE_Packed_SilentInstallBuilder {
    meta:
        description = "Detects executables packed with Silent Install Builder"
        author = "ditekSHen"
        snort2_sid = "930070-930072"
        snort3_sid = "930025"
    strings:
        $s1 = "C:\\Users\\Operations\\Source\\Workspaces\\Sib\\Sibl\\Release\\Sibuia.pdb" fullword ascii
        $s2 = "->mb!Silent Install Builder Demo Package." fullword wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_NyanXCat_CSharpLoader {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables utilizing NyanX-CAT C# Loader"
    strings:
        $s1 = { 00 50 72 6f 67 72 61 6d 00 4c 6f 61 64 65 72 00 4e 79 61 6e 00 }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Loader {
    meta:
        author = "ditekSHen"
        description = "Detects packed executables observed in Molerats"
    strings:
        $l1 = "loaderx86.dll" fullword ascii
        $l2 = "loaderx86" fullword ascii
        $l3 = "loaderx64.dll" fullword ascii
        $l4 = "loaderx64" fullword ascii
        $s1 = "ImportCall_Zw" wide
        $s2 = "DllInstall" ascii wide
        $s3 = "evb*.tmp" fullword wide
        $s4 = "WARNING ZwReadFileInformation" ascii
        $s5 = "LoadLibrary failed with module " fullword wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($l*) and 4 of ($s*)
}

rule INDICATOR_EXE_Packed_Bonsai {
    meta:
        description = "Detects .NET executables developed using Bonsai"
    strings:
        $bonsai1 = "<Bonsai." ascii
        $bonsai2 = "Bonsai.Properties" ascii
        $bonsai3 = "Bonsai.Core.dll" fullword wide
        $bonsai4 = "Bonsai.Design." wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($bonsai*)
}

rule INDICATOR_EXE_Packed_TriumphLoader {
    meta:
        author = "ditekSHen"
        description = "Detects TriumphLoader"
        cape_type = "TriumphLoader"
    strings:
        $id1 = "User-Agent: TriumphLoader" ascii wide
        $id2 = "\\loader\\absent-loader-master\\client\\full\\absentclientfull\\absentclientfull\\absent\\json.hpp" wide
        $id3 = "\\triumphloader\\triumphloaderfiles\\triumph\\json.h" wide
        $s1 = "current == '\\\"'" fullword wide
        $s2 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii
        $s3 = "646566676869707172737475767778798081828384858687888990919293949596979899object key" fullword ascii
        $s4 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s5 = "last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10" fullword wide
        $s6 = "p2 <= (std::numeric_limits<std::uint64_t>::max)() / 10" fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($id*) or all of ($s*) or (3 of ($s*) and 1 of ($id*)) or (4 of them and pe.imphash() == "784001f4b755832ae9085d98afc9ce83"))
}

rule INDICATOR_EXE_Packed_LLVMLoader {
    meta:
        author = "ditekSHen"
        description = "Detects LLVM obfuscator/loader"
    strings:
        $s1 = "exeLoaderDll_LLVMO.dll" fullword ascii
        $b = { 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 ?? 96 01 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? 45 78 69
               74 50 72 6f 63 65 73 73 00 4b 45 52 4e 45 4c 33
               32 2e 64 6c 6c 00 00 00 00 00 00 }
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x0158) and ((pe.exports("StartFunc") and 1 of ($s*)) or all of ($s*) or ($b))
}

rule INDICATOR_EXE_Packed_NoobyProtect {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with NoopyProtect"
    strings:
        $s1 = "NoobyProtect SE" ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "SE"
            )
        )
}

rule INDICATOR_EXE_Packed_nBinder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with nBinder"
    strings:
        $s1 = "This file was created using nBinder" ascii
        $s2 = "Warning: Contains binded files that may pose a security risk." ascii
        $s3 = "a file created with nBinder" ascii
        $s4 = "name=\"NKProds.nBinder.Unpacker\" type=\"win" ascii
        $s5 = "<description>nBinder Unpacker. www.nkprods.com</description>" ascii
        $s6 = "nBinder Unpacker (C) NKProds" wide
        $s7 = "\\Proiecte\\nBin" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_SmartAssembly {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with SmartAssembly"
    strings:
        $s1 = "PoweredByAttribute" fullword ascii
        $s2 = "SmartAssembly.Attributes" fullword ascii
        $s3 = "Powered by SmartAssembly" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_BlackMoon {
    meta:
        author = "ditekSHen"
        description = "Detects executables using BlackMoon RunTime"
    strings:
        $s1 = "blackmoon" fullword ascii
        $s2 = "BlackMoon RunTime Error:" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_AgileDotNet {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Agile.NET / CliSecure"
    strings:
        $x1 = "AgileDotNetRT" fullword ascii
        $x2 = "AgileDotNetRT64" fullword ascii
        $x3 = "<AgileDotNetRT>" fullword ascii
        $x4 = "AgileDotNetRT.dll" fullword ascii
        $x5 = "AgileDotNetRT64.dll" fullword ascii
        $x6 = "get_AgileDotNet" ascii
        $x7 = "useAgileDotNetStackFrames" fullword ascii
        $x8 = "AgileDotNet." ascii
        $x9 = "://secureteam.net/webservices" ascii
        $x10 = "AgileDotNetProtector." ascii
        $s1 = "Callvirt" fullword ascii
        $s2 = "_Initialize64" fullword ascii
        $s3 = "_AtExit64" fullword ascii
        $s4 = "DomainUnload" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or all of ($s*))
}

rule INDICATOR_EXE_Packed_Fody {
    meta:
        author = "ditekSHen"
        description = "Detects executables manipulated with Fody"
    strings:
        $s1 = "ProcessedByFody" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Costura {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Costura DotNetGuard"
    strings:
        $s1 = "DotNetGuard" fullword ascii
        $s2 = "costura." ascii wide
        $s3 = "AssemblyLoader" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_SimplePolyEngine {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Sality Polymorphic Code Generator or Simple Poly Engine or Sality"
    strings:
        $s1 = "Simple Poly Engine v" ascii
        $b1 = "yrf<[LordPE]" ascii
        $b2 = "Hello world!" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($b*))
}

rule INDICATOR_EXE_Packed_dotNetProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with dotNetProtector"
    strings:
        $s1 = "dotNetProtector" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_DotNetReactor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with unregistered version of .NET Reactor"
    strings:
        $s1 = "is protected by an unregistered version of Eziriz's\".NET Reactor\"!" wide
        $s2 = "is protected by an unregistered version of .NET Reactor!\" );</script>" wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Dotfuscator {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Dotfuscator"
    strings:
        $s1 = "DotfuscatorAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_DNGuard {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with DNGuard"
    strings:
        $s1 = "DNGuard Runtime library" wide
        $s2 = "[*=*]This application is expired ![*=*]" fullword wide
        $s3 = "DNGuard.Runtime" ascii wide
        $s4 = "EnableHVM" ascii
        $s5 = "DNGuard.SDK" ascii
        $s6 = "DNGuard HVM Runtime" wide
        $s7 = "HVMRuntm.dll" wide
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_NETProtectIO {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with NETProtect.IO"
    strings:
        $s1 = "NETProtect.IO v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_KoiVM {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with or use KoiVM"
    strings:
        $s1 = "KoiVM v" ascii wide
        $s2 = "DarksVM " ascii wide
        $s3 = "Koi.NG" ascii wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Goliath {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Goliath"
    strings:
        $s1 = "ObfuscatedByGoliath" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Babel {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Babel"
    strings:
        $s1 = "BabelObfuscatorAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}
