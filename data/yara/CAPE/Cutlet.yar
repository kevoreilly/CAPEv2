rule Cutlet {
        meta:
                description = "Detects Cutlet ATM malware"
                author = "@VK_Intel"
                reference = "Detects the Cutlet ATM malware"
                date = "2017-12-26"
                hash = "fac356509a156a8f11ce69f149198108"
                cape_type = "Cutlet Payload"
        strings:
                // DIEBOLD NIXDORF DLL ATM LIBRARY
                $dll = "CSCWCNG.dll" wide ascii

                // DLL PROCEDURES ASSOCIATED WITH CUTLET ATM
                $dll_proc1 = "CscCngClose" wide ascii
                $dll_proc2 = "CscCngTransport" wide ascii
                $dll_proc3 = "CscCngReset" wide ascii
                $dll_proc4 = "CscCngDispense" wide ascii
                $dll_proc5 = "CscCngOpen" wide ascii

                // CUTLET MALWARE STRINGS
                $str0 = "CSCCNG" wide ascii
                $str1 = "Code:" wide ascii
                $str2 = "Delphi" wide ascii

        condition:
                $dll and 4 of ($dll_proc*) and all of ($str*)
}
