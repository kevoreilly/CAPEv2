rule Buran {
    meta:
        author = "ditekshen"
        description = "Buran Payload"
        cape_type = "Buran payload"
    strings:
        // Variant 1
        $v1_1 = "U?$error_info_injector@V" ascii
        $v1_2 = "Browse for Folder (FTP)" fullword ascii
        $v1_3 = "Find/Replace in Files" fullword ascii
        $v1_4 = "PAHKLM" fullword ascii
        $v1_5 = "PAHKCR" fullword ascii
        $v1_6 = "chkOpt_" ascii
        $h1 = "Search <a href=\"location\" class=\"menu\">in this folder</a>" ascii
        $h2 = "<br>to find where the text below" ascii
        $h3 = "</a> files with these extensions (separate with semi-colons)" ascii
        $h4 = "Need help with <a href=\"" ascii
        $path = "\\work\\cr\\nata\\libs\\boost_" wide
        // Variant 2
        $v2_1 = "(ShlObj" fullword ascii
        $v2_2 = "\\StreamUnit" fullword ascii
        $v2_3 = "TReadme" fullword ascii
        $v2_4 = "TDrivesAndShares" fullword ascii
        $v2_5 = "TCustomMemoryStreamD" fullword ascii
        $v2_6 = "OpenProcessToken" fullword ascii
        $v2_7 = "UrlMon" fullword ascii
        $v2_8 = "HttpSendRequestA" fullword ascii
        $v2_9 = "InternetConnectA" fullword ascii
        $v2_10 = "FindFiles" fullword ascii
        $v2_12 = "$*@@@*$@@@$" ascii
    condition:
        uint16(0) == 0x5a4d and (((all of ($v1*) and 1 of ($h*)) or ($path and 2 of ($v1*) and 1 of ($h*)) or 10 of them) or all of ($v2*))
}
