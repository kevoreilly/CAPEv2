rule PandaStealer {
    meta:
        author = "ditekSHen"
        description = "Detects Panda Stealer"
        cape_type = "PandaStealer Payload"
    strings:
        $s1 = "\\tokens.txt" fullword ascii
        $s2 = "user.config" fullword ascii
        $s3 = "Discord\\" ascii
        $s4 = "%s\\etilqs_" fullword ascii
        $s5 = "buildSettingGrabber" ascii
        $s6 = "buildSettingSteam" ascii
        $s7 = ".?AV?$_Ref_count_obj2@U_Recursive_dir_enum_impl@filesystem@std@@@" ascii
        $s8 = "UPDATE %Q.%s SET sql = substr(sql,1,%d) || ', ' || %Q || substr" ascii
        $s9 = "|| substr(name,%d+18) ELSE name END WHERE tbl_name=%Q AND (" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
