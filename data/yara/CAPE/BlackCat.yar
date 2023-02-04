rule BlackCat {
    meta:
        author = "ditekSHen"
        description = "Detects BlackCat ransomware"
        cape_type = "BlackCat Payload"
    strings:
        $x1 = "{\"config_id\":\"\",\"public_key\":\"MIIBIjANBgkqhkiG9w0BAQEFAAO" ascii
        $x2 = "C:\\Users\\Public\\All Usersdeploy_note_and_image_for_all_users=" fullword ascii
        $s1 = "encrypt_app::windows" ascii
        $s2 = /locker::core::os::windows::(desktop_note|self_propagation|privilege_escalation|psexec|shadow_copy)/ ascii
        $s3 = "uac_bypass::shell_exec=" ascii
        $s4 = "-u-p-s-d-f-cpropagate::attempt=" ascii
        $s5 = "masquerade_peb" ascii
        $s6 = "RECOVER-${EXTENSION}-FILES.txt" ascii
        $s7 = ".onion/?access-key=${ACCESS_KEY}" ascii
        $s8 = "-vm-killno-vm-snapshot-killno-vm-kill-" ascii
        $s9 = "esxi_vm_killenable_esxi_vm_snapshot_killstrict_" ascii
        $s10 = /enum_(shares|servers)_sync::ok/ fullword ascii
        $s11 = "hidden_partitions::mount_all::mounting=" ascii
        //bcdedit /set {default}bcdedit /set {default} recoveryenabled No
        //kill_all::found=
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and (all of ($x*) or 5 of ($s*) or (1 of ($x*) and 3 of ($s*)))
}
