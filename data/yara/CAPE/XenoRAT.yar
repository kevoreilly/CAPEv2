rule XenoRAT {
    meta:
        author = "jeFF0Falltrades"
        cape_type = "XenoRAT payload"
    strings:
        $str_xeno_rat_1 = "xeno rat" wide ascii nocase
        $str_xeno_rat_2 = "xeno_rat" wide ascii nocase
        $str_xeno_update_mgr = "XenoUpdateManager" wide ascii
        $str_nothingset = "nothingset" wide ascii 
        $byte_enc_dec_pre = { 1f 10 8d [4] (0a | 0b) }
        $patt_config = { 72 [3] 70 80 [3] 04 }
    condition:
        4 of them and #patt_config >= 5
 }
