rule RemoteUtilitiesRAT {
    meta:
      author = "ditekshen"
      description = "RemoteUtilitiesRAT RAT payload"
      cape_type = "RemoteUtilitiesRAT payload"
    strings:
      $s1 = "rman_message" wide
      $s2 = "rms_invitation" wide
      $s3 = "rms_host_" wide
      $s4 = "rman_av_capture_settings" wide
      $s5 = "rman_registry_key" wide
      $s6 = "rms_system_information" wide
      $s7 = "_rms_log.txt" wide
      $s8 = "rms_internet_id_settings" wide
    condition:
      uint16(0) == 0x5a4d and 4 of them
}
