rule Kinsing {
    meta:
      author = "ditekshen"
      description = "Kinsing RAT payload"
      cape_type = "Kinsing payload"
    strings:
      $s1 = "backconnect" ascii
      $s2 = "connectForSocks" ascii
      $s3 = "downloadAndExecute" ascii
      $s4 = "download_and_exec" ascii
      $s5 = "masscan" ascii
      $s6 = "UpdateCommand:" ascii
      $s7 = "exec_out" ascii
      $s8 = "doTask with type %s" ascii
   condition:
      uint16(0) == 0x457f and 6 of them
}
