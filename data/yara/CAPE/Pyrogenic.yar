rule Pyrogenic {
    meta:
      author = "ditekshen"
      description = "Pyrogenic/Qealler infostealer payload"
      cape_type = "Pyrogenic payload"
    strings:
      $s1 = "bbb6fec5ebef0d93" ascii wide
      $s2 = "2a898bc98aaf6c96f2054bb1eadc9848eb77633039e9e9ffd833184ce553fe9b" ascii wide
      $s3 = "addShutdownHook" ascii wide
      $s4 = "obfuscated/META-INF/QeallerV" ascii wide
      $s5 = "globalIpAddress" ascii wide
    condition:
      all of them
}
