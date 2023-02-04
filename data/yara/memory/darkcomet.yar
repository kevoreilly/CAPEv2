// Copyright (C) 2015 KillerInstinct
// The contents of this file are Yara rules processed by procmemory.py processing
// module. Add your signatures here.
rule DarkCometConfig
{
    meta:
        author = "KillerInstinct"
        description = "Configuration for DarkComet"
		malfamily = "darkcomet"

    strings:
        $buf = /#BEGIN\sDARKCOMET[A-Za-z0-9\r\n\s\-\=\_\{\}\.:\\\/]*\#EOF\sDARKCOMET\sDATA\s--/s

    condition:
        $buf
}
