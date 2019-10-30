// Copyright (C) 2010-2014 Cuckoo Foundation.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

// The contents of this file are Yara rules processed by procmemory.py processing
// module. Add your signatures here.
rule DridexCfgBotID
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dridex Bot ID"
		malfamily = "dridex"

    strings:
        $buf = /(\<cfg net)?=\"\d+\"\shash=.*bottickmin=\"\d+\"\sbottickmax=\"\d+\"\snodetickmin=\"\d+\"\snodetickmax=\"\d+\"\sport=\"\d+\"\sstatus=\"\d+\"\sbuild=\"\d+\"\>/s

    condition:
        $buf
}

rule DridexCfgNodeList
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dridex node list"
		malfamily = "dridex"

    strings:
        $buf = /\<node\>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\<\/node\>/s

    condition:
        $buf
}

rule DridexCfgKeylog
{
    meta:
        author = "KillerInstinct"
        description = "Configuration element for Dridex keylogger"
		malfamily = "dridex"

    strings:
        $buf = /\<latest.*\keylog=.*\/\>/s

    condition:
        $buf
}

