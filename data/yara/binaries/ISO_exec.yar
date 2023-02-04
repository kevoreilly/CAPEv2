rule ISO_exec
{
    meta:
        id = "2QhuTkbDSP1KGwZGeesrla"
        fingerprint = "27b4636deff9f19acfbbdc00cf198904d3eb630896514fb168a3dc5256abd7b4"
        version = "1.0"
        first_imported = "2022-07-29"
        last_modified = "2022-07-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies execution artefacts in ISO files, seen in malware such as Bumblebee."
        category = "MALWARE"

strings:
       $ = "\\System32\\cmd.exe" ascii wide nocase
       $ = "\\System32\\rundll32.exe" ascii wide nocase
       $ = "OSTA Compressed Unicode" ascii wide
       $ = "UDF Image Creator" ascii wide

condition:
       uint16(0) != 0x5a4d and 3 of them
}
