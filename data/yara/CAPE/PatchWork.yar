rule PatchWork
{
    meta:
        description = "PatchWork"
        author = "@avman1995"
        reference = "https://app.any.run/tasks/7ef05c98-a4d4-47ff-86e5-8386f8787224"
        date = "2019/01"
        maltype = "APT"
        cape_type = "PatchWork Payload"

    strings:
        $string1 = "AppId"
        $string2 = "AXE: #"
        $string3 = "Bld: %s.%s.%s"
        $string4 = "%s@%s %s"
        $string5 = "c:\\intel\\"

    condition:
        all of ($string*)
}