rule Themida
{
    meta:
        author = "kevoreilly"
        description = "Themida detonation shim"
        cape_options = "unhook-apis=NtSetInformationThread,force-sleepskip=0"
        packed = "6337ff4cf413f56cc6c9a8e67f24b8d7f94f620eae06ac9f0b113b5ba82ea176"
    strings:
        $code = {FC 31 C9 49 89 CA 31 C0 31 DB AC 30 C8 88 E9 88 D5 88 F2 B6 08 66 D1 EB 66 D1 D8 73 09}
    condition:
        uint16(0) == 0x5A4D and all of them
}
