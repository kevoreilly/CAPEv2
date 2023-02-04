rule VMProtectStub
{
meta:
	description = "Identifies VMProtect packer stub."
	author = "@bartblaze"
	date = "2020-05"
	tlp = "White"

strings:
$ = ".?AV?$VirtualAllocationManager@VRealAllocationStrategy@@@@" ascii wide
$ = ".?AVEncryptedFastDllStream@@" ascii wide
$ = ".?AVGetBlock_CC@HardwareID@@" ascii wide
$ = ".?AVHookManager@@" ascii wide
$ = ".?AVIDllStream@@" ascii wide
$ = ".?AVIGetBlock@HardwareID@@" ascii wide
$ = ".?AVIHookManager@@" ascii wide
$ = ".?AVIUrlBuilderSource@@" ascii wide
$ = ".?AVIVirtualAllocationManager@@" ascii wide
$ = ".?AVMyActivationSource@@" ascii wide

condition:
	2 of them
}
