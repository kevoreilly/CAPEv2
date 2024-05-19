### [11.04.2024]
* Monitor updates:
    * YARA upgrade to 4.5.0 (& disabled assertion dialogs)
    * Enable 64-bit 'native' hooks to avoid SSN overwriting
    * Expand YARA options to allow offsets relative to the end of a pattern to be specified using asterisk (e.g. bp0=$code*+6)

### [25.03.2024]
* Bypass for variant of Heaven's Gate direct syscall seen in ecrime loader
* Monitor updates: misc fixes (see capemon repo for details)

### [20.03.2024]
* Formbook: ntdll remap bypass & config extraction updates
* Monitor update: Trace GetRegister() tweak

### [15.03.2024]
* Monitor update: Further unpacker refinement: Improve filter for unwanted .NET payloads to avoid missing interesting payloads

### [14.03.2024]
* Monitor update: Unpacker refinement for e.g. Shikata Ga Nai - thanks @para0x0dise

### [12.03.2024]
* Monitor update: Initial IPv6 support - thanks @cccs-mog
* Linux support details can be seen in this [Pull Request](https://github.com/kevoreilly/CAPEv2/pull/2001)
* We remove all `x.conf` to finish the mess with the configs.
    * DO NOT EDIT `.conf.default` files. cape2.sh makes a copy of them removing `.default`.
    * If you don't use `cape2.sh`.
        * Run: `for filename in conf/default/*.conf.default; do cp -vf "./$filename" "./$(echo "$filename" | sed -e 's/.default//g' | sed -e 's/default//g')";  done`

### [07.03.2024]
* Monitor updates:
    * Countermeasure for NtCreateUserProcess block-non-Microsoft-DLLs mitigation policy affecting monitoring
    * Expand 'syscall' breakpoints to handle indirect syscalls (sysbpmode=1)
    * Small fixes & improvements
* Pikabot detection update & anti-hook bypass

### [29.02.2024]
* TLP fields added to distributed database. Requires db upgrade: `cd utils/db_migration_db && alembic upgrade head`
* Monitor fixes

### [28.02.2024]
* Add 'ShellWindows' COM object injection mechanism (e.g. Latrodectus MSIs)
* Monitor: add option to disable ntdll remap protection: ntdll-remap=0
* Lumma direct systenter unmap crash bypass

### [26.02.2024]
* Monitor updates: Service injection delay for e.g. msi detonation & EnumDisplayDevices hooks & anti-vm (thanks @enzo)
* Updated DarkGate config & payload extraction (thanks @enzo)
* Latrodectus auto-export selection

### [23.02.2024]
* Monitor updates: Debugger/Trace enhancements

### [14.02.2024]
* Monitor update: Protect NtFreeVirtualMemory hook against spurious pointer values (e.g. f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2)

### [08.02.2024] CAPA 7 + CAPE
* [CAPA](https://github.com/mandiant/capa) allows to generate a summary of CAPE's analysis. This gives quick abstract summary of analysis. More details [CAPA v7 blogpost](https://www.mandiant.com/resources/blog/dynamic-capa-executable-behavior-cape-sandbox)
* Monitor update: Fix logging bug causing rare buffer overflows (e.g. 780be7a70ce3567ef268f6c768fc5a3d2510310c603bf481ebffd65e4fe95ff3)

### [05.02.2024]
* PhemedroneStealer config extractor - thanks @tccontre18 - Br3akp0int

### [31.01.2024]
* Monitor update: Protect 64-bit hooks against unaligned stack (e.g. 780be7a70ce3567ef268f6c768fc5a3d2510310c603bf481ebffd65e4fe95ff3)

### [24.01.2024]
* Monitor update: Improve handling of irregularly mapped PE images (e.g. from 7911e39e07995e3afb97ac0e5a4608c10c2e278bef29924ecc3924edfcc495ca)

### [23.01.2024]
* Monitor updates:
    * PE dumping refinements for small PEs
    * Debugger: don't trace rundll32 entry point for dlls submitted with bpX=ep

### [18.01.2024]
* Monitor update: Harden against volatile register anti-hook technique in e.g. AgentTesla (thanks @ClaudioWayne)

### [10.01.2024]
* Monitor updates:
    * Further process dump filter hardening
    * Fix dotnet cache dumps

### [05.01.2024]
* Monitor updates: fix a couple of issues affecting detonation (see capemon repo for details)

### [08.12.2023]
* Monitor updates:
    * Expand procdump config option to allow forced procdumps irrespective of code section changes (procdump=2)
    * Improve dumping of images with missing section addresses (e.g. VMP)

### [07.12.2023]
* Monitor update: fix bug in dumping malformed PEs

### [05.12.2023]
* Monitor updates:
    * Process dump filter enhancements & fix
    * Enhanced checks (parent process path) for service hookset assignment
    * Misc fixes

### [04.12.2023] IPinfo.io database integration
* Introduce support for IPinfo.io database. You can download database [here](https://ipinfo.io/account/data-downloads).
* To enable it:
    * `conf/processing.conf` -> `network` -> `country_lookup = yes` and point `maxmind_database` to proper file.

### [30.11.2023]
* Monitor update: Fix bug affecting some process dumps

### [29.11.2023] Unify download services
* Virustotal config moved from `auxiliary.conf` to `web.conf` under `download_services`

### [24.11.2023]
* AsyncRAT config parser overhaul
* Monitor update: Debugger tweaks

### [17.11.2023]
* Monitor update: Debugger fixes & enhancements (action target registers can be pointers when within [], e.g. action2=string:[esp])

### [14.11.2023]
* Monitor update: Small detonation fix
* Formbook detonation & config tweaks

### [7.11.2023]
* Monitor updates: Misc debugger tweaks
* XWorm config extraction

### [3.11.2023]
* Monitor updates:
    * New debugger actions: 'setsrc' & 'setdst' to set values pointed at by instruction operands
    * Improve filtering of uninteresting process dumps
    * Misc fixes/improvements

### [1.11.2023] ZPAQ Support
* __ACTION REQUIRED__
    * `sudo apt install zpaq`
    * as cape user: `poetry install`

### [20.10.2023]
* Monitor fixes: address new issue affecting procdump and add check in compileMethod hook

### [19.10.2023]
* Monitor update:
    * Unpacker: reduce/filter unwanted .NET payloads

### [13.10.2023]
* Formbook updates
* Monitor updates:
    * NtContinueEx hook
    * Debugger action enhancements: setptr, patch, sleep, exit
    * Software breakpoint handler enhancement
    * Misc fixes/improvements

### [11.10.2023]
* Formbook config extraction
* Monitor updates:
    * GetComputerNameExW hook added, PostThreadMessage hook enhancement
    * Debugger action enhancements
    * Misc fixes

### Download files matched by YARA
* When doing search by `capeyara` we expose button to download files that only matches that search criteria.
    * For [@fumik0_](https://twitter.com/fumik0_) with love.

### [22.9.2023] CSRF changes
* __IMPORTANT__. If you using __https__ please update config to use new field for __CSRF__ in `conf/web.conf`.
    * Before: `[general]` -> `hostname`.
    * Now: `[security]` -> `csrf_trusted_origins`

### [19.9.2023]
* Storage of file data in MongoDB
    * Store the parts of a report's file data that is independent of a detonation in a separate collection
      to conserve disk space.
* __ACTION REQUIRED__
    * It is recommended to add a regular cron job to call `cd /opt/CAPEv2 && sudo -u cape poetry run python ./utils/cleaners.py --delete-unused-file-data-in-mongo`
      to prune these entries that are no longer needed.

### [13.9.2023]
* Monitor updates:
    * .NET JIT native cache handling improvements
    * New debugger action 'string' to capture decrypted strings
    * Fix issue in procname_watch_init() with non-null-terminated unicode paths - thanks Proofpoint for the report

### [8.9.2023]
* Monitor update:
    * .NET JIT native cache scanning & dumping

### [1.9.2023]
* Monitor updates:
    * Fix missing browser hooks config setting for Edge & Chrome
    * Trace: add config option to try and skip loops which flood trace logs (loopskip=1)

### [25.8.2023]
* Monitor update: Upgrade monitor Yara to 4.3.2 (thanks Michael Weiser)

### [19.8.2023]
* Monitor update: fix memcpy hook logging issue

### [16.8.2023]
* Monitor updates:
    * Filter uninteresting process dumps via new VerifyCodeSection() function checking code section for modification
    * Fix issue with process path-based options being set too late (after yara init)
    * YaraScan: do not call SetInitialBreakpoints() unless DebuggerInitialised flag is set

### [10.8.2023]
* Monitor updates:
    * Fix for NtQueueApcThread hook: do not send thread handle in 'process' message
    * Add WmiPrvSE.exe to services hookset to fix Win10 WMI/interop detonation issues

### [8.8.2023]
* Minimal YARA version now is 4.3.1
* `file_extra_info` modules autoload, see example in `lib/cuckoo/common/file_extra_info_modules`
* Initial compatibility with x64 python version in guests.
* In `agent.py` add `is_admin` value.

### [5.8.2023]
* New anti-direct-syscall feature: 'syscall breakpoints' (64-bit only)
    * redirect syscalls back through traditional hooks
    * via monitor yara & updated monitor
* Monitor updates:
    * Unpacker: add dumping of decrypted PEs from CryptDecrypt(), NCryptDecrypt(), BCryptDecrypt()
    * NtOpenProcessToken, NtQueryInformationToken, RtlWow64GetThreadContext hooks
    * Syscall breakpoint implementation (64-bit)
    * Fix hook issues with NtQueueApcThread, GetWriteWatch
    * Misc fixes & improvements (see capemon repo for details)

### [31.7.2023] Prescan feature
* Allows to scan all new file tasks with YARA. Must be enabled in `web.conf` -> `[general]` -> `yara_recon`.
    * This allows you to set CAPE arguments, as tags for example for proper VM pickup.
    * YARA name must ends with `Crypter`, `Packer`, `Obfuscator` or `Loader` and have `cape_name` and `cape_options` in meta. Example:
    * See `def recon` in `CAPEv2/lib/cuckoo/common/web_utils.py`
```
rule X_cryptor {
    meta:
        author = "doomedraven"
        description = "New X Crypter"
        cape_type = "New X Crypter"
        cape_options = "tags=win10"
    strings:
        $a = "New awesome crypter <3" fullword
    condition:
        $a
}
```

### [28.7.2023]
* Syscall hooks now enabled by default
* Monitor updates:
    * improved syscall hook logging, unpacker & debugger integration
    * new debugger actions "call" & "setbpX"
    * misc improvements

### [18.7.2023]
* FLARE CAPA v6 support. Is now uniq supported version. They doing breaking changes.

### [14.7.2023]
* Monitor update: Add hook for LoadLibraryExW

### [7.7.2023]
* UPX-type dynamic unpacker in yara sig
* Monitor updates:
    * New debugger action 'Step2OEP' for packers like UPX
    * Deprecate obsolete UPX unpacker code
    * misc improvements & fixes

### [24.6.2023] EuskalHack feature
* .inf detonation. Requires `sflock2==0.3.50`
* New admin/admin.py - Cluster edition - [Documentation](https://capev2.readthedocs.io/en/latest/usage/cluster_administration.html)
* New dependency. Run `cd /opt/CAPEv2 && poetry install`
*
### [19.6.2023]
* Monitor update: misc improvements & fixes

### [13.6.2023]
* Monitor update: fix issue with Microsoft Edge not launching properly (#1587)

### [5.6.2023]
* Stealc detection update
* Monitor update: Fix NtWriteFile hook issue by removing critical sections - thanks to @RazviOverflow for report

### [30.5.2023]
* Monitor updates:
    * Add GetWriteWatch & UpdateProcThreadAttribute hooks which allow Pikabot detonation - thanks @enzok!
    * CoCreateInstance(Ex) hook improvements - thanks @heck-gd!
    * PostThreadMessage hooks - thanks @nblog!
* PikaBot detection update

### [29.5.2023]
* URL default analysis package selection in web.conf
* SQLAlchemy2 migration started
* MSIX extract

### [21.4.2023]
* Fix issue with Rhadamanthys & BumbleBeeLoader FPs due to monitor sigs in process dumps
* Monitor update: Debugger hardening & new actions

### [21.4.2023]
* Monitor updates: Misc fixes (see capemon repo) & hooks for CreateProcessA/W to reduce noise

### [6.4.2023]
* Monitor update: Add hook for WinExec()

### [5.4.2023] Configs make easier
* Simplifing the configuration
    * Do NOT edit any config that ends on `.default` as it will be default config.
    * For more details read readme inside of `conf` folder.

### [30.3.2023]
* RedLine config extraction - thanks @Gi7w0rm
* Monitor fixes:
    * Harden GetExportAddress() against malformed PE images
    * Add fallback payload metadata in ProcessTrackedRegions

### [21.3.2023] Syscall Hooks
* New feature (beta):
    * Syscall hooks on Win10+ (via InstrumentationCallback) via submission checkbox or option: syscall=1
* Ursnif/ISFB detection & config extraction update

### [17.3.2023]
* Monitor fixes:
    * Unpacker: Improve ProcessTrackedRegion() to allow yara scans of mapped modules
    * Disable sleep skips prior to thread creation (rather than after) and upon CoCreateInstance (WMI etc)

### [16.3.2023] Loggers
* New config `conf/logging.conf`. Remember to copy it to `custom/conf/logging.conf` for moddifications.
    * Syslog handler for `cuckoo.py` and `process.py` can be on/off in config. Useful for global monitoring tools or cloud setups.
    * Allow to create logs per analysis in analysis folder. Useful for distributed setup to show on webgui if enabled and have logs in main server.

### [10.3.2023]
* Monitor fixes:
    * Prevent unpacker initialisation from adding imagebase to tracked regions, allow yara scans on caller
    * CoGetClassObject hook: remove modification of dwClsContext parameter causing detonation failures

### [9.3.2023]
* Monitor updates:
    * Remove cryptsp 'double' hooks in Office processes due to detonation failures (e.g. Word 2016)
    * Prevent following child processes of WerSvc (to prevent werfault.exe producing mini dumps that are detected by yara due to in-memory monitor sigs)

### [8.3.2023]
* Virtual machine tags: For Windows only. Please set windows version in tag, any of: winxp, win7, win8, win10, win11.
    * This is required for proper detonation for packages like MsiX.
* New feature. In `web.conf` there is section `[packages]`:
    * It allows to create new packages and push them to correct VMs.
    * Or in case you want to detonate some of the packages only on specific VMs you can specify it there like: `package:vm_tag1,vm_tagX`
* MsiX file proper recognization requires upgrade to `sflock2==0.3.48`, otherwise it will push it as zip or extract and add each file as separated job.

### [1.03.2023]
* Msix/MsixBundle package works only on Windows >= 10
* Quarantine is integrated into normal file submission so you don't need to know if file is normal or quarantined.

### [24.2.2023] CAPE 2.4: 🌻 Edition
* New Unpacker option: `unpacker=2`
* Deprecated:
    * submitCAPE.py - no more additional jobs
* Staging branch:
    * We want to have CAPE stable. So new features will go to staging branch for 1-2 weeks before merged to master.
    * If you want to help us to spot any possible issue use that branch on your dev side.
* We need help to add as much tests as possible to cover all possible cases to prevent broken code.
* Stop using `conf/` folder. All config should be in `custom/conf/`. This will simplify your life on CAPE updates when new entry added to base templates. [Details](https://github.com/kevoreilly/CAPEv2/blob/master/conf/readme.md)

### [20.2.2023]
* Scheduler update:
    * A machine may be configured with `reserved = yes` in `<machinery>.conf`. For such machines, the scheduler will
      not use it for tasks unless the user specifically requests it by its label.
* Database update:
    * The 'name' of all machines defined in `<machinery>.conf` must be unique. The same goes for their 'label' fields.

### [16.2.2023]
* Monitor update: Hooking engine stability fix for detonation issues (e.g. Word)

### [4.2.2023]
* Monitor updates:
    * Extend svchost hookset to Winmgmt (netsvcs) service
    * Fix for bug in get_full_keyvalue_pathUS() (thanks oalieno)

### [2.2.2023]
* Monitor update: Process dump improvements & 'export' option to allow DLL export to be defined by monitor yara signature

### [1.2.2023]
* Monitor update: Disable spawning WER processes (werfault.exe etc) via RtlReportSilentProcessExit hook

### [30.01.2023]
* Add `utils/fstab.py` utils which is used by `utils/dist.py` when NFS mode is used.
    * Check configure NFS in [documentation](https://capev2.readthedocs.io/en/latest/usage/dist.html):
* Now when you register new server in distributed cluster that uses NFS, it will automatically:
    * Create worker folder
    * Add NFS entry to `/etc/fstab`. Ex:
        * `192.168.1.1:/opt/CAPEv2 /opt/CAPEv2/workers/192.168.1.1 nfs, auto,user,users,nofail,noatime,nolock,intr,tcp,actimeo=1800, 0 0`
    * Mount folder

### [26.1.2023] Configs
* Please read [this](https://github.com/kevoreilly/CAPEv2/blob/master/conf/readme.md) to simplify your life with configs managment

### [25.1.2023]
* Google Cloud Platform (GCP) support in distributed CAPE aka dist.py

### [5.1.2023]
* Big duplicated code cleanup. Context: CAPE.py module processing all the files so it calling File(x).get_all() which is pretty heavy.
* Deprecated standalone modules. They are moved inside of CAPE.py. Data will be under the same keys.
    * Target info
    * Dropped
    * ProcDump
* Url analysis moved to `nodules/processing/url_analysis.py`

### [4.1.2023]
* Monitor update: Fix 32-bit stack recursion hook issue (affecting, for example, golang binaries)

### [28.12.2022] NETReactorSlayer
* Integrated deobfuscator and unpacker for Eziriz .NET Reactor. [Source](https://github.com/SychicBoy/NETReactorSlayer).
    * You need to download version for your CPU and extract it to `data/NETReactorSlayer.CLI`
        * In case if you are on x64 host, then just run: `poetry run python utils/community.py -waf`
    * Add execution permission with `chmod a+x data/NETReactorSlayer.CLI`
* Now each section inside of `selfextract.conf` has timeout value. Default is 60 seconds

### [24.12.2022]
* Monitor updates: Fix NtAllocateVirtualMemoryEx & NtMapViewOfSectionEx hooks and rebuild with Visual Studio 2022

### [2.12.2022]
* Monitor updates: add 32-bit hook compatibility to allow hooking of GetCommandLine APIs (and add GetCommandLineA hook)

### [17.11.2022]
* QakBot config extraction update
* Emotet detection & config extractor updates

### [10.11.2022]
* Monitor fixes:
    * Fixes for CreateTimerQueueTimer hook affecting Emotet detonation
    * Remove function name resolving via ScyllaGetExportNameByAddress() in thread & process hooks due to issues

### [14.11.2022]
* Monitor fixes:
    * hook recursion issue in 64-bit monitor
    * UNICODE_STRING comparison issue in add_all_dlls_to_dll_ranges()

### [7.11.2022]
* Monitor updates: misc fixes & improvements (see capemon repo for details)
* Fix merging of split configs per family in CAPE processing module

### [11.10.2022] Archive package
* [archive package](https://github.com/kevoreilly/CAPEv2/blob/master/analyzer/windows/modules/packages/archive.py) by [@cccs-kevin](https://github.com/cccs-kevin) with a nice talk explaining how to detonate some kind of malware properly [here](https://youtu.be/-70Mlkmtdds?t=13013). Thank you Kevin and CCCS team for this contribution. [Documentation](https://capev2.readthedocs.io/en/latest/usage/packages.html).

### [6.10.2022]
* Some not core dependencies are commented out and won't be installed anympore by default.
* Our idea is to leave CAPE core with core dependencies to avoid conflicts with another libraries.

### [1-10-2022]
* Monitor update: GetSystemInfo anti-vm improvement & 64-bit hooking engine fix

### [24-9-2022]
* Monitor update: Per-api total cap (api-cap=X) and Javascript (wscript) hookset

### [17-9-2022]
* Monitor update: misc fixes (see capemon repo for details)

### [12-9-2022]
* Monitor update: TLSdump on Win10 & other improvements (see capemon repo for details)

### [2-9-2022]
* Monitor update: Fix issue with incorrect prototype for NtCreateThreadEx hook

### [28-08-2022] [Maco - Malware config extractor framework](https://github.com/CybercentreCanada/Maco)
* [MACO foramt for malware configs](https://github.com/kevoreilly/CAPEv2/pull/1037)

### [26-08-2022]
* [Interactive mode](https://github.com/kevoreilly/CAPEv2/pull/1065) thanks to @enzok based on his [guac-session](https://github.com/enzok/guac-session/). [Docs](https://capev2.readthedocs.io/en/latest/usage/interactive_desktop.html)

### [18-8-2022]
* Function `yara_detected` now returns 4 arguments. 4th is file metadata

### [17-8-2022]
* Monitor updates:
    * Enable enhanced .NET dumps
    * Misc updates & fixes (see capemon repo)

### [30-7-2022]
* [Details here](https://github.com/kevoreilly/CAPEv2/pull/1020)
* __ACTION REQUIRED__
    * `cd /opt/CAPEv2/utils/db_migration && alembic upgrade head`
    * Restart:
        * CAPE service `systemctl restart cape cape-processor`
        * Web: uwsgi or cape-web

### [15-7-2022]
* Monitor updates:
    * MSI detonation (Win10)
    * Misc updates & fixes (see capemon repo)

### [11-7-2022]
* FLARE-CAPA fix, you must install it from `GitHub`. Pip version is different.
* FLOSS 2.0 integration.
* BinGraph requires CAPE's version: `poetry run pip install git+https://github.com/CAPESandbox/binGraph`
* `on_demand` fixed.
* __ACTION REQUIRED__
    * Now that CAPA and Floss uses the same signatures we renamed `capa-signatures` to `flare-signatures`
    * `python3 utils/community.py -cr`

### [15-6-2022]
* [Azure machinery](https://github.com/kevoreilly/CAPEv2/pull/922) by @cccs-kevin

### [8-6-2022]
* Use poetry to handle dependencies
    * requirements.txt is still present to continue support for pip
* Added pre-commit hooks
* Add community blocklist to avoid pulling some undesired modules/signatures/etc.

### [10-5-2022]
* Added AWS machinery and ReversingLabs file lookup by @JaminB

### [5-5-2022]
* Monitor updates:
    * Increase GlobalMemoryStatusEx faked return value
    * Loosen requirements in TestPERequirements to allow zero-sized sections
    * Fix issue with missing dropped files (e.g. 64-bit Al-khaser log.txt)
    * Crypto hooks: add buffer length to logs, add dump-crypto to NCrypt APIs & use DumpMemoryRaw()
    * Trace improvements (64-bit set register range and DoStepOver function)
    * Debugger improvements (NoSetThreadContext for Win 10 breakpoints)
    * Fix off-by-one in ReverseScanForNonZero()

### [3-5-2022]
*  lnkparse3 integration

### [20-4-2022]
* Emotet E5 update
* Monitor updates:
    * New hooks: LdrGetProcedureAddressForCaller, GetCommandLineW
    * Fix issue with payload metadata incorrectly set in certain conditions

### [19-4-2022]
* Emotet E4 update (new 64-bit)

### [1-4-2022]
* Monitor update: Fix issue with attempted dll load notifications in tlsdump mode causing lsass to crash

### [31-3-2022]
* Monitor updates:
    * dump-crypto option: add dumping of Bcrypt encrypt/decrypt apis
    * Add general typestring to options, overrides type codes

### [28-3-2022]
* Monitor: Fix issue causing some exceptions in VirtualProtectEx and NtProtectVirtualMemory hooks
* Unittests for core enabled on GitHub. Please help us cover as much as we can to make CAPE more stable than never.

### [16-3-2022]
* Monitor updates:
    * Add 'Unwind' debugger action for x86
    * Fix for NtCreateThreadEx hook not initialising thread breakpoints
    * Filter dlls alongside target process executable in add_all_dlls_to_dll_ranges()
    * Fix issues with WriteMemoryHandler invocation in hooks, update NtWow64 function prototypes
    * Show dll load notifications in behavior log, use already_hooked() on load check
    * Add module name to debugger log exception output
    * Do RestoreHeaders() at end of init
    * Add Yara logging switch

### [4-3-2022]
* Rewritten detection.
    * Now if you have many different detections it will show all of them, not only 1. Details about each detection is in CAPE signature
    * This is not backward compatible feature, so search won't return old matches

### [2-3-2022]
* Emotet updates

### [23-2-2022]
* Loader update: fix check for previous IAT patch with corrected size (fixes #748 - Obsidium packers)
* PlugX updates
* Emotet updates

### [20-02-2022] [UnAutoIt](https://github.com/x0r19x91/UnAutoIt) by @x0r19x91
* You need to compile it by yourself and put binary under `/opt/CAPEv2/data/UnAutoIt`
```
cd /opt/CAPEv2/data/
snap install go --classic
git clone https://github.com/x0r19x91/UnAutoIt && cd UnAutoIt
GOOS="linux" GOARCH="amd64" go build -o UnAutoIt
```

### [19-02-2022] [Detect It Easy](https://github.com/horsicq/Detect-It-Easy/) by @horsicq
* To install it you can download installer from [here](https://github.com/horsicq/DIE-engine/releases)
```
sudo apt install libqt5opengl5 libqt5script5 libqt5scripttools5 -y
wget "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_${UBUNTU_VERSION}_amd64.deb" -O DIE.deb
sudo dpkg -i DIE.deb
```

### [18-02-2022] Depricate static
* To be able to generate the same info as was generated for initial binary under static tab. We decided to depricate static module and make it reusable for any other files like dropped, downloaded, etc.
* So now you will be able all file static info on each file to speedup your analysis

### [15-2-2022]
* Monitor updates:
    * Do not call notify_successful_load() if tlsdump mode (avoid lsass being added to analyzer process list)
    * Fix: ensure module (ntdll) is writeable before calling restore_hooks_on_range()

### [13-02-2022] PEEPDF
* [peepdf](https://github.com/CAPESandbox/peepdf) isn't installed anymore by default, python3 version is pretty buggy, so if you want to fix it you are more than welcome!

### [7-2-2022]
* Monitor updates:
    * Add hooks for NtAllocateVirtualMemoryEx, NtMapViewOfSectionEx, NtUnmapViewOfSectionEx (Win10+)
    * Extend ntdll protection to cover VirtualProtectEx, make more stealthy

### [5-02-2022] Config extractors
* Make standard file key for all `path` keys. No more: `file`, `path`, etc. Now just `x["path"]`
* MWCP, malwareconfigs, and malduck are not part of requirements.txt anymore! They bring their own dependencies that not everyone needs. If you enable that framework in processing.conf you need to install that dependencies.
    * TIP: You need to figurate the proper version(is another reason why we abondone them)
        * `poetry run pip install git+https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP`
        * `poetry run pip install git+https://github.com/kevthehermit/RATDecoders`
        * `poetry run pip install git+https://github.com/CERT-Polska/malduck/`
* `PyCrypto` replaced with [PyCryptoDoMeX](https://pycryptodome.readthedocs.io/en/latest/src/installation.html)
* __ACTION REQUIRED__
    * `poetry run pip install pycryptodomex==3.14.0`
    * Restart:
        * CAPE service `systemctl restart cape-processor`

### [4-2-2022]
* Monitor updates:
    * Dump-on-API bug fix
    * YaraHarness: fix issue with delta variable
    * End yara later during shutdown
    * Prevent unloading core modules (fix #531)
    * New crypto hooks: CryptDeriveKey, CryptDestroyKey, CryptDestroyHash
    * YaraInit: log number of loaded sigs rather than a list
    * Debugger push & pop actions
    * WriteMemoryHandler: tiny code clean
    * CreateProcessHandler: improve logging
    * Fix evasion techniques reported by (& many thanks to) Alexey Bukhteyev of Checkpoint, [writeup](https://research.checkpoint.com/2022/invisible-cuckoo-cape-sandbox-evasion/)
* Update 'GetTickCount' anti-vm bypass with latest IcedID packers

### [26-1-2022]
* Config extension, for short details see [PR](https://github.com/kevoreilly/CAPEv2/pull/724) or full [read docs](https://capev2.readthedocs.io/en/latest/installation/host/configuration.html)

### [20-1-2022]
* MongoDB abstraction for easier upgrades when they depricate some apis + code cleanup

### [19-1-2022]
* Monitor: PE dumping more tolerant of inaccessible sections (e.g. recent Emotet)
* Updates for latest Emotet Epoch 4

### [8-1-2022]
* Feature: AMSI dumps (enabled by default for Win10+)

### [17-12-2021]
* Monitor: x64 debugger updates & improvements
* Al-khaser bypass
* ElasticSearch to store reports support by @CorraMatte

### [22-12-2021]
* Add new field to DB `arch`. To avoid problems with pendings tasks when user didn't read config and set tags
* If you using `dist.py` ensure next:
    * If you have `x64` and `x86` VMs:
        * `x64` VMs should have both `x64` and `x86` tags. Otherwise only `x64` tag
    * `x86` VMs should have only `x86` tag.
    * You can use any other tags, just to work properly you need those two.
    * Tags requires update in `machine` table in distributed database if your server contains only x64 VMs.
    * Probably will be improved in future for better solution
* __ACTION REQUIRED__
    * `cd /opt/CAPEv2/utils/db_migration && alembic upgrade head`
    * Restart:
        * CAPE service `systemctl restart cape`
        * Web: uwsgi or cape-web

### [14-12-2021]
* Monitor: Add Add debugger actions: 'nop' and 'wret' to patch instructions with nop and ret
* Yara dynamic bypass for latest Emotet packer anti-vm trick

### [11-12-2021]
* Monitor: Add RDTSCP NOP option as alternative for when emulation is too slow (and timestamp counter value not needed)
* Yara signature to enable RDTSCP NOP dynamically for recent Emotet/ISFB packers

### [07-12-2021] Decode them all
* VBE/JSE/BATCH decoded and shown on WebGui
* __ACTION REQUIRED__
    * `poetry run pip install -U git+https://github.com/DissectMalware/batch_deobfuscator`
* Monitor: Add support for parent pid in payload capture (thanks to Intezer)

### [02-12-2021] - API changes
* We spot that pyzipper adds huge overhead specially to distributed cape.
* Repors now are just zips, screens also now zips, anything that is not contains malicious code is just pure zip, the rest is keeps the same.

### [01-12-2021]
* Monitor: Bcrypt hooks, disable yara scans in IE, silent rdtscp emulation, other misc tweaks

### [23-11-2021]
* Integrate [Kixtart-Detokenizer](https://github.com/jhumble/Kixtart-Detokenizer)
* Simplify integration of another tools to unpack/extract files

### [18-11-2021]
* Add [RichHeader](https://github.com/RichHeaderResearch/RichPE) MD5
* Improve Suricata family detection
* Extract strings on demand feature

### [08-11-2021]
* Monitor: rdtscp emulation, optional exception & breakpoint logging

### [04-11-2021]
* Move Office hook options from packages to monitor
* Monitor: Disable NtWaitForSingleObject hook for 32-bit Windows 8+ due to crashes

### [03-11-2021]
* Add MongoDB multifield index for all SHA256 fields.
    * if you using any other fields for frequent lookup, add indexes for that on your side to speedup database

### [01-11-2021]
* Allow download reports as zip via API
* Fix python analysis support in Windows

### [22-10-2021]
* POC: AntiRansomware:
    * Can be enabled in `processing.conf` it will disable processing of files with extensions that are not in allowed list, see `modules/processing/antiransomware.py`
    * Specially useful to disable them in CAPE.py that gather all the metadata, yara etc and can consume a lot of ram

### [21-10-2021]
* Monitor update: Monitor fix for scan crashes in e.g. Equation Editor/Cmd (thanks Will)

### [19-10-2021]
* Monitor update: Monitor fix for NtSuspendThread hook issue (thanks Intezer)

### CENTS - Configuration Extraction to Network Traffic Signatures
* For full description [read](https://github.com/kevoreilly/CAPEv2/pull/605)

### [17-10-2021]
* Monitor update: Win10x64 deadlock fix & other misc fixes (see capemon repo for details)

### [2-10-2021] Hacktoberfest
* Add test module to extraction framework to ensure that they are loaded properly: CAPE, MWCP, RATDecoders, Malduck
* Monitor update: Fixes/hardening of dumps (PE & memory) and yara scans (e.g. SquirrelWaffle)
* Handled errors that was giving problem to use `init_yara` sometime, used in Qakbot extractor
    * `OSError: /opt/CAPEv2/lib/cuckoo/common/blzpack_lib.so: failed to map segment from shared object`
* Bingraph:
    * matplotlib `forward` deprication fixed
    * moved to external dependency, we host CAPE's version here https://github.com/CAPESandbox/binGraph.
    * __ACTION REQUIRED__
        * `poetry run pip install -U git+https://github.com/CAPESandbox/binGraph`


### [23-09-2021]
* Monitor update: Add CLSIDs and IsValidUrl hook for CVE-2021-40444

### [22-09-2021]
* SquirrelWaffle detection & config extraction
* Monitor improvements:
    * Dumping stability improvements (ScanForDisguisedPE, IsDisguisedPEHeader, DumpMemory, DumpRegion)
    * Add config option to allow enable/disable scans/dumps while loader lock held
    * Monitor updates: dump/scan stability improvements, configurable loader lock scans/dumps, window hook fixes

### [14-09-2021]
* Update Lockbit yara sig
* Update Bazar yara sig
* We spot that some extractors only works with `mwcp==3.2.1`, requirements updated
* FLARE-CAPA v3

### [11-09-2021]
* Monitor improvements:
    * Restrict debugger breakpoint protection to current process (NtSetContextThread)
    * Limit "Dropped file limit reached" messages to just one per process

### [02-09-2021]
* Monitor fixes:
    * Some dropped files being missed (file_handle_terminate())
    * Disable ntdll write-protection for Office processes

### [06-09-2021]
* Sflock update with more PE checks, as in many cases PE has other formats strings inside
* __ACTION REQUIRED__
    * `poetry run pip install -U sflock2`

### [02-09-2021]
* Monitor: Remove case-sensitivity from check for dll path (e.g. Hancitor maldoc-spawned dlls)

### [28-08-2021]
* Monitor: revert changes to IsPeImageRaw() while crashes (e.g. BazarLoader) are investigated

### [25-08-2021]
* __ACTION REQUIRED__
    * `poetry run pip install -U pyattck`

### [19-08-2021]
* Move office settings from package options to in-monitor (automatic)
* Fix issue with tlsdump/lsass being assigned 'first process' in analyzer
* Usage graph moved to under statistics block

### [18-08-2021]
* Monitor update: stability fixes (window hooks, ...) & debugger improvements

### [11-08-2021]
* Distributed. Master node stop picking pending tasks when `node=X` is specified and master_storage_only=False

### [10-08-2021]
* Monitor update: Remove unnecessary check in TestPERequirements causing failed PE dumps
* Search by hash now will cover any file in CAPE that contains hash.
    * It searches in binary/Dropped files/CAPE payloads/ProcessDump
    * payloads: md5 <- as example not needed anymore and will be deprecated in next month

### [08-08-2021]
* Monitor update: debugger improvements
* Loader: fix debug output for shellcode start address including offset
* Allow start offsets into shellcode to be set for Shellcode packages (offset=x)

### [07-08-2021]
* Monitor update: fix issue causing occasional crashes on x64 when calling ScyllaGetExportDirectory on apphelp.dll
* XLMMacroDeobfuscator moved to `on_demand`

### [28-07-2021]
* bzip archives was replaced with zip with password, default infected, can be changes in conf/web.conf -> zipped_download -> zip_pwd
    * use 7zip or pyzipper to extract

### [23-07-2021] Distribute task based on route
* Add hability to have different exit nodes on each cape worker in cluster, that will auto pickup proper worker server based on route.
    * To update current nodes details on main db server, do the request with pull request

### [21-07-2021] [Xll support](https://www.fortinet.com/blog/threat-research/signed-sealed-and-delivered-signed-xll-file-delivers-buer-loader)
* __ACTION REQUIRED__
    * `poetry run pip install -U sflock2`

### [07-07-2021] Signature testing
* Allow to execute one specific signature, loading data from mongo or json report. Specially useful for signature based extractors.
    * python3 utils/process.py -r ID -sig -sn cape_detected_threat

### [06-07-2021] [Malduck](https://github.com/CERT-Polska/malduck)
* Integration of part of [mwcfg-modules](https://github.com/c3rb3ru5d3d53c/mwcfg-modules) by [@c3rb3ru5d3d53c](https://github.com/c3rb3ru5d3d53c)

### [05-07-2021]
* Add support for archives in static extraction, so you don't need to submit them one by one

### [20-06-2021] [enter the sandman](https://www.youtube.com/watch?v=CD-E-LDc384) @doomedraven moved to CAPEv2
* Expect more fixes :)

### [17-06-2021]
* Updates to processing module & monitor to allow type strings to replace old type codes
* Updates to 'dump' Debugger action
* Hit counts added to debugger breakpoints

### [17-06-2021]
* add `username` field to be used for custom auth
* __ACTION REQUIRED__ if you using dist.py
    * `cd utils/db_migration && alembic upgrade head`

### [13-06-2021]
* Introdiced checker of available space in process.py to prevent system run out of memory and generate a lot of troubles

### [10-06-2021] dist.py
* Migrates from ht_user/ht_pass to apikey for proper apiv2 integration
* __ACTION REQUIRED__ if you using dist.py
    * `cd utils/db_migration_dist && alembic upgrade head`

### [09-06-2021] RAMFS renamed to TMPFS
* As TMPFS is better and modernish, and it was a naming typo

```
# only if you using volatility to speedup IO
mkdir -p /mnt/tmpfs
mount -t tmpfs -o size=50g tmpfs /mnt/tmpfs
chown cape:cape /mnt/tmpfs
vim /etc/fstab
tmpfs       /mnt/tmpfs tmpfs   nodev,nosuid,noexec,nodiratime,size=50g   0 0
```

* [ORJson](https://pypi.org/project/orjson/) library is now used for json report if installed
    * orjson is a fast JSON library for Python. It benchmarks as the fastest Python library for JSON. Its serialization performance is 2x to 3x the nearest other library and 4.5x to 11.5x the standard library.

### [07-06-2021] MongoDB auth fixed
* [Example of user/role creation](https://pymongo.readthedocs.io/en/stable/examples/authentication.html)
```
use admin

# To Create root user
use admin
db.createUser(
      {
          user: "username",
          pwd:  passwordPrompt(),   // or cleartext password
          roles: [ "root" ]
      }
  )

# To create user with perm RW on db
db.createUser(
    {
        user: "WORKER_USERNAME",
        pwd:  passwordPrompt(),   // or cleartext password
        roles: [{ role: "readWrite", db: "cuckoo" }]
    }
)
```

### [06-06-2021] Ratelimit strikes again
* Reintroduce ratelimit to control abuses

### [04-06-2021]
* Allow anon users list reports and view them
    * `conf/web.conf ->  general -> anon_viewable`

### [31-05-2021]
* Monitor updates:
    * Fixes for NtCreateProcessEx hook, regsvr32 arg parsing, branch tracing (debugger)
    * Remove instruction filtering from ntdll protection
    * Add more debug logging to YaraHarness

### [15-05-2021]
* Reports download moved to main page, under file info as Strings, VirusTotal, Mitre

### [02-05-2021] [Square Hammer](https://youtu.be/VqoyKzgkqR4)
* Add button to ban user and their pending tasks on admin tab
    * __ACTION REQUIRED!__
        * `cd utils/db_migration/ && alembic upgrade head`
        * `sudo systemctl restart cape.service cape-web.service`

### [01-05-2021]
* Dirty cluster admin utils helper -> `admin/admin.py`, see `-h`

### [28-04-2021]
* Strings tab are under the file info on main page
* VirusTotal tab are also under the file info on main page
* VT apiv3 integrated

### [23-04-2021]
* Pyattck v3.0.1 support
* If you are using alternative location to `/opt/CAPEv2` and wants to use `MITRE TTPs` next action is required:
    * you need to update value of `data_path` in config `data/mitre/config.yml`

### [18-04-2021]
* Move MITRE ATT&CK from tab to collapse table after signatures

### [15-04-2021]
* Allow pass search patter in url: `analysis/search/detections:<family>/`

### [13-04-2021]
* Add example how to add custom auth, see `web/web/middleware.py`

### [06-04-2021] Small performance improvements
* New dependecy `ujson`
    * __REQUIRED ACTION:__ -> `poetry run pip install ujson -U`


### [23-03-2021] API Subscription
* Default 5/m, it can be changed using Django Admin in user profile. ratelimit is deprecated
* This was done with huge help from those writeups
    - [How to add subscription based throtting to django](https://dev.to/mattschwartz/how-to-add-subscription-based-throttling-to-a-django-api-28j0)
    - [How to add custom fields to user profile](https://simpleisbetterthancomplex.com/tutorial/2016/11/23/how-to-add-user-profile-to-django-admin.html)

* __REQUIRED ACTION:__ -> `cd web && python3 manage.py migrate`


### [09-02-2021] Registration more configrations
* Allow enable/disable all new users to activate them by hand
* Disable new users after email verification if set `manual_approve` in `conf/web.conf`
* __REQUIRED ACTION:__ -> `poetry run pip install django-extensions`

### [05-02-2021] Volatility3 integration done, some future optimizations might come later
* ToDo: pass yara file to exec yarascan
* Thanks to Xabier Ugarte-Pedrero and dadokkio for their work
* `poetry run pip install volatility3`, then check
    * `conf/processing.conf` -> `[memory]`
    * `conf/memory.conf` for the plugins

* You will need to download `symbols`, see [volatility3 readme for details](https://github.com/volatilityfoundation/volatility3)

### [03-02-2021]
* ratelimit 4 upgrade -> `poetry run pip install django-ratelimit -U`

### [02-02-2021]
* Link task to user_id, to be able to ban spammers and bad users
* __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/utils/db_migration && alembic upgrade head`
* Instead of Volatility3 integration planned for today you got this, thanks spammers
* If registration enabled, allow to set manual approve of users and set them inactive by default

### [28-01-2021] CAPE 2.3
* APIv2 - [Django REST Framework](https://www.django-rest-framework.org) + [Token AUTH](https://simpleisbetterthancomplex.com/tutorial/2018/11/22/how-to-implement-token-authentication-using-django-rest-framework.html)
    * just replace `/api/` to `/apiv2/` in your urls
* Current API will be removed in future, so move toward new one
* Updated API [documentation](https://capev2.readthedocs.io/en/latest/usage/api.html)
* New dependency: `poetry run pip install djangorestframework`
* __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/web/`
    * `python3 manage.py migrate && python3 manage.py collectstatic`

### [24-01-2021] Disposable email services ban support
* To enable it see `[registration]` in `web.conf`
* List of domains can be placed in `data/safelist/disposable_domain_list.txt`
* Allow enable ReCaptcha for user registration to avoid bots
* Integrated [stopforumspam domain list](https://www.stopforumspam.com/downloads/toxic_domains_partial.txt)

### [21-01-2021] JA3 by Suricata no custom scripts anymore
* `sed -i 's|#ja3-fingerprints: auto|ja3-fingerprints: yes|g' /etc/suricata/suricata.yaml && sudo systemctl restart suricata`

### [20-01-2021]
* [TLSH hashing](https://github.com/trendmicro/tlsh) - Trend Micro Locality Sensitive Hash
* sha3-384

### [14-01-2021] [Headers Quality](https://adamj.eu/tech/2019/04/10/how-to-score-a+-for-security-headers-on-your-django-website/)
* [Content Security Policy](https://www.laac.dev/blog/content-security-policy-using-django/) - [writeup](https://www.laac.dev/blog/content-security-policy-using-django/)
* [2FA for Django Admin](https://hackernoon.com/5-ways-to-make-django-admin-safer-eb7753698ac8)
* New dependency: `poetry run pip install django-otp qrcode`
 __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/web/`
    * `python3 manage.py migrate` if no you will get `no such table: otp_totp_totpdevice`

### [13-01-2020] Social Media buttons for sign in
* Adding [bootstrap-social](https://github.com/peterblazejewicz/bootstrap-social) to simplify sign buttons integration
* Move SSO providers config to from `web/web/settings.py` to `web/web/local_settings.py`
* `[oauth]` added to `conf/web.conf` for future on/off of the buttons
* New dependency: `poetry run pip install django-settings-export`

### [10-01-2020] Scrappers&Bots nightmare :)
* Add Web signup/SSO, email verification - [more details](https://django-allauth.readthedocs.io/en/latest/overview.html) - Amazing [writeup](https://www.theophilusn.com/blog/django-with-bootstrap-4) was used for integration
* [ReCaptcha protected admin](https://github.com/axil/django-captcha-admin/)
* New dependencies -> `poetry run pip install django-allauth django-recaptcha==2.0.6 django-crispy-forms git+https://github.com/CAPESandbox/httpreplay.git`
* __REQUIRED ACTION:__ -> `cd /opt/CAPEv2/web/`
    * `python3 manage.py migrate` if no you will get `No such table as django_site`
    * `python3 manage.py collectstatic` -> to enable django admin css -> requires web/web/local_settings.py modifiy `STATIC_ROOT`

### [02.01.02021] POST 2020
* Allow download http(s) Request/Response and Response 48bytes hex preview
* auth_only in api.conf to allow apikey/autentificated users hit the rest api

### [29.12.2020]
* YARA integrated to capemon, this allows to bypass anti-* aka capemon scripting, more [here](https://github.com/kevoreilly/CAPEv2/commit/9306e4e2629f569d4275e241d14aea65a74b421b)
* Docs and more anti bypasses and examples coming soon

### [22.12.2020] Peque edition
* TLS decrypt integration, huge thanks to Hatching team to release their code. WEBGUI integration isn't finished yet, but you already can see https requests there
* Safelists moved from network.py to `data/safelist/{domains,ips}.py`

### [08.12.2020] On demand
* Add uniq submission limitation, can be enabled in `conf/web.conf` to disable the same submission during X hours
* Bingraph, FLARE CAPA, vba2graph on demand
* Added `on_demand` feature.
    * This funcions aim to speedup processing but allow to user to generate parts of analysis that takes some time to finish and not used frequently. Example scripted submissions

### [02.12.2020] CAPE 2.2
* Malduck integration
* Bootrstarp 4.5.3 & font awesome 5
* Statistics
* Tag_tasks - allows you tag your jobs
* self.pefiles: introduced to prcessing/signatures modules, you can get PEFILE object by sha256 self.pefiles.get(sha256)
* Pending page now is much useful and show hashes to easilly spot duplicated
* Submission of file or resubmission will show all the jobs and detection for that file
* [Flare capa](https://github.com/fireeye/capa) integrated under static tab for original binary, procdump and cape (should be enabled in processing.conf), Rules can be pulled from community, but we will leave it community driven to sync them. So you can copy them from https://github.com/fireeye/capa-rules and place under `data/flare-capa`
* More soon ;)

### 16-11-2020
* `utils/cleaners.py` option `--delete-older-than-days` moved to bulk remove 10 in 10, to improve performance and decrease IO

### [31-10-2020] Pre Halloween edition
* [Box-js](https://github.com/kirk-sayre-work/box-js/) integration [docs](https://capev2.readthedocs.io/en/latest/integrations/box-js.html)
* Fixed support for office in x64 VMs

### [22-10-2020]
* cape.py rewrite so it affects `api/tasks/get/config/` so before it was list of configs and it has `cape_name`, now its like `[{malware_family:{config}}]`

### [20-10-2020]
* static config extraction lookup in database before scan file with yara and extract
* resubmit added to CAPE/procdump tabs

### [15-10-2020]
* Huge code unification and cleanup between `submission/views.py` and `api/views.py`
* Improve error messages on bulk submission, for failed samples/hashes
* Physical machinery updated by @hariomenkel, you can [read details in his writeup](https://mariohenkel.medium.com/using-cape-sandbox-and-fog-to-analyze-malware-on-physical-machines-4dda328d4e2c)

### [05-10-2020]
* Static extraction fix, thanks for testing it @nikhilh-20
* Static endpoint now will return config apart of the task id

### [01-10-2020] HacktoberFest edition
* Create zip files in memory (requires pyzipper) instead of using 7z and write them to temp folder
* Simplified parsing of arguments between submission/api views
* Created [docs](https://capev2.readthedocs.io/en/latest/development/current_module_improvement.html) on how to test `Curtain` and `Suricata`
* Static extraction api added
* Curtain module updated
* Code clenup
* Massive useless IO improved, read config once instead of on each file submit

### [14-09-2020]
* Added ability to enable/disable some of 3rd part services for malware detection, like: VirusTotal, ClamAV, Suricata

### [13-09-2020]
* Enable ratelimit on download any file, to avoid scrapping, to change limits, edit: `api.conf` -> `download_file`
* Error message for ratelimit can be configured in `web/web/settings.py`
* Fixed a lot of bugs/typos, thanks Flake8 + GitHub Actions :)

### [11-08-2020]
* Update suricata socket path in processing.conf as in cape2.sh from `/var/run/` to `/tmp/`
* Fix pebble pool restart on timeout
* Zip package reintroduced but it should be only used with option `file=X` when we need side load files

### [23-07-2020]
* Scan extracted macro with yara from macro/CAPE folder

### [11-07-2020]
* [ReadTheDocs](https://capev2.readthedocs.io/en/latest/#)

### [24-06-2020]
* Show url from where file was downloaded when using Download'n'Exec
* Zip package is depricate as it doesn't support AES etc, to upload with side files use file=X and submit in zip archive, for rest you have [sflock](https://github.com/doomedraven/sflock) <3

### [18-06-2020]
* Restore original dump file, don't dump inmediatelly
* CAPE tab now also loaded via ajax request

### [11-06-2020]
* Extended api search changed, now instead of return only ids, return some basic info, as detection, etc

### [31-05-2020]
* Rewrite /api/ ratelimit implementation to allow unlimited api for existing users([htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)), just set username and password as get/post arguments

### [17-05-2020]
* [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) from @DissectMalware integrated
* Yara now compiled once at processing start or reprocessing

### [15-05-2020]
* pyattck upgrade to >= 2.0.2
* moved many files from `/data/` to `community` -> `python3 utils/community.py -h`

### [07-05-2020]
* Behavior data/tab is now loaded via ajax request, to speedup webgui

### [06-05-2020]
* Add parent sample details to analysis
* Add Yara author to webgui, useful when yara name overlap with private yara

### [18-04-2020]
* All not core yara moved to community repo

### [17-04-2020]
* Dark theme is default now, to set old one just do
    * Backup current: `cp /opt/CAPEv2/web/templates/header.html /opt/CAPEv2/web/templates/header-dark.html`
    * Set old theme: `cp /opt/CAPEv2/web/templates/header-light.html /opt/CAPEv2/web/templates/header.html`

### [13-04-2020]
* TLP implemented for analysis, thanks @enzok

### [30-03-2020]
* /configdownload/ is moved to /api/tasks/get/config/<task_id>/ or /api/tasks/get/config/<task_id>/Family/
* Anti-api-spamming feature in monitor
* webgui optimizations(mongo queries improved a lot), thanks [MongoDB university](https://university.mongodb.com) for free cources :)

### [28-03-2020]
* CAPE 2.1 ;)
* A lot of small bug fixes, code cleanup, gui fixes, and monitor improvements
* Now insted if "None matched" we just hide field
* All VMs now are disabled on submission you need to enable it in web.conf
* To submit ZIP file for analisis you need to specify zip package, if no it will be extracted

### [24-03-2020]
* Big update of suricata name extraction/detection
* malscore now is off by default, can be enabled in conf/reporting.conf
* MalFamily renamed to detections

### [12-03-2020]
* community.py reintroduced to simplify everything
    * now all signatures and not core modules are moved to specific repo, please see `python3 utils/community.py -h`

### [29-02-2020]
* SIGHUP handling to stop submitting tasks and stop cuckoo.py, useful for when you need to reload it without breaking running jobs
    * `ps aux|grep "python3 cuckoo.py"|cut -d" " -f 5| xargs kill -1`

### [22-01-2020]
* Add qemu.py with support for x64/x86/MIPS/MIPSEL/ARM/ARMWRT/ARM64/PowerPC/PowerPC64/Sparc/Sparc64
* Basic linux integration is done thanks to @enzok

### [17-01-2020]
* Bson data compression to remove api spamming, [details](http://security.neurolabs.club/2019/12/inline-loop-detection-for-compressing.html), thanks @mabj
* Many bug fixes in cleaners.py, thanks @Enzok

### [14-01-2020]
* Fix local_settings
* move all in 1 dlls, example option to capemon: combo=1,extraction=1,injection=1,compression=1
* Fix ratelimit enabled/disabled in /api/
* Agent now by default set outout to StringIO to make it works with pythonw without extra args

### [08-01-2020]
* Screenshot deduplicacion algorithm is configurable now and default set to ahash, pr #10, thanks @wmetcalf
* Fixed pythonw compability problem, pr #7, thanks @wmetcalf
* Pillow 7 compatible, pr #9, thanks @wmetcalf
* Upgrade ClamAV support, pr #11, thanks @wmetcalf
* All cleaners from cuckoo.py and some from utils folder are moved to unique file utils/cleaners.py, see, -h @doomedraven
* distributed CAPE documentation updated
* m2crypto+swig replaced with cryptography library

### [25-12-2019]
* CAPEv2 is Python3 based
* Django 3 tested
* [ASGI support - async "wsgi"](https://docs.djangoproject.com/en/3.0/howto/deployment/asgi/)
* All found memleaks fixed
* A lot of code improved and bug fixed
* Malware parsers/extractors moved to use upstream libraries instead of include them to the project, to simplify maintaining and code bug fixes
* User experience improved
* Still might contain some bugs, so please let us know if you see any
* Thanks NaxoneZ for all your bug reports and hard testing <3
