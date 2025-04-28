## CAPE: Malware Configuration And Payload Extraction - [Documentation](https://capev2.readthedocs.io/en/latest/#)

### CAPE is a malware sandbox.
A sandbox is used to execute malicious files in an isolated environment
whilst instrumenting their dynamic behaviour and collecting forensic artefacts.

CAPE was derived from Cuckoo v1 which features the following core capabilities
on the Windows platform:

* Behavioral instrumentation based on API hooking
* Capture of files created, modified and deleted during execution
* Network traffic capture in PCAP format
* Malware classification based on behavioral and network signatures
* Screenshots of the desktop taken during the execution of the malware
* Full memory dumps of the target system

CAPE complements Cuckoo's traditional sandbox output with several key additions:

* Automated dynamic malware unpacking
* Malware classification based on YARA signatures of unpacked payloads
* Static & dynamic malware configuration extraction
* Automated debugger programmable via YARA signatures, allowing:
    * Custom unpacking/config extractors
    * Dynamic anti-sandbox countermeasures
    * Instruction traces
* Interactive desktop

There is a free demonstration instance online that anyone can use:

https://capesandbox.com - For account activation reach to https://twitter.com/capesandbox

### Some History

Cuckoo Sandbox started as a Google Summer of Code project in 2010 within
The Honeynet Project. It was originally designed and developed by Claudio
Guarnieri, the first beta release was published in 2011. In January 2014,
Cuckoo v1.0 was released.

2015 was a pivotal year, with a significant fork in Cuckoo's history.
Development of the original monitor and API hooking method was halted in the
main Cuckoo project. It was replaced by an [alternative monitor](https://github.com/cuckoosandbox/monitor)
using a ``restructuredText``-based signature format compiled via Linux toolchain,
created by Jurriaan Bremer.

Around the same time, a fork called [Cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified)
was created by Brad 'Spender' Spengler continuing development of the original
monitor with significant improvements including 64-bit support and importantly
introducing Microsoft's Visual Studio compiler.

During that same year development of a dynamic command-line configuration and payload
extraction tool called CAPE was begun at Context Information Security by Kevin O'Reilly.
The name was coined as an acronym of 'Config And Payload Extraction' and the original
research focused on using API hooks provided by Microsoft's [Detours](https://github.com/microsoft/Detours)
library to capture unpacked malware payloads and configuration. However, it became
apparent that API hooks alone provide insufficient power and precision to allow for
unpacking of payloads or configs from arbitrary malware.

For this reason research began into a novel debugger concept to allow malware to be
precisely controlled and instrumented whilst avoiding use of Microsoft debugging
interfaces, in order to be as stealthy as possible. This debugger was integrated
into the proof-of-concept Detours-based command-line tool, combining with API hooks
and resulting in very powerful capabilities.

When initial work showed that it would be possible to replace Microsoft Detours
with Cuckoo-modified's [API hooking engine](https://github.com/spender-sandbox/cuckoomon-modified),
the idea for CAPE Sandbox was born. With the addition of the debugger, automated unpacking,
YARA-based classification and integrated config extraction, in September 2016 at 44con, CAPE Sandbox was
publicly released for the first time: [CAPE](https://github.com/ctxis/CAPE) version 1.

In the summer of 2018 the project was fortunate to see the beginning of huge
contributions from Andriy 'doomedraven' Brukhovetskyy, a long-time Cuckoo
contributor. In 2019 he began the mammoth task of porting CAPE to Python 3
and in October of that year [CAPEv2](https://github.com/kevoreilly/CAPEv2) was released.

CAPE has been continuously developed and improved to keep pace with advancements
in both malware and operating system capabilities. In 2021, the ability to program
CAPE's debugger during detonation via dynamic YARA scans was added, allowing for
dynamic bypasses to be created for anti-sandbox techniques. Windows 10 became the
default operating system, and other significant additions include interactive desktop,
AMSI (Anti-Malware Scan Interface) payload capture, 'syscall hooking' based on Microsoft
Nirvana and debugger-based direct/indirect syscall countermeasures.

### Classification
![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/15b34a87-6b2a-49bd-a58a-d16d5fee438e)

Malware can be classified in CAPE via three mechanisms:
* YARA scans of unpacked payloads
* Suricata scans of network captures
* Behavioral signatures scanning API hook output

### Config Extraction

![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/a44f2f8a-10df-47cc-9690-5ef08f04ea6b)

Parsing can be done using CAPE's own framework, alternatively the following frameworks are supported: [RATDecoders](https://github.com/kevthehermit/RATDecoders), [DC3-MWCP](https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP), [MalDuck](https://github.com/CERT-Polska/malduck/tree/master/malduck/), or [MaCo](https://github.com/CybercentreCanada/maco)

#### Special note about config parsing frameworks:
* Due to the nature of malware, since it changes constantly when any new version is released, something might become broken!
* We suggest using CAPE's framework which is simply pure Python with entry point `def extract_config(data):` that will be called by `cape_utils.py` and 0 complications.
    * As a bonus, you can reuse your extractors in other projects.

### Automated Unpacking
![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/090ce3fb-9dc8-4316-bc20-469c6fff725a)

CAPE takes advantage of many malware techniques or behaviours to allow for unpacked payload capture:
- Process injection
    - Shellcode injection
    - DLL injection
    - Process Hollowing
    - Process Doppelganging
- Extraction or decompression of executable modules or shellcode in memory

These behaviours will result in the capture of payloads being injected, extracted, or decompressed for further analysis. In addition CAPE automatically creates a process dump for each process, or, in the case of a DLL, the DLL's module image in memory. This is useful for samples packed with simple packers, where often the module image dump is fully unpacked.

In addition to CAPE's default 'passive' unpacking mechanisms, it is possible to enable 'active' unpacking which uses breakpoints to detect writing to newly allocated or protected memory regions, in order to capture unpacked payloads as early as possible prior to execution. This is enabled via web submission tickbox or by specifying option `unpacker=2` and is left off by default as it may impact detonation quality.

CAPE can be programmed via YARA signature to unpack specific packers. For example, UPX-type packers are very common and, although in CAPE these result in unpacked payloads being passively captured, the default capture is made after the unpacked payload has begun executing. Therefore by detecting UPX-derived packers dynamically via custom YARA signature and setting a breakpoint on the final packer instruction, it is possible to capture the payload at its original entry point (OEP) before it has begun executing.

![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/daf702c8-a658-48fe-850a-d86f0a89dc82)

![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/76b2c800-1d96-4ea5-ae86-c261b3946424)

The `dump-on-api` option allows a module to be dumped when it calls a specific API function that can be specified in the web interface (e.g. `dump-on-api=DnsQuery_A`).

### [Debugger](https://capev2.readthedocs.io/en/latest/usage/monitor.html)
The debugger has allowed CAPE to continue to evolve beyond its original capabilities, which now include dynamic anti-evasion bypasses. Since modern malware commonly tries to evade analysis within sandboxes, for example by using timing traps for virtualisation or API hook detection, CAPE allows dynamic countermeasures to be developed combining debugger actions within Yara signatures to detect evasive malware as it detonates, and perform control-flow manipulation to force the sample to detonate fully or skip evasive actions.

![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/801fb4d3-2569-44aa-b40e-d3d5cc7d8bb3)
![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/d76da82f-38b7-4cdf-ad9d-f16e8d2dfa66)

Quick access to the debugger is made possible with the submission options `bp0` through `bp3` accepting RVA or VA values to set breakpoints, whereupon a short instruction trace will be output, governed by `count` and `depth` options (e.g. `bp0=0x1234,depth=1,count=100`).
![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/6aa3d31e-cd52-4549-997f-734fb755f10b)

To set a breakpoint at the module entry point, `ep` is used instead of an address (e.g. `bp0=ep`). Alternatively `break-on-return` allows for a breakpoint on the return address of a hooked API (e.g. `break-on-return=NtGetContextThread`). An optional `base-on-api` parameter allows the image base for RVA breakpoints to be set by API call (e.g. `base-on-api=NtReadFile,bp0=0x2345`).

![image](https://github.com/kevoreilly/CAPEv2/assets/22219888/3acfbde2-68e1-479d-a829-0c9142fb1be7)

Options `action0` - `action3` allow actions to be performed when breakpoints are hit, such as dumping memory regions (e.g. `action0=dumpebx`) or changing the execution control flow (e.g. `action1=skip`). CAPE`s documentation contains further examples of such actions.

### [capemon](https://github.com/kevoreilly/capemon)
The repository containing the code for the CAPE's monitor is distinct.

### Updates summary [changelog](https://github.com/kevoreilly/CAPEv2/blob/master/changelog.md)

### [Community contributions](https://github.com/CAPESandbox/community)
There is a community repository of signatures containing several hundred signatures developed by the CAPE community. All new community feature should be pushed to that repo. Later they can be moved to core if devs are able and willing to maintain them.

Please contribute to this project by helping create new signatures, parsers, or bypasses for further malware families. There are many in the works currently, so watch this space.

A huge thank you to @D00m3dR4v3n for single-handedly porting CAPE to Python 3.

## Installation recommendations and scripts for optimal performance
* Python3
    * agent.py is tested with python (3.7.2|3.8) x86. __You should use x86 python version inside of the VM!__
    * host tested with python3 version 3.10, 3.12, but newer versions should work too

* __Only rooter should be executed as root__, the rest as __cape__ user. Running as root will mess with permissions.
1. Become familiar with the [documentation](https://capev2.readthedocs.io/en/latest/) and __do read ALL__ config files inside of `conf` folder!
2. For best compabitility we strongly suggest installing on [Ubuntu 24.04 LTS](https://ubuntu.com/#download) and using Windows 10 21H2 as target.
3. `kvm-qemu.sh` and `cape2.sh` __SHOULD BE__ executed from `tmux` session to prevent any OS problems if ``ssh`` connections breaks.
4. [KVM](https://github.com/kevoreilly/CAPEv2/blob/master/installer/kvm-qemu.sh) is recommended as the hypervisor.
 * Replace `<username>` with a real pattern.
 * You need to replace all `<WOOT>` inside!
 * Read it! You must understand what it does! It has configuration in header of the script.
 * `sudo ./kvm-qemu.sh all <username> 2>&1 | tee kvm-qemu.log`
4. To install CAPE itself, [cape2.sh](https://github.com/kevoreilly/CAPEv2/blob/master/installer/cape2.sh) with all optimizations
    * Read and understand what it does! This is not a silver bullet for all your problems! It has configuration in header of the script.
    * `sudo ./cape2.sh base 2>&1 | tee cape.log`
5. After installing everything save both installation logs as gold!
6. Configure CAPE by doing mods to config files inside `conf` folder.
7. Restart all CAPE services to pick config changes and run CAPE properly!
    * CAPE Services
        * cape.service
        * cape-processor.service
        * cape-web.service
        * cape-rooter.service
        * To restart any service use `systemctl restart <service_name>`
        * To see service log use `journalctl -u <service_name>`
    * To debug any problem, stop the relevant service and run the command that runs that service by hand to see more logs. Check `-h` for the help menu. Running the service in debug mode (`-d`) can help as well.
5. Reboot and enjoy!


* All scripts contain __help__ `-h`, but please check the scripts to __understand__ what they are doing.


### How to create VMs with virt-manager see docs for configuration
* [step by step](https://www.doomedraven.com/2020/04/how-to-create-virtual-machine-with-virt.html)

## Virtual machine core dependency
* [choco.bat](https://github.com/kevoreilly/CAPEv2/blob/master/installer/choco.bat)

## How to update
* CAPE: `git pull`
* community: `python3 utils/community.py -waf` see `-h` before to ensure you understand

## How to upgrade with a lot of custom small modifications that can't be public?

#### With rebase
```
git add --all
git commit -m '[STASH]'
git pull --rebase origin master
# fix conflict (rebase) if needed
git reset HEAD~1
```

#### With merge
```
# make sure kevoreilly repo has been added as a remote (only needs to be done once)
git remote add kevoreilly https://github.com/kevoreilly/CAPEv2.git
# make sure all your changes are commited on the branch which you will be merging
git commit -a -m '<your commit message goes here>'
# fetch changes from kevoreilly repo
git fetch kevoreilly
# merge kevoreilly master branch into your current branch
git merge kevoreilly/master
# fix merge conflicts if needed
# push to your repo if desired
git push
```

### How to cite this work
If you use CAPEv2 in your work, please cite it as specified in the "Cite this repository" GitHub menu.

### Special note about 3rd part dependencies:
* They becoming a headache, specially those that using `pefile` as each pins version that they want.
    * Our suggestion is clone/fork them, remove `pefile` dependency as you already have it installed. Volia no more pain.

### Docs
* [ReadTheDocs](https://capev2.readthedocs.io/en/latest/#)
* [DeepWiki](https://deepwiki.com/kevoreilly/CAPEv2/1-overview) - AI generated, some might be wrong but generally pretty accurate.
