## CAPE: Malware Configuration And Payload Extraction - [Documentation](https://capev2.readthedocs.io/en/latest/#)

CAPE is a malware sandbox. It was derived from Cuckoo with the goal of adding automated malware unpacking and config extraction - hence its name is an acronym: 'Config And Payload Extraction'. Automated unpacking allows classification based on Yara signatures to complement network (Suricata) and behavior (API) signatures.

There is a free community instance online which anyone can use:

https://capesandbox.com

Although config and payload extraction was the original stated goal, it was the development of the debugger in CAPE which first inspired the project: in order to extract configs or unpacked payloads from arbitrary malware families without relying on process dumps (which sooner or later the bad guys will thwart), instruction-level monitoring and control is necessary. The novel debugger in CAPE follows the principle of maximising use of processor hardware and minimising (almost completely) use of Windows debugging interfaces, allowing malware to be stealthily instrumented and manipulated from the entry point with hardware breakpoints programmatically set during detonation by Yara signatures or API calls. This allows instruction traces to be captured, or actions to be performed such as control flow manipulation or dumping of a memory region.

The debugger has allowed CAPE to continue to evolve beyond its original capabilities, which now include dynamic anti-evasion bypasses. Since modern malware commonly tries to evade analysis within sandboxes, for example by using timing traps for virtualisation or API hook detection, CAPE allows dynamic countermeasures to be developed combining debugger actions within Yara signatures to detect evasive malware as it detonates, and perform control-flow manipulation to force the sample to detonate fully or skip evasive actions. The list of dynamic bypasses in CAPE is growing but includes:
- Guloader
- Ursnif
- Dridex
- Zloader
- Formbook
- BuerLoader
- Pafish

CAPE takes advantage of many malware techniques or behaviours to allow for unpacked payload capture:
- Process injection
    - Shellcode injection
    - DLL injection
    - Process Hollowing
    - Process Doppelganging
- Decompression of executable modules in memory
- Extraction of executable modules or shellcode in memory

These behaviours will result in the capture of payloads being injected, extracted or decompressed for further analysis. In addition CAPE automatically creates a process dump for each process, or, in the case of a DLL, the DLL's module image in memory. This is useful for samples packed with simple packers, where often the module image dump is fully unpacked.

Quick access to the debugger is made possible with the breakpoint options 'bp0' through 'bp3' accepting RVA or VA values to set breakpoints, whereupon a short instruction trace will be output, governed by 'count' and 'depth' options (e.g. bp0=0x1234,depth=1,count=100). To set a breakpoint at the module entry point, 'ep' is used instead of an address (e.g. bp0=ep). Alternatively 'break-on-return' allows for a breakpoint on the return address of a hooked API (e.g. break-on-return=NtGetContextThread). An optional 'base-on-api' parameter allows the image base for RVA breakpoints to be set by API call (e.g. base-on-api=NtReadFile,bp0=0x2345).

Options 'action0' - 'action3' allow actions to be performed when breakpoints are hit, such as dumping memory regions (e.g. action0=dumpebx) or changing the execution control flow (e.g. action1=skip). CAPE's documentation contains further examples of such actions.

'dump-on-api' allows a module to be dumped when it calls a specific API function which can be specified in the web interface which can be useful for quickly unpacking/dumping novel samples (e.g. dump-on-api=DnsQuery_A).

CAPE also has an option 'upx=1' which can dynamically unpack samples that use 'hacked' (modified) UPX, very popular with malware authors. These samples are run in CAPE's debugger until their OEP (original entry point), whereupon they are dumped, fixed and their imports are automatically reconstructed, ready for analysis.

CAPE is constantly growing in malware family coverage, but has config parsers for the following examples:
- Emotet
- TrickBot
- QakBot
- Hancitor
- Ursnif
- Dridex
- SmokeLoader
- IcedID
- RedLeaf
- ChChes
- HttpBrowser
- Enfal
- PoisonIvy
- Screech
- TSCookie

CAPE uses Yara signatures as its principal classification method to detect unpacked payloads. This list is constantly growing, and includes:
- Azorult, Formbook, Ryuk, Hermes, Shade, Remcos, Ramnit, Gootkit, QtBot, ZeroT, WanaCry, NetTraveler, Locky, BadRabbit, Magniber, Redsip, Kronos, PetrWrap, Kovter, Azer, Petya, Dreambot, Atlas, NanoLocker, Mole, Codoso, Cryptoshield, Loki, Jaff, IcedID, Scarab, Cutlet, RokRat, OlympicDestroyer, Gandcrab, Fareit, ZeusPanda, AgentTesla, Imminent, Arkei, Sorgu, tRat, T5000, TClient, TreasureHunter.

There is a community repository of signatures containing several hundred signatures developed by the CAPE community: https://github.com/kevoreilly/community

Config parsing can be done using either of CAPE's config parsing frameworks, the RATDecoders framework from malwareconfig.com and DC3-MWCP (Defense Cyber Crime Center - Malware Configuration Parser). The many parsers/decoders from malwareconfig.com are also included, comprising among many others: Sakula, DarkComet, PredatorPain and PoisonIvy. Thanks to Kevin Breen/TechAnarchy for this framework and parsers (https://github.com/kevthehermit/RATDecoders), and to DC3 for their framework (https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP). Special thanks to Jason Reaves (@sysopfb) for the TrickBot parser and Fabien Perigaud for the PlugX parser.

The repository containing the code for the monitor DLLs is a distinct one: https://github.com/kevoreilly/capemon.

Please contribute to this project by helping create new signatures, parsers or bypasses for further malware families. There are many in the works currently, so watch this space.

## CAPEv2!

A huge thank you to @D00m3dR4v3n for single-handedly porting CAPE to Python 3.

* Python3
    * agent.py is tested with python (3.7.2|3.8) x86. __You should use x86 python version inside of the VM!__
    * host tested with python3 version 3.7 and 3.8, but newer versions should works too

## Installation recommendations and scripts for optimal performance
0. Become familiar with [documentation](https://capev2.readthedocs.io/en/latest/installation/guest/network.html#virtual-networking) for proper configuration
1. For best compability we strongly suggest installing on [Ubuntu 20.04 LTS](https://ubuntu.com/#download)
2. [KVM](https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh) is recommended as hypervisor, replace `<W00T>` to real pattern
 * `sudo ./kvm-qemu.sh all <username> | tee kvm-qemu.log`
3. To install CAPE itself, [cape2.sh](https://github.com/doomedraven/Tools/blob/master/Sandbox/cape2.sh) with all optimizations
    * `sudo ./cape2.sh base cape | tee cape.log`
    * CAPE Services
        * cape.service
        * cape-processor.service
        * cape-web.service
        * cape-rooter.service
        * To restart any service use `systemctl restart <service_name>`
    * To debug any problem, stop service and run the command that runs service by hand to see more logs, check `-h`, debug mode (`-d`) can help.
    * __Only rooter should be executed as root__, the rest as __cape__ user.
    * Running as root will mess with permissions

4. Reboot and enjoy


* All scripts contain __help__ `-h`, but please check the scripts to __understand__ what they are doing.


### How to create VMs with virt-manager see docs for configration
* [step by step](https://www.doomedraven.com/2020/04/how-to-create-virtual-machine-with-virt.html)

## Virtual machine core dependecy
* [choco.bat](https://github.com/doomedraven/Tools/blob/master/Windows/choco.bat)

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



### Docs
* [ReadTheDocs](https://capev2.readthedocs.io/en/latest/#)
