## CAPEv2! you are welcome to test and report any bug

* Python3
* agent.py is tested with python (3.7.2|3.8) x86
* host python3 version 3.6.8

## Installation recommendations and scripts for optimal performance
1. For best compability we strongly suggest installing on [Ubuntu 18.04 LTS](https://ubuntu.com/#download)
2. [KVM](https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh) is recommended as hypervisor
 * `sudo ./kvm-qemu.sh all <username>`
3. To install CAPE itself, [cape2.sh](https://github.com/doomedraven/Tools/blob/master/Sandbox/cape2.sh) with all optimizations
 * `sudo ./cape2.sh all cape`
4. Reboot and enjoy

\* All scripts contain __help__ `-h`, but please check the scripts to __understand__ what they are doing.

__requirements.txt is decpricated now in favour of the script__

#### What doesn't work
* volatility details, the bridge exist to use VolatilityAPI with vol3, but not to run the default modules

## CAPE: Malware Configuration And Payload Extraction

CAPE is a malware sandbox. It is derived from Cuckoo and is designed to automate the process of malware analysis with the goal of extracting payloads and configuration from malware. This allows CAPE to detect malware based on payload signatures, as well as automating many of the goals of malware reverse engineering and threat intelligence.

There is a community version online which is free for anyone to try:

https://capesandbox.com/submit

CAPE can detect a number of malware techniques or behaviours, as well as specific malware families, from its initial run on a sample. This detection may then trigger a further run with a specific package, in order to extract the malware payload and possibly its configuration, for further analysis.

CAPE works by controlling malware via a bespoke debugger and API hooks. Detection to trigger a CAPE package can be based on API or Yara signatures. The debugger uses Yara signatures or API hooks to allow breakpoints to be set on individual instructions, memory regions or function calls. Once a region of interest is reached, it can be manipulated and dumped for processing and analysis, and possibly configuration parsing.

The techniques or behaviours that CAPE detects and has packages for include:
- Process injection
    - Shellcode injection
    - DLL injection
    - Process Hollowing
    - Process Doppelganging
- Decompression of executable modules in memory
- Extraction of executable modules or shellcode in memory

Packages for these behaviours will dump the payloads being injected, extracted or decompressed for further analysis. This is often the malware payload in unpacked form.

CAPE automatically creates a process dump for each process, or, in the case of a DLL, the DLL's module image in memory. This is useful for samples packed with simple packers, where often the module image dump is fully unpacked. Yara signatures may trigger on the process dumps, possibly resulting in submission with a specific package or configuration parsing.

CAPE also has a package which can dynamically unpack samples that use 'hacked' (modified) UPX, very popular with malware authors. These samples are run in CAPE's debugger until their OEP (original entry point), whereupon they are dumped, fixed and their imports are automatically reconstructed, ready for analysis.

Currently CAPE has specific packages dumping configuration and payloads for the following malware families:
- PlugX
- EvilGrab
- Sedreco
- Cerber
- TrickBot
- Hancitor
- Ursnif
- QakBot

CAPE has config parsers/decoders for the following malware families, whose payloads are automatically extracted by a behavioural package:
- Emotet
- RedLeaf
- ChChes
- HttpBrowser
- Enfal
- PoisonIvy
- Screech
- TSCookie
- Dridex
- SmokeLoader

Many other malware families have their payloads automatically extracted by behavioural packages, for which CAPE uses Yara signatures to detect the payloads. This list is growing, and includes:
- Azorult, Formbook, Ryuk, Hermes, Shade, Remcos, Ramnit, Gootkit, QtBot, ZeroT, WanaCry, NetTraveler, Locky, BadRabbit, Magniber, Redsip, Kronos, PetrWrap, Kovter, Azer, Petya, Dreambot, Atlas, NanoLocker, Mole, Codoso, Cryptoshield, Loki, Jaff, IcedID, Scarab, Cutlet, RokRat, OlympicDestroyer, Gandcrab, Fareit, ZeusPanda, AgentTesla, Imminent, Arkei, Sorgu, tRat, T5000, TClient, TreasureHunter.

Configuration data may be output from either family packages, or in payloads resulting from behavioural packages. Configuration parsing may then be performed on this by virtue of Yara-based detection, and config parsing based on either of CAPE's config parsing frameworks, the RATDecoders framework from malwareconfig.com and DC3-MWCP (Defense Cyber Crime Center - Malware Configuration Parser). The many parsers/decoders from malwareconfig.com are also included, comprising among many others: Sakula, DarkComet, PredatorPain and PoisonIvy. Thanks to Kevin Breen/TechAnarchy for this framework and parsers (https://github.com/kevthehermit/RATDecoders), and to DC3 for their framework (https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP). Special thanks to Jason Reaves (@sysopfb) for the TrickBot parser and Fabien Perigaud for the PlugX parser.

Utility packages are also included: 'DumpOnAPI' allows a module to be dumped when it calls a specific API function which can be specified in the web interface. 'DumpConfigRegion' allows the memory region containing C2 information or other config data to be dumped for commonly used API calls. These packages can be useful for quickly unpacking/dumping novel samples or configs. The 'Trace' package allows quick access to the debugger by accepting four breakpoints (RVA values) to set on instructions, whereupon a short instruction trace will be output. An optional 'base-on-api' parameter allows the image base to be set by API call.

The CAPE debugger allows breakpoints to be set on read, write or execute of a memory address or region, as well as single-step mode. This allows fine control over malware execution until it is possible to dump the memory regions of interest, containing code or configuration data. Breakpoints can be set dynamically by package code, API hooks or Yara signatures. Thanks to the embedded distorm library the debugger can output the disassembly of instructions during single-step mode or when breakpoints are hit, resulting in instruction traces.

Processes, modules and memory regions can variously be dumped by CAPE through use of a simple API. These dumps can then be scanned and parsed for configuration information. Executable modules are fixed on being dumped, and may also have their imports automatically reconstructed (based on Scylla: https://github.com/NtQuery/Scylla). Packages can be written based on API hooks, the CAPE debugger, or a combination of both. There are a number of other behavioural and malware family packages and parsers currently in the works, so watch this space.

The repository containing the code for the monitor DLLs which form the basis of these packages is a distinct one: https://github.com/kevoreilly/capemon. This repository is organised in branches for the various packages.

Please contribute to this project by helping create new packages for further malware families, packers, techniques or configuration parsers. Alternatively contact @CapeSandbox or Kevin O'Reilly for further details of CAPE development.
