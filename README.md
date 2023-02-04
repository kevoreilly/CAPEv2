## CAPE: Malware Configuration And Payload Extraction - [FYPJ Documentation](https://docs.google.com/document/d/1jCbfvdsTQfzFsQa0wUFmHCpRn2QrdMaMLNT-waB3QbU/edit?usp=sharing)

CAPE is a malware sandbox. It was derived from Cuckoo with the goal of adding automated malware unpacking and config extraction - hence its name is an acronym: 'Config And Payload Extraction'. Automated unpacking allows classification based on Yara signatures to complement network (Suricata) and behavior (API) signatures.

There is a free community instance online that anyone can use:

https://capesandbox.com

* Python3
    * agent.py is tested with python (3.7.2|3.8) x86. __You should use x86 python version inside of the VM!__
    * host tested with python3 version 3.7 and 3.8, but newer versions should work too

## Installation recommendations and scripts for optimal performance
* __Only rooter should be executed as root__, the rest as __cape__ user. Running as root will mess with permissions.
0. Become familiar with the [documentation](https://capev2.readthedocs.io/en/latest/) and __do read ALL__ config files inside of `conf` folder!
    * DO NOT FOLLOW BLOGS LIKE THESE - they suggest things that are against what we suggest:
        * https://notes.netbytesec.com/2020/12/cape-sandbox-installation-from-0-to-hero.html
2. For best compabitility we strongly suggest installing on [Ubuntu 22.04 LTS](https://ubuntu.com/#download)
3. [KVM](https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh) is recommended as the hypervisor.
 * Replace `<username>` with a real pattern.
 * You need to replace all `<WOOT>` inside!
 * Read it! You must understand what it does! It has configuration in header of the script.
 * `sudo ./kvm-qemu.sh all <username> | tee kvm-qemu.log`
4. To install CAPE itself, [cape2.sh](https://github.com/kevoreilly/CAPEv2/blob/master/installer/cape2.sh) with all optimizations
    * Read and understand what it does! This is not a silver buller for all your problems! It has configuration in header of the script.
    * `sudo ./cape2.sh base | tee cape.log`
5. After installing everything save both instalation logs as gold!
**6. Configure CAPE by doing mods to config files inside `conf` folder.**
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

### Special note about config parsing frameworks:
* Due to the nature of malware, since it changes constantly when any new version is released, something might become broken!
* We suggest using only pure Python with entry point `def config(data):` that will be called by `cape_utils.py` and 0 complications.
    * As a bonus, you can reuse your extractors in other projects.

### Special note about 3rd part dependencies:
* They becoming a headache, specially those that using `pefile` as each pins version that they want. 
    * Our suggestion is clone/fork them, remove `pefile` dependency as you already have it installed. Volia no more pain.

### Docs
* [Original CAPE Documentation](https://capev2.readthedocs.io/en/latest/#)
* [CAPE Documentation for FYPJ](https://docs.google.com/document/d/1jCbfvdsTQfzFsQa0wUFmHCpRn2QrdMaMLNT-waB3QbU/edit?usp=sharing)
